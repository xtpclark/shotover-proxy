use super::{CodecWriteError, Direction, message_latency};
use crate::codec::{CodecBuilder, CodecReadError, CodecState};
use crate::frame::postgres::{
    BackendMessage, CANCEL_REQUEST_CODE, GSSENC_REQUEST_CODE, PostgresFrame, SSL_REQUEST_CODE,
    message_wire_length,
};
use crate::frame::{Frame, MessageType};
use crate::message::{Encodable, Message, MessageId, Messages};
use anyhow::{Result, anyhow};
use bytes::BytesMut;
use metrics::Histogram;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder};

/// A client that connects must complete its SSL negotiation and startup message within this window.
/// It bounds the WHOLE startup handshake — the 8-byte header AND the message body (see
/// `read_startup_body`) — so a client that connects and sends nothing, or sends a partial header/body
/// and stalls, cannot hold a connection permit forever. The body read is not otherwise deadlined: the
/// source `timeout` config bounds only established connections and is unset by default.
const CLIENT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// The result of answering a client's pre-startup negotiation requests.
pub enum SourcePrologue {
    /// The client will proceed in plaintext. The prefix holds bytes already read
    /// from the socket that belong to the message stream (the head of the startup message).
    Plaintext { prefix: BytesMut },
    /// The client requested TLS and was answered 'S': perform the TLS accept next.
    TlsRequested,
    /// The client disconnected during negotiation.
    Disconnected,
}

/// Answers SSLRequest/GSSENCRequest negotiation on a new client connection.
///
/// These arrive BEFORE the startup message and expect a raw single byte answer
/// with no message framing, so they must be handled before the codec sees the stream:
/// * SSLRequest is answered 'S' when this source has TLS configured (the caller then
///   performs the TLS accept), 'N' otherwise (the client proceeds in plaintext or disconnects).
/// * GSSENCRequest is always answered 'N': GSSAPI encryption is not supported.
///
/// A client may probe both in sequence, so negotiation loops until a real startup
/// message begins. Those first 8 bytes of startup message are returned as a prefix
/// to be fed to the decoder.
pub async fn source_prologue(
    stream: &mut TcpStream,
    tls_configured: bool,
) -> Result<SourcePrologue> {
    let mut header = [0u8; 8];
    loop {
        match tokio::time::timeout(CLIENT_STARTUP_TIMEOUT, stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(SourcePrologue::Disconnected);
            }
            Ok(Err(err)) => return Err(err.into()),
            // The client connected but sent no startup within the window: drop it rather than
            // hold the connection permit indefinitely.
            Err(_elapsed) => {
                tracing::debug!("postgres client sent no startup within the timeout, closing");
                return Ok(SourcePrologue::Disconnected);
            }
        }
        let length = i32::from_be_bytes(header[0..4].try_into().unwrap());
        let code = i32::from_be_bytes(header[4..8].try_into().unwrap());
        if length == 8 && code == SSL_REQUEST_CODE {
            if tls_configured {
                stream.write_all(b"S").await?;
                return Ok(SourcePrologue::TlsRequested);
            } else {
                stream.write_all(b"N").await?;
            }
        } else if length == 8 && code == GSSENC_REQUEST_CODE {
            stream.write_all(b"N").await?;
        } else if code == CANCEL_REQUEST_CODE {
            // A CancelRequest is sent on its own plaintext connection even to a TLS server (libpq's
            // PQcancel opens a raw socket with no SSL negotiation). Accept it regardless of whether
            // this source terminates TLS, reading its whole body under the handshake deadline before
            // handing it to the codec as a startup-framed message.
            return read_startup_body(stream, header).await;
        } else if tls_configured {
            // This source terminates TLS: a plaintext startup is refused, matching a postgres
            // server whose pg_hba requires hostssl. Close quietly (a debug line, not an error per
            // connection) so a port scanner cannot flood the log.
            tracing::debug!("postgres source requires TLS; closing a plaintext startup attempt");
            return Ok(SourcePrologue::Disconnected);
        } else {
            return read_startup_body(stream, header).await;
        }
    }
}

/// Reads the remainder of a startup-framed message (StartupMessage or CancelRequest) whose 8-byte
/// header has already been read, under the same [`CLIENT_STARTUP_TIMEOUT`] that bounds the header.
///
/// This closes the half-startup hold: once the header arrived, the body was previously read by the
/// codec with no deadline (the source `timeout` config is unset by default), so a client that sent 8
/// bytes then stalled held a connection permit forever. The declared length is validated against the
/// startup-packet cap FIRST (via [`message_wire_length`]), so an over-cap length is rejected
/// immediately instead of being read or waited on.
async fn read_startup_body(stream: &mut TcpStream, header: [u8; 8]) -> Result<SourcePrologue> {
    let total = match message_wire_length(&header, true) {
        Ok(Some(total)) => total,
        // 8 header bytes are always enough to read the startup length prefix.
        Ok(None) => return Ok(SourcePrologue::Disconnected),
        Err(err) => {
            tracing::debug!("postgres client sent an invalid startup packet length: {err}");
            return Ok(SourcePrologue::Disconnected);
        }
    };

    let mut message = BytesMut::from(&header[..]);
    let body_len = total - header.len();
    if body_len > 0 {
        let mut body = vec![0u8; body_len];
        match tokio::time::timeout(CLIENT_STARTUP_TIMEOUT, stream.read_exact(&mut body)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(SourcePrologue::Disconnected);
            }
            Ok(Err(err)) => return Err(err.into()),
            // The header arrived but the body did not complete within the window: drop it rather than
            // hold the connection permit indefinitely.
            Err(_elapsed) => {
                tracing::debug!(
                    "postgres client sent an incomplete startup body within the timeout, closing"
                );
                return Ok(SourcePrologue::Disconnected);
            }
        }
        message.extend_from_slice(&body);
    }
    Ok(SourcePrologue::Plaintext { prefix: message })
}

/// Sends an SSLRequest on a fresh connection to a postgres server and reads the
/// raw single byte answer. The TLS handshake may only begin after an 'S' answer.
pub async fn sink_tls_prologue(stream: &mut TcpStream) -> Result<()> {
    let mut request = [0u8; 8];
    request[0..4].copy_from_slice(&8i32.to_be_bytes());
    request[4..8].copy_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
    stream.write_all(&request).await?;
    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer).await?;
    match answer[0] {
        b'S' => Ok(()),
        b'N' => Err(anyhow!(
            "This postgres server does not support TLS but the sink has TLS configured"
        )),
        other => Err(anyhow!(
            "Unexpected answer {:?} to SSLRequest",
            other as char
        )),
    }
}

/// What the decoder observed of a response's trailing ReadyForQuery.
///
/// Three states, not `Option<u8>`, because `None` would have to mean both "this train has no
/// ReadyForQuery" and "nobody recorded one" — and a caller that read the second as the first would
/// silently mis-report a transaction as idle.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TrailingReadyStatus {
    /// Not recorded, so the answer has to be parsed out. Three ways to get here: a transform built
    /// the message from a frame, its frame has been modified since decoding, or it is a PARTIAL
    /// chunk — which is deliberately left unrecorded because a ReadyForQuery always completes a
    /// train and so is never inside one.
    ///
    /// The first two are cheap to parse; the third is not, and is the reason
    /// [`trailing_ready_status`] must not be called on a partial. See its doc.
    Unknown,
    /// The decoder read every message and none of them was a ReadyForQuery.
    Absent,
    /// The status byte of the last ReadyForQuery the decoder saw.
    Present(u8),
}

/// Per message connection level state needed to parse and reencode postgres messages.
#[derive(Debug, Clone, PartialEq, Copy)]
pub struct PostgresCodecState {
    /// Tag parsing is direction aware: several tag bytes mean different messages
    /// depending on whether the client or the server sent them.
    pub is_request: bool,
    /// The message uses the tag-less startup framing (StartupMessage/CancelRequest).
    pub startup: bool,
    /// Sink responses only: this message is a PARTIAL chunk of a response train that is still being
    /// received — more chunks follow and only the last one completes the train. A partial chunk
    /// holds whole backend messages, so it parses and reencodes exactly like any other response;
    /// the flag exists so transforms can tell a piece of a train from a whole one.
    ///
    /// A partial chunk NEVER carries a request id — see [`PostgresDecoder::emit_partial_chunk`].
    pub partial: bool,
    /// Sink responses only: this message COMPLETES a train that was delivered in chunks. It carries
    /// the request id and the train's trailing messages, but everything before it already went out
    /// in earlier, id-less partials — so to anything that wants a WHOLE train (to cache it, to
    /// compare it, to learn a row shape from it) this is a fragment, not a result.
    ///
    /// Stamped by the decoder, which is the only layer that knows it chunked. A transform must not
    /// try to re-derive it by remembering that a partial went past: responses from more than one
    /// backend connection are merged into a single batch by the cluster sink, so a transform cannot
    /// tell which train an earlier partial belonged to. This flag rides on the message it describes.
    pub chunked_tail: bool,
    /// What the decoder saw of this response's trailing ReadyForQuery, so that asking for it costs
    /// a field read rather than a parse of the whole train. See [`trailing_ready_status`].
    pub trailing_ready_status: TrailingReadyStatus,
}

impl PostgresCodecState {
    /// A frontend message. `startup` selects the tag-less startup framing.
    pub fn request(startup: bool) -> Self {
        Self {
            is_request: true,
            startup,
            partial: false,
            chunked_tail: false,
            trailing_ready_status: TrailingReadyStatus::Unknown,
        }
    }

    /// A whole backend response train, or a single unrequested backend message.
    pub fn response() -> Self {
        Self {
            is_request: false,
            startup: false,
            partial: false,
            chunked_tail: false,
            trailing_ready_status: TrailingReadyStatus::Unknown,
        }
    }

    /// One chunk of a response train that is still being received. The only state that sets
    /// `partial`, so every other construction is a whole message by construction rather than by
    /// remembering to write `partial: false`.
    pub fn partial_response() -> Self {
        Self {
            is_request: false,
            startup: false,
            partial: true,
            chunked_tail: false,
            // A ReadyForQuery always completes a train, so it is never inside a partial. Left
            // Unknown rather than Absent because every caller skips partials before asking, so
            // claiming knowledge here would buy nothing and could only ever be wrong.
            trailing_ready_status: TrailingReadyStatus::Unknown,
        }
    }

    /// The message that completes a train already partly delivered as chunks.
    pub fn chunked_response_tail() -> Self {
        Self {
            is_request: false,
            startup: false,
            partial: false,
            chunked_tail: true,
            trailing_ready_status: TrailingReadyStatus::Unknown,
        }
    }

    /// Records what the decoder saw of this response's trailing ReadyForQuery.
    pub fn with_trailing_ready_status(mut self, status: TrailingReadyStatus) -> Self {
        self.trailing_ready_status = status;
        self
    }
}

#[derive(Clone)]
pub struct PostgresCodecBuilder {
    direction: Direction,
    message_latency: Histogram,
    stream_threshold_bytes: usize,
}

impl PostgresCodecBuilder {
    /// Sets the size, in bytes, past which the sink decoder emits an in-progress response train as
    /// partial chunks rather than accumulate the whole thing (see
    /// [`PostgresDecoder::stream_threshold_bytes`], which records what this does and does not bound
    /// on its own). `0`, the default, never chunks.
    ///
    /// # Which chains may enable it
    ///
    /// Every transform declares whether it can receive partial trains
    /// ([`TransformConfig::accepts_partial_responses`](crate::transforms::TransformConfig::accepts_partial_responses)),
    /// and shotover refuses to start a chain that streams into one that cannot — so a wrong
    /// combination is a startup error naming the transform, never silent misbehaviour.
    /// Each transform declares its own answer and says why, so the authoritative list is the
    /// declarations themselves rather than a copy here that would rot.
    ///
    /// A separate method rather than a `new` argument because [`CodecBuilder::new`]'s signature is
    /// fixed by the trait.
    pub fn with_stream_threshold(mut self, stream_threshold_bytes: usize) -> Self {
        self.stream_threshold_bytes = stream_threshold_bytes;
        self
    }
}

// Depending on if the codec is used in a sink or a source requires different processing logic:
// * Sources decode single frontend messages, which parse standalone.
// * Sinks decode backend messages and must group them into one response train per request.
//   To know which request is being answered (and therefore where each train ends) the sink
//   encoder sends a RequestInfo for every sent request to the decoder over an mpsc channel.
impl CodecBuilder for PostgresCodecBuilder {
    type Decoder = PostgresDecoder;
    type Encoder = PostgresEncoder;

    fn new(direction: Direction, destination_name: String) -> Self {
        let message_latency = message_latency(direction, destination_name);
        Self {
            direction,
            message_latency,
            stream_threshold_bytes: 0,
        }
    }

    fn build(&self) -> (PostgresDecoder, PostgresEncoder) {
        let (tx, rx) = match self.direction {
            Direction::Source => (None, None),
            Direction::Sink => {
                let (tx, rx) = mpsc::channel();
                (Some(tx), Some(rx))
            }
        };
        (
            PostgresDecoder::new(rx, self.direction, self.stream_threshold_bytes),
            PostgresEncoder::new(tx, self.direction, self.message_latency.clone()),
        )
    }

    fn protocol(&self) -> MessageType {
        MessageType::Postgres
    }
}

/// What kind of request was sent to the server, used by the sink decoder to
/// determine where its response train ends.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RequestKind {
    /// The startup message. Train ends at an authentication challenge, error or ReadyForQuery.
    Startup,
    /// A 'p' authentication data message. Same terminators as Startup.
    AuthenticationData,
    /// A simple 'Q' query. Train ends at ReadyForQuery or when a COPY FROM/BOTH begins.
    Query,
    /// Extended protocol messages, each answered by its own completion message.
    Parse,
    Bind,
    DescribeStatement,
    DescribePortal,
    Execute,
    Sync,
    Close,
    /// End of a COPY FROM STDIN stream. Terminator depends on whether the COPY
    /// was started by a simple query or by an extended protocol Execute.
    CopyDone,
    CopyFail,
    /// Anything else e.g. FunctionCall. Treated like a simple query: ends at ReadyForQuery.
    Other,
}

impl RequestKind {
    /// Whether this kind of request's response train may be emitted in partial chunks. Only row
    /// streams are eligible: a simple `Query` and an extended protocol `Execute` — which is also
    /// how a `COPY ... TO STDOUT` arrives, since its CopyOutResponse/CopyData/CopyDone messages
    /// continue the train of the request that started the copy. Every other train (startup and
    /// auth, Parse/Bind/Describe/Close/Sync completions, COPY FROM terminators) is small, and
    /// several transforms depend on receiving those whole.
    fn streamable(self) -> bool {
        matches!(self, RequestKind::Query | RequestKind::Execute)
    }
}

#[derive(Debug)]
pub struct RequestInfo {
    kind: RequestKind,
    id: MessageId,
    /// Whether this request's response train may be emitted in partial chunks, recorded when the
    /// request is sent. Today this is exactly [`RequestKind::streamable`], which is where the rule
    /// lives; it is carried per request so that eligibility can later narrow to something the
    /// decoder cannot see (an `Execute` with a row limit, say) without touching the decoder.
    streamable: bool,
}

/// How the in-progress COPY was initiated, which decides CopyDone/CopyFail terminators.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CopyMode {
    SimpleQuery,
    Extended,
}

/// The decision for one backend message against the current response train.
#[derive(Clone, Copy)]
enum TrainAction {
    /// The message belongs to the current train, more will follow.
    Continue,
    /// The message completes the current train.
    Complete,
    /// The message completes the current train AND the server will now discard
    /// further extended protocol messages until a Sync: emit dummy responses for them.
    CompleteAndDiscard,
}

pub struct PostgresDecoder {
    direction: Direction,

    /// Source only: the first message on a connection uses the tag-less startup framing.
    seen_startup: bool,

    /// Sink only: request info from the encoder, in send order.
    request_rx: Option<mpsc::Receiver<RequestInfo>>,
    /// Sink only: requests awaiting their response train, in order.
    pending: VecDeque<RequestInfo>,
    /// Sink only: the raw bytes of the response train being accumulated.
    train: BytesMut,
    /// Sink only: the status byte of the last ReadyForQuery appended to the train in progress.
    /// Taken when the train completes, so the completing message can carry it and nothing upstream
    /// has to parse a whole result to learn one byte.
    train_ready_status: Option<u8>,
    /// Sink only: the train in progress has already had chunks emitted, so the message that
    /// completes it holds only the tail of the result.
    ///
    /// Set only by [`PostgresDecoder::emit_partial_chunk`] and cleared only where the completing
    /// message is built, in the same `mem::take` that reads it. That single site is load-bearing:
    /// a second path that emitted a completing message without going through it would leave the
    /// tail unstamped, and everything above the codec would treat a fragment as a whole result.
    train_chunked: bool,
    /// Sink only: when the train started accumulating.
    train_started_at: Option<Instant>,
    /// Sink only: an error was returned for an extended protocol request, the server is
    /// discarding until the next Sync. Queued non-Sync requests receive dummy responses.
    discarding_until_sync: bool,
    /// Sink only: Some while a COPY FROM STDIN is in progress.
    copy_mode: Option<CopyMode>,
    /// Sink only: an in-progress STREAMABLE response train is emitted as a partial chunk rather
    /// than grow past this many bytes. `0` never chunks, which is the default and reproduces the
    /// unchunked behaviour exactly.
    ///
    /// On its own this takes peak RSS for a large result from roughly 6x the result size down to
    /// roughly 1.6x, by removing the result-sized accumulation buffer and the repeated doublings
    /// that grew it (measured on a 442 MB result: 2748 MB peak unchunked, 740-836 MB at a 1 MiB
    /// threshold, 658 MB at 64 KiB).
    ///
    /// It does NOT yet bound memory to O(threshold). The remaining ~1.6x is the chunks themselves:
    /// [`crate::transforms::postgres::exchange`] collects every chunk of a train before returning,
    /// because partials carry no request id and so nothing satisfies its drain loop until the final
    /// chunk — plus the source encoder's copy. Reaching O(threshold) needs the chain to forward
    /// partials incrementally and a bounded sink channel.
    stream_threshold_bytes: usize,
}

impl PostgresDecoder {
    pub fn new(
        request_rx: Option<mpsc::Receiver<RequestInfo>>,
        direction: Direction,
        stream_threshold_bytes: usize,
    ) -> Self {
        Self {
            direction,
            seen_startup: false,
            request_rx,
            pending: VecDeque::new(),
            train: BytesMut::new(),
            train_ready_status: None,
            train_chunked: false,
            train_started_at: None,
            discarding_until_sync: false,
            copy_mode: None,
            stream_threshold_bytes,
        }
    }

    fn decode_request(&mut self, src: &mut BytesMut) -> Result<Option<Messages>, CodecReadError> {
        let mut messages = vec![];
        loop {
            let startup = !self.seen_startup;
            let length = match message_wire_length(src, startup).map_err(CodecReadError::Parser)? {
                Some(length) => length,
                None => break,
            };
            if src.len() < length {
                break;
            }
            let received_at = Instant::now();
            let bytes = src.split_to(length).freeze();
            tracing::debug!(
                "{}: incoming postgres message:\n{}",
                self.direction,
                pretty_hex::pretty_hex(&bytes)
            );
            if startup {
                self.seen_startup = true;
            }
            messages.push(Message::from_bytes_at_instant(
                bytes,
                CodecState::Postgres(PostgresCodecState::request(startup)),
                Some(received_at),
            ));
        }
        if messages.is_empty() {
            Ok(None)
        } else {
            Ok(Some(messages))
        }
    }

    fn decode_response(&mut self, src: &mut BytesMut) -> Result<Option<Messages>, CodecReadError> {
        // Bring over any request info the encoder has sent since the last read.
        // A request is always fully sent (and its info in this channel) before the server
        // can possibly respond to it, so an empty channel means genuinely unrequested traffic.
        if let Some(rx) = self.request_rx.as_ref() {
            while let Ok(info) = rx.try_recv() {
                self.pending.push_back(info);
            }
        }

        let mut messages = vec![];

        // If the server is discarding until the next Sync, requests that arrived since the
        // error must be dummy-answered now, so the eventual ReadyForQuery pairs with the Sync.
        if self.discarding_until_sync {
            self.emit_dummies_until_sync(&mut messages);
        }
        loop {
            let length = match message_wire_length(src, false).map_err(CodecReadError::Parser)? {
                Some(length) => length,
                None => break,
            };
            if src.len() < length {
                break;
            }
            let received_at = Instant::now();
            let tag = src[0];
            // The auth code discriminates Authentication messages into
            // "challenge, client must answer" vs "progress, more of this train follows".
            let auth_code = if tag == b'R' && length >= 9 {
                Some(i32::from_be_bytes(src[5..9].try_into().unwrap()))
            } else {
                None
            };
            // A ReadyForQuery is tag, length, then one status byte.
            let ready_status = if tag == b'Z' && length >= 6 {
                Some(src[5])
            } else {
                None
            };
            let bytes = src.split_to(length);
            tracing::debug!(
                "{}: incoming postgres message:\n{}",
                self.direction,
                pretty_hex::pretty_hex(&bytes)
            );

            let (head_kind, head_streamable) = match self.pending.front() {
                Some(info) => (info.kind, info.streamable),
                None => {
                    // No request is awaiting a response: async server traffic
                    // (notices, notifications, parameter changes, or a dying gasp error).
                    // Forward each as its own unrequested response message.
                    messages.push(Message::from_bytes_at_instant(
                        bytes.freeze(),
                        CodecState::Postgres(
                            PostgresCodecState::response().with_trailing_ready_status(
                                match ready_status {
                                    Some(status) => TrailingReadyStatus::Present(status),
                                    None => TrailingReadyStatus::Absent,
                                },
                            ),
                        ),
                        Some(received_at),
                    ));
                    continue;
                }
            };

            // Decided before the flush so that a message which COMPLETES the train can never
            // trigger one. A train that only crosses the threshold on its terminator does not need
            // splitting, and splitting it would emit a pointless chunk and stamp the result as a
            // chunked tail — making a result that fitted perfectly well uncacheable. `train_action`
            // reads none of the state the flush touches, so deciding it first is free.
            let action = train_action(head_kind, tag, auth_code, self.copy_mode);

            // Flush what has accumulated BEFORE appending a message that would push the train past
            // the threshold, so the train buffer never has to grow beyond it and each chunk pins
            // only its own allocation. Never while the server is discarding until a Sync: those
            // requests are answered by dummies below, and a Sync train is not streamable anyway.
            if matches!(action, TrainAction::Continue)
                && self.stream_threshold_bytes > 0
                // Not an empty chunk when the train's very first message is itself over-sized.
                && !self.train.is_empty()
                && self.train.len() + bytes.len() > self.stream_threshold_bytes
                && head_streamable
                && !self.discarding_until_sync
            {
                messages.push(self.emit_partial_chunk());
            }

            // Deliberately not `train.is_empty()`: emitting a partial chunk empties `train`
            // mid-train, and the latency sample covers the WHOLE train. `train_started_at` is only
            // cleared when a train completes, so `is_none()` means "no train in progress".
            if self.train_started_at.is_none() {
                self.train_started_at = Some(received_at);
            }
            self.train.extend_from_slice(&bytes);
            if let Some(status) = ready_status {
                self.train_ready_status = Some(status);
            }

            match action {
                TrainAction::Continue => {}
                TrainAction::Complete | TrainAction::CompleteAndDiscard => {
                    // Track COPY FROM state transitions, which change CopyDone/CopyFail pairing.
                    match tag {
                        b'G' | b'W' => {
                            self.copy_mode = Some(match head_kind {
                                RequestKind::Query => CopyMode::SimpleQuery,
                                _ => CopyMode::Extended,
                            })
                        }
                        _ => {
                            if matches!(head_kind, RequestKind::CopyDone | RequestKind::CopyFail) {
                                self.copy_mode = None;
                            }
                        }
                    }

                    let info = self.pending.pop_front().unwrap();
                    // A train that had chunks emitted completes with only its tail, and says so:
                    // everything upstream that needs a whole train reads this off the message
                    // instead of trying to remember what went past earlier.
                    // Stamped on EVERY train completion, including the CompleteAndDiscard 'E'
                    // tail: a decoded train that reached a transform without its status recorded
                    // would send that transform back to parsing the whole result.
                    let status = match self.train_ready_status.take() {
                        Some(status) => TrailingReadyStatus::Present(status),
                        None => TrailingReadyStatus::Absent,
                    };
                    let state = if std::mem::take(&mut self.train_chunked) {
                        PostgresCodecState::chunked_response_tail()
                    } else {
                        PostgresCodecState::response()
                    }
                    .with_trailing_ready_status(status);
                    let mut message = Message::from_bytes_at_instant(
                        self.train.split().freeze(),
                        CodecState::Postgres(state),
                        self.train_started_at.take(),
                    );
                    message.set_request_id(info.id);
                    messages.push(message);

                    if matches!(action, TrainAction::CompleteAndDiscard) {
                        self.discarding_until_sync = true;
                    }
                    if self.discarding_until_sync {
                        // The server discards everything until the next Sync: answer the
                        // discarded requests with dummy responses to keep one response per request.
                        // The ReadyForQuery that completes the Sync train ends discard mode.
                        if tag == b'Z' {
                            self.discarding_until_sync = false;
                        } else {
                            self.emit_dummies_until_sync(&mut messages);
                        }
                    }
                }
            }
        }
        if messages.is_empty() {
            Ok(None)
        } else {
            Ok(Some(messages))
        }
    }

    /// Splits the whole backend messages accumulated so far off an in-progress response train and
    /// returns them as a PARTIAL CHUNK. The train continues accumulating into the next chunk; the
    /// chunk that finally completes it is emitted by the completion arm and carries the request id.
    ///
    /// # A partial chunk MUST carry no request id
    ///
    /// Every site in the proxy that accounts for a response counts only messages for which
    /// `request_id().is_some()`:
    /// * `count_answered` in [`crate::transforms::postgres::exchange`]'s drain loop,
    /// * `PendingRequests::Ordered::process_responses` in [`crate::source_task`],
    /// * `DummyResponseInserter::process_responses` in [`crate::connection`],
    /// * the `RequestPending` gauge in the sink connection's reader task.
    ///
    /// Give a partial an id and `exchange()` returns to the transform chain on the FIRST chunk,
    /// before the real response exists; every later chunk is then accounted against the NEXT
    /// request. That is a silent, unrecoverable client desync rather than an error. With no id, all
    /// four treat a partial exactly like the unrequested async server messages (notices,
    /// notifications) they already forward in order and never count — which is why chunking needs
    /// no change at any of them.
    ///
    /// `train_started_at` is deliberately not taken: the latency sample covers the whole train and
    /// is recorded once, by the final chunk.
    fn emit_partial_chunk(&mut self) -> Message {
        self.train_chunked = true;
        // `mem::replace` rather than `BytesMut::split`: split would leave `train` holding only the
        // SPARE capacity of the buffer it just handed to the chunk, and because the chunk keeps
        // that buffer alive `BytesMut` cannot reclaim it — every following append would reallocate
        // and copy the accumulating train until it doubled its way back up to the threshold. A
        // fresh buffer sized to the threshold fills exactly once, with no growth copies, and the
        // chunk owns its allocation outright instead of pinning a shared one.
        let chunk = std::mem::replace(
            &mut self.train,
            BytesMut::with_capacity(self.stream_threshold_bytes),
        )
        .freeze();
        // The decode loop only ever appends WHOLE backend messages to `train` — it breaks out when
        // fewer than `message_wire_length` bytes are buffered — so a chunk boundary can never fall
        // inside a message. One that did would desync the client permanently, so the invariant is
        // asserted here rather than merely argued.
        debug_assert!(
            ends_on_message_boundary(&chunk),
            "postgres partial chunk does not end on a backend message boundary"
        );
        Message::from_bytes(
            chunk,
            CodecState::Postgres(PostgresCodecState::partial_response()),
        )
    }

    /// Pops queued requests up to (but not including) the next Sync, answering each with a dummy.
    fn emit_dummies_until_sync(&mut self, messages: &mut Messages) {
        while let Some(info) = self.pending.front() {
            if matches!(info.kind, RequestKind::Sync) {
                break;
            }
            let info = self.pending.pop_front().unwrap();
            let mut dummy = Message::from_frame(Frame::Dummy);
            dummy.set_request_id(info.id);
            messages.push(dummy);
        }
    }
}

/// Whether `message` is a partial chunk of a response train rather than a whole one.
///
/// Matched rather than unwrapped through [`CodecState::as_postgres`], which panics on the
/// `CodecState::Dummy` carried by a dummy response.
pub fn is_partial_response(message: &Message) -> bool {
    matches!(message.codec_state, CodecState::Postgres(state) if state.partial)
}

/// The status byte of the last ReadyForQuery in a postgres response, or `None` if it has none.
///
/// Reads what the decoder recorded where there is a record, which is the entire point: the
/// alternative is parsing a whole response train — for a large result, millions of typed messages
/// that `Message::frame` then retains alongside the raw bytes — to learn one byte. Non-postgres
/// messages and dummies answer `None` without being touched.
///
/// # Do not call this on a partial chunk
///
/// A partial is recorded [`TrailingReadyStatus::Unknown`] — a ReadyForQuery completes a train, so
/// one is never inside a chunk — which means asking would fall back to PARSING a chunk that may be
/// as large as `stream_threshold_bytes`. Guard with [`is_partial_response`] first, as the three
/// call sites do. Everything else that lands in the fallback is small: a message a transform built
/// from a frame is already parsed, so reading the status off it is free, and one modified since
/// decoding is the same. A large decoded train always carries its record.
///
/// # It does not remove every parse from every caller
///
/// It removes the parse this question used to require. A caller that parses the same response for
/// another reason still pays for that: `PostgresReadCache` scans for ParameterStatus via
/// `capture_rendering_gucs` before asking, so in a chain containing the cache the train is parsed
/// regardless and only `RequestThrottling` and `PostgresSinkCluster` realise the saving.
pub fn trailing_ready_status(response: &mut Message) -> Option<u8> {
    if let CodecState::Postgres(state) = response.codec_state {
        match state.trailing_ready_status {
            TrailingReadyStatus::Present(status) => return Some(status),
            TrailingReadyStatus::Absent => return None,
            TrailingReadyStatus::Unknown => {}
        }
    } else {
        // A dummy, or another protocol entirely: never parse it looking for postgres messages.
        return None;
    }

    if let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() {
        for message in messages.iter().rev() {
            if let BackendMessage::ReadyForQuery { status } = message {
                return Some(*status);
            }
        }
    }
    None
}

/// Whether `message` completes a response train that was delivered in chunks, and therefore holds
/// only the tail of its result. See [`PostgresCodecState::chunked_tail`].
pub fn is_chunked_train_tail(message: &Message) -> bool {
    matches!(message.codec_state, CodecState::Postgres(state) if state.chunked_tail)
}

/// Whether `bytes` holds a whole number of backend messages, i.e. walking their length headers
/// lands exactly on the end. Only used by [`PostgresDecoder::emit_partial_chunk`]'s assertion.
fn ends_on_message_boundary(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        // A tagged message is always at least 5 bytes, so this always makes progress.
        match message_wire_length(&bytes[offset..], false) {
            Ok(Some(length)) if offset + length <= bytes.len() => offset += length,
            _ => return false,
        }
    }
    true
}

/// Decides whether a backend message continues or completes the response train
/// of the head request. Driven by tag bytes rather than parsed frames so that
/// even messages whose typed parse degrades to Raw pair correctly.
fn train_action(
    head: RequestKind,
    tag: u8,
    auth_code: Option<i32>,
    copy_mode: Option<CopyMode>,
) -> TrainAction {
    // Async messages never terminate any train.
    if matches!(tag, b'N' | b'A') {
        return TrainAction::Continue;
    }
    match head {
        RequestKind::Startup | RequestKind::AuthenticationData => match tag {
            // AuthenticationOk (0) and SASLFinal (12) are followed by more of the train.
            // Every other authentication code is a challenge the client must answer.
            b'R' => match auth_code {
                Some(0) | Some(12) => TrainAction::Continue,
                _ => TrainAction::Complete,
            },
            // Authentication failure: the server sends no ReadyForQuery, just the error.
            b'E' => TrainAction::Complete,
            b'Z' => TrainAction::Complete,
            _ => TrainAction::Continue,
        },
        RequestKind::Query | RequestKind::Other => match tag {
            b'Z' => TrainAction::Complete,
            // COPY FROM STDIN / copy-both begins: the client streams next, the train ends here.
            b'G' | b'W' => TrainAction::Complete,
            _ => TrainAction::Continue,
        },
        RequestKind::Parse => match tag {
            b'1' => TrainAction::Complete,
            b'E' => TrainAction::CompleteAndDiscard,
            _ => TrainAction::Continue,
        },
        RequestKind::Bind => match tag {
            b'2' => TrainAction::Complete,
            b'E' => TrainAction::CompleteAndDiscard,
            _ => TrainAction::Continue,
        },
        RequestKind::DescribeStatement => match tag {
            // ParameterDescription then RowDescription or NoData.
            b'T' | b'n' => TrainAction::Complete,
            b'E' => TrainAction::CompleteAndDiscard,
            _ => TrainAction::Continue,
        },
        RequestKind::DescribePortal => match tag {
            b'T' | b'n' => TrainAction::Complete,
            b'E' => TrainAction::CompleteAndDiscard,
            _ => TrainAction::Continue,
        },
        RequestKind::Execute => match tag {
            b'C' | b's' | b'I' => TrainAction::Complete,
            b'G' | b'W' => TrainAction::Complete,
            b'E' => TrainAction::CompleteAndDiscard,
            _ => TrainAction::Continue,
        },
        RequestKind::Close => match tag {
            b'3' => TrainAction::Complete,
            b'E' => TrainAction::CompleteAndDiscard,
            _ => TrainAction::Continue,
        },
        RequestKind::Sync => match tag {
            b'Z' => TrainAction::Complete,
            _ => TrainAction::Continue,
        },
        RequestKind::CopyDone | RequestKind::CopyFail => match copy_mode {
            Some(CopyMode::Extended) => match tag {
                b'C' => TrainAction::Complete,
                b'E' => TrainAction::CompleteAndDiscard,
                _ => TrainAction::Continue,
            },
            // Simple query COPY: the server finishes with CommandComplete/ErrorResponse
            // and then ReadyForQuery, all one train.
            _ => match tag {
                b'Z' => TrainAction::Complete,
                _ => TrainAction::Continue,
            },
        },
    }
}

impl Decoder for PostgresDecoder {
    type Item = Messages;
    type Error = CodecReadError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.direction {
            Direction::Source => self.decode_request(src),
            Direction::Sink => self.decode_response(src),
        }
    }
}

pub struct PostgresEncoder {
    message_latency: Histogram,
    // Some when Sink (because it sends requests)
    request_tx: Option<mpsc::Sender<RequestInfo>>,
    direction: Direction,
}

impl PostgresEncoder {
    pub fn new(
        request_tx: Option<mpsc::Sender<RequestInfo>>,
        direction: Direction,
        message_latency: Histogram,
    ) -> Self {
        Self {
            message_latency,
            request_tx,
            direction,
        }
    }
}

impl Encoder<Messages> for PostgresEncoder {
    type Error = CodecWriteError;

    fn encode(&mut self, item: Messages, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.into_iter().try_for_each(|mut m| {
            let start = dst.len();
            m.ensure_message_type(MessageType::Postgres)
                .map_err(CodecWriteError::Encoder)?;
            let response_is_dummy = m.response_is_dummy();
            let id = m.id();
            let received_at = m.received_from_source_or_sink_at;
            let startup = match m.codec_state {
                CodecState::Postgres(state) => state.startup,
                _ => false,
            };
            let result = match m.into_encodable() {
                Encodable::Bytes(bytes) => {
                    dst.extend_from_slice(&bytes);
                    Ok(())
                }
                Encodable::Frame(frame) => {
                    let frame = frame.into_postgres().map_err(CodecWriteError::Encoder)?;
                    frame.encode(dst).map_err(CodecWriteError::Encoder)
                }
            };
            result?;

            // Tell the decoder what kind of request this is so it can pair the
            // response train, unless the message wrote nothing (Dummy) or the
            // server will not respond to it.
            if !dst[start..].is_empty()
                && !response_is_dummy
                && let Some(tx) = self.request_tx.as_ref()
            {
                let kind = if startup {
                    RequestKind::Startup
                } else {
                    match dst[start] {
                        b'Q' => RequestKind::Query,
                        b'P' => RequestKind::Parse,
                        b'B' => RequestKind::Bind,
                        // The statement/portal kind byte sits right after the tag and length.
                        b'D' => match dst.get(start + 5) {
                            Some(b'S') => RequestKind::DescribeStatement,
                            _ => RequestKind::DescribePortal,
                        },
                        b'E' => RequestKind::Execute,
                        b'S' => RequestKind::Sync,
                        b'C' => RequestKind::Close,
                        b'c' => RequestKind::CopyDone,
                        b'f' => RequestKind::CopyFail,
                        b'p' => RequestKind::AuthenticationData,
                        _ => RequestKind::Other,
                    }
                };
                tx.send(RequestInfo {
                    kind,
                    id,
                    streamable: kind.streamable(),
                })
                .map_err(|e| CodecWriteError::Encoder(anyhow!(e)))?;
            }

            if let Some(received_at) = received_at {
                self.message_latency.record(received_at.elapsed());
            }
            if !dst[start..].is_empty() {
                tracing::debug!(
                    "{}: outgoing postgres message:\n{}",
                    self.direction,
                    pretty_hex::pretty_hex(&&dst[start..])
                );
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    use crate::frame::PostgresFrame;
    use crate::frame::postgres::{
        AuthenticationMessage, BackendMessage, FieldDescription, FrontendMessage,
    };
    use bytes::{BufMut, Bytes};
    use pretty_assertions::assert_eq;

    fn source_codec() -> (PostgresDecoder, PostgresEncoder) {
        PostgresCodecBuilder::new(Direction::Source, "postgres".to_owned()).build()
    }

    fn sink_codec() -> (PostgresDecoder, PostgresEncoder) {
        sink_codec_with_threshold(0)
    }

    /// A sink codec that chunks a streamable response train rather than let it exceed `bytes`.
    fn sink_codec_with_threshold(bytes: usize) -> (PostgresDecoder, PostgresEncoder) {
        PostgresCodecBuilder::new(Direction::Sink, "postgres".to_owned())
            .with_stream_threshold(bytes)
            .build()
    }

    fn query_message(query: &str) -> Message {
        Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Query {
                query: query.to_owned(),
            },
        )))
    }

    /// A one column int4 RowDescription.
    fn row_description(name: &str) -> BackendMessage {
        BackendMessage::RowDescription {
            fields: vec![FieldDescription {
                name: name.to_owned(),
                table_oid: 0,
                column_attribute_number: 1,
                data_type_oid: 23,
                data_type_size: 4,
                type_modifier: -1,
                format_code: 0,
            }],
        }
    }

    /// A row stream: RowDescription, `rows` DataRows, CommandComplete, ReadyForQuery.
    fn row_stream_train(rows: usize) -> BytesMut {
        let mut messages = vec![row_description("n")];
        messages.extend((0..rows).map(|i| BackendMessage::DataRow {
            values: vec![Some(Bytes::from(i.to_string()))],
        }));
        messages.push(BackendMessage::CommandComplete {
            tag: format!("SELECT {rows}"),
        });
        messages.push(BackendMessage::ReadyForQuery { status: b'I' });
        encode_backend(messages)
    }

    fn is_partial(message: &Message) -> bool {
        is_partial_response(message)
    }

    /// The streaming contract, asserted identically for every chunked train: it arrived in more
    /// than one message; every chunk but the last is an id-less partial; the last carries
    /// `query_id` and is marked as the TAIL of a chunked train rather than a whole response; and
    /// the chunks concatenate back to exactly the bytes the server sent, so no byte was dropped,
    /// duplicated or reordered by chunking.
    fn assert_chunked_train(messages: Messages, query_id: MessageId, train: &BytesMut) {
        assert!(
            messages.len() > 1,
            "expected the train to be chunked, got {} message(s)",
            messages.len()
        );

        let (final_chunk, partials) = messages.split_last().unwrap();
        for partial in partials {
            assert_eq!(
                partial.request_id(),
                None,
                "a partial chunk must never carry a request id"
            );
            assert!(is_partial(partial));
        }
        assert_eq!(final_chunk.request_id(), Some(query_id));
        assert!(!is_partial(final_chunk));
        // Everything above the codec learns "this result is not whole" from this stamp, so it must
        // be set by the decoder itself — a transform cannot re-derive it, because the cluster sink
        // merges responses from two backend connections into one batch.
        assert!(is_chunked_train_tail(final_chunk));
        // The ReadyForQuery that ends the train is in this chunk, so its status is recorded here.
        assert_eq!(
            final_chunk.codec_state.as_postgres().trailing_ready_status,
            TrailingReadyStatus::Present(b'I')
        );

        let mut rejoined = BytesMut::new();
        for message in messages {
            rejoined.extend_from_slice(&message_bytes(message));
        }
        assert_eq!(rejoined, *train);
    }

    /// Drives the extended protocol error path — a pipelined Parse/Bind/Execute/Sync whose Parse
    /// the server rejects — and asserts the pairing it must produce: the error train to the Parse,
    /// dummy responses to the Bind and Execute the server discarded, the ReadyForQuery to the
    /// Sync, and no partial chunk anywhere.
    fn assert_error_skips_to_sync((mut decoder, mut encoder): (PostgresDecoder, PostgresEncoder)) {
        let mut sent = BytesMut::new();
        let requests = vec![
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Parse {
                    statement_name: "".to_owned(),
                    query: "SELECT * FROM missing_table".to_owned(),
                    parameter_data_types: vec![],
                },
            ))),
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Bind {
                    portal_name: "".to_owned(),
                    statement_name: "".to_owned(),
                    parameter_format_codes: vec![],
                    parameter_values: vec![],
                    result_format_codes: vec![],
                },
            ))),
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Execute {
                    portal_name: "".to_owned(),
                    max_rows: 0,
                },
            ))),
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Sync,
            ))),
        ];
        let ids: Vec<MessageId> = requests.iter().map(|m| m.id()).collect();
        encoder.encode(requests, &mut sent).unwrap();

        let mut response = encode_backend(vec![
            BackendMessage::ErrorResponse {
                fields: vec![
                    (b'S', "ERROR".to_owned()),
                    (b'C', "42P01".to_owned()),
                    (b'M', "relation \"missing_table\" does not exist".to_owned()),
                ],
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let mut messages = decoder.decode(&mut response).unwrap().unwrap();

        assert_eq!(messages.len(), 4);
        assert!(messages.iter().all(|m| !is_partial(m)));
        assert_eq!(
            messages.iter().map(|m| m.request_id()).collect::<Vec<_>>(),
            ids.iter().copied().map(Some).collect::<Vec<_>>()
        );
        // Parse gets the error train.
        match messages[0].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => {
                assert!(train[0].error_message().unwrap().contains("missing_table"));
            }
            other => panic!("expected Response, got {other:?}"),
        }
        // Bind and Execute get dummies.
        assert!(messages[1].is_dummy());
        assert!(messages[2].is_dummy());
        // Sync gets the ReadyForQuery.
        match messages[3].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => {
                assert_eq!(train[0], BackendMessage::ReadyForQuery { status: b'I' });
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    /// The raw wire bytes of a decoded message. Parsing a message's frame leaves its bytes intact,
    /// so this is what the server actually sent, not a reencoding of it.
    fn message_bytes(message: Message) -> Bytes {
        match message.into_encodable() {
            Encodable::Bytes(bytes) => bytes,
            Encodable::Frame(_) => panic!("expected a message still backed by its raw bytes"),
        }
    }

    fn encode_frontend(messages: Vec<FrontendMessage>) -> BytesMut {
        let mut bytes = BytesMut::new();
        for message in messages {
            message.encode(&mut bytes).unwrap();
        }
        bytes
    }

    fn encode_backend(messages: Vec<BackendMessage>) -> BytesMut {
        let mut bytes = BytesMut::new();
        for message in messages {
            message.encode(&mut bytes).unwrap();
        }
        bytes
    }

    fn startup_message() -> FrontendMessage {
        FrontendMessage::Startup {
            protocol_version: 196608,
            parameters: vec![("user".to_owned(), "admin".to_owned())],
        }
    }

    /// Source: startup framing then tagged framing, decode and reencode byte identical.
    #[test]
    fn test_source_decode_encode_round_trip() {
        let (mut decoder, mut encoder) = source_codec();

        let mut bytes = encode_frontend(vec![startup_message()]);
        bytes.extend_from_slice(&encode_frontend(vec![FrontendMessage::Query {
            query: "SELECT 1".to_owned(),
        }]));
        let original = bytes.clone();

        let mut messages = decoder.decode(&mut bytes).unwrap().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(bytes.is_empty());

        // The startup message parses under startup framing, the query under tagged framing.
        assert_eq!(
            messages[0].frame().unwrap(),
            &mut Frame::Postgres(PostgresFrame::Request(startup_message()))
        );
        assert_eq!(
            messages[1].frame().unwrap(),
            &mut Frame::Postgres(PostgresFrame::Request(FrontendMessage::Query {
                query: "SELECT 1".to_owned(),
            }))
        );

        let mut dest = BytesMut::new();
        encoder.encode(messages, &mut dest).unwrap();
        assert_eq!(original, dest);
    }

    /// Source: a partial message decodes to None until the rest arrives.
    #[test]
    fn test_source_partial_message() {
        let (mut decoder, _) = source_codec();
        let full = encode_frontend(vec![startup_message()]);
        let mut partial = BytesMut::from(&full[..5]);
        assert!(decoder.decode(&mut partial).unwrap().is_none());
        partial.extend_from_slice(&full[5..]);
        assert_eq!(decoder.decode(&mut partial).unwrap().unwrap().len(), 1);
    }

    /// Sink: the response train to one query aggregates into ONE message
    /// carrying the request id of the query.
    #[test]
    fn test_sink_aggregates_query_response_train() {
        let (mut decoder, mut encoder) = sink_codec();

        // Send a query through the encoder so the decoder knows what to pair.
        let query = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Query {
                query: "SELECT company_id FROM bronze.company".to_owned(),
            },
        )));
        let query_id = query.id();
        let mut sent = BytesMut::new();
        encoder.encode(vec![query], &mut sent).unwrap();

        // The server responds with a full train, arriving in two chunks.
        let train = encode_backend(vec![
            BackendMessage::RowDescription {
                fields: vec![FieldDescription {
                    name: "company_id".to_owned(),
                    table_oid: 0,
                    column_attribute_number: 1,
                    data_type_oid: 23,
                    data_type_size: 4,
                    type_modifier: -1,
                    format_code: 0,
                }],
            },
            BackendMessage::DataRow {
                values: vec![Some(Bytes::from_static(b"300"))],
            },
            BackendMessage::DataRow {
                values: vec![Some(Bytes::from_static(b"400"))],
            },
            BackendMessage::CommandComplete {
                tag: "SELECT 2".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let split_at = train.len() / 2;
        let mut chunk = BytesMut::from(&train[..split_at]);
        // Partial train: nothing is produced yet.
        assert!(decoder.decode(&mut chunk).unwrap().is_none());
        chunk.extend_from_slice(&train[split_at..]);

        let mut messages = decoder.decode(&mut chunk).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].request_id(), Some(query_id));
        // A whole train is not a tail: nothing upstream should treat it as a fragment.
        assert!(!is_chunked_train_tail(&messages[0]));
        match messages[0].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => {
                assert_eq!(train.len(), 5);
                assert_eq!(train[4], BackendMessage::ReadyForQuery { status: b'I' });
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    /// Sink: startup authentication is multiple round trips, each its own train:
    /// Startup -> SASL offer, AuthData -> SASLContinue, AuthData -> Ok..ReadyForQuery.
    #[test]
    fn test_sink_pairs_sasl_auth_round_trips() {
        let (mut decoder, mut encoder) = sink_codec();
        let mut sent = BytesMut::new();

        let startup =
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(startup_message())));
        let startup_id = startup.id();
        encoder.encode(vec![startup], &mut sent).unwrap();

        let mut offer = encode_backend(vec![BackendMessage::Authentication(
            AuthenticationMessage::Sasl {
                mechanisms: vec!["SCRAM-SHA-256".to_owned()],
            },
        )]);
        let messages = decoder.decode(&mut offer).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].request_id(), Some(startup_id));

        let first = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::AuthenticationData(Bytes::from_static(b"n,,n=,r=nonce")),
        )));
        let first_id = first.id();
        encoder.encode(vec![first], &mut sent).unwrap();

        let mut challenge = encode_backend(vec![BackendMessage::Authentication(
            AuthenticationMessage::SaslContinue {
                data: Bytes::from_static(b"r=nonce123,s=salt,i=4096"),
            },
        )]);
        let messages = decoder.decode(&mut challenge).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].request_id(), Some(first_id));

        let last = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::AuthenticationData(Bytes::from_static(b"c=biws,r=nonce123,p=proof")),
        )));
        let last_id = last.id();
        encoder.encode(vec![last], &mut sent).unwrap();

        // SASLFinal and AuthenticationOk continue the train through to ReadyForQuery.
        let mut finale = encode_backend(vec![
            BackendMessage::Authentication(AuthenticationMessage::SaslFinal {
                data: Bytes::from_static(b"v=verifier"),
            }),
            BackendMessage::Authentication(AuthenticationMessage::Ok),
            BackendMessage::ParameterStatus {
                name: "server_version".to_owned(),
                value: "18.0".to_owned(),
            },
            BackendMessage::BackendKeyData {
                process_id: 7,
                secret_key: Bytes::from_static(&[0, 0, 0, 7]),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let mut messages = decoder.decode(&mut finale).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].request_id(), Some(last_id));
        match messages[0].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => assert_eq!(train.len(), 5),
            other => panic!("expected Response, got {other:?}"),
        }
    }

    /// Sink: an extended protocol pipeline pairs each message with its own completion,
    /// and the whole pipeline still produces exactly one response per request.
    #[test]
    fn test_sink_pairs_extended_query_pipeline() {
        let (mut decoder, mut encoder) = sink_codec();
        let mut sent = BytesMut::new();

        let requests = vec![
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Parse {
                    statement_name: "".to_owned(),
                    query: "SELECT $1::int".to_owned(),
                    parameter_data_types: vec![],
                },
            ))),
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Bind {
                    portal_name: "".to_owned(),
                    statement_name: "".to_owned(),
                    parameter_format_codes: vec![],
                    parameter_values: vec![Some(Bytes::from_static(b"1"))],
                    result_format_codes: vec![],
                },
            ))),
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Describe {
                    kind: b'P',
                    name: "".to_owned(),
                },
            ))),
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Execute {
                    portal_name: "".to_owned(),
                    max_rows: 0,
                },
            ))),
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::Sync,
            ))),
        ];
        let ids: Vec<MessageId> = requests.iter().map(|m| m.id()).collect();
        encoder.encode(requests, &mut sent).unwrap();

        let mut response = encode_backend(vec![
            BackendMessage::ParseComplete,
            BackendMessage::BindComplete,
            BackendMessage::RowDescription {
                fields: vec![FieldDescription {
                    name: "int4".to_owned(),
                    table_oid: 0,
                    column_attribute_number: 0,
                    data_type_oid: 23,
                    data_type_size: 4,
                    type_modifier: -1,
                    format_code: 0,
                }],
            },
            BackendMessage::DataRow {
                values: vec![Some(Bytes::from_static(b"1"))],
            },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let messages = decoder.decode(&mut response).unwrap().unwrap();
        assert_eq!(messages.len(), 5);
        for (message, id) in messages.iter().zip(&ids) {
            assert_eq!(message.request_id(), Some(*id));
        }
    }

    /// Sink: an error to a Parse pairs with the Parse, queued requests get dummy
    /// responses, and the Sync gets the ReadyForQuery.
    #[test]
    fn test_sink_error_skip_to_sync() {
        assert_error_skips_to_sync(sink_codec());
    }

    /// Sink: COPY FROM STDIN over a simple query. The Query train ends at CopyInResponse,
    /// CopyData/Flush get no pairing (they are dummy-response requests), and CopyDone
    /// collects CommandComplete + ReadyForQuery.
    #[test]
    fn test_sink_copy_in_flow() {
        let (mut decoder, mut encoder) = sink_codec();
        let mut sent = BytesMut::new();

        let query = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Query {
                query: "COPY t FROM STDIN".to_owned(),
            },
        )));
        let query_id = query.id();
        encoder.encode(vec![query], &mut sent).unwrap();

        let mut response = encode_backend(vec![BackendMessage::CopyInResponse {
            overall_format: 0,
            column_formats: vec![0],
        }]);
        let messages = decoder.decode(&mut response).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].request_id(), Some(query_id));

        // CopyData produces no RequestInfo: the server will not respond to it.
        let copy_data = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::CopyData(Bytes::from_static(b"1\tx\n")),
        )));
        encoder.encode(vec![copy_data], &mut sent).unwrap();

        let copy_done = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::CopyDone,
        )));
        let done_id = copy_done.id();
        encoder.encode(vec![copy_done], &mut sent).unwrap();

        let mut response = encode_backend(vec![
            BackendMessage::CommandComplete {
                tag: "COPY 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let messages = decoder.decode(&mut response).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].request_id(), Some(done_id));
    }

    /// Sink: async server messages with no pending request pass through as
    /// unrequested responses (the valkey pubsub precedent).
    #[test]
    fn test_sink_unrequested_async_messages() {
        let (mut decoder, _encoder) = sink_codec();
        let mut bytes = encode_backend(vec![
            BackendMessage::NotificationResponse {
                process_id: 99,
                channel: "events".to_owned(),
                payload: "hello".to_owned(),
            },
            BackendMessage::ParameterStatus {
                name: "TimeZone".to_owned(),
                value: "UTC".to_owned(),
            },
        ]);
        let messages = decoder.decode(&mut bytes).unwrap().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].request_id(), None);
        assert_eq!(messages[1].request_id(), None);
    }

    /// Sink: a NoticeResponse mid-train stays inside the train it interrupts.
    #[test]
    fn test_sink_notice_stays_in_train() {
        let (mut decoder, mut encoder) = sink_codec();
        let mut sent = BytesMut::new();

        let query = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Query {
                query: "DROP TABLE IF EXISTS missing".to_owned(),
            },
        )));
        let query_id = query.id();
        encoder.encode(vec![query], &mut sent).unwrap();

        let mut response = encode_backend(vec![
            BackendMessage::NoticeResponse {
                fields: vec![(
                    b'M',
                    "table \"missing\" does not exist, skipping".to_owned(),
                )],
            },
            BackendMessage::CommandComplete {
                tag: "DROP TABLE".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let mut messages = decoder.decode(&mut response).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].request_id(), Some(query_id));
        match messages[0].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => assert_eq!(train.len(), 3),
            other => panic!("expected Response, got {other:?}"),
        }
    }

    /// Terminate is a fire-and-forget request: no RequestInfo is sent for it,
    /// so a subsequent unrequested server message does not mispair.
    #[test]
    fn test_sink_terminate_produces_no_pairing() {
        let (mut decoder, mut encoder) = sink_codec();
        let mut sent = BytesMut::new();
        let terminate = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Terminate,
        )));
        encoder.encode(vec![terminate], &mut sent).unwrap();
        // 'X' message written to the wire...
        assert_eq!(sent[0], b'X');
        // ...but nothing pends: a stray server notice decodes as unrequested.
        let mut bytes = encode_backend(vec![BackendMessage::NoticeResponse {
            fields: vec![(b'M', "shutting down".to_owned())],
        }]);
        let messages = decoder.decode(&mut bytes).unwrap().unwrap();
        assert_eq!(messages[0].request_id(), None);
    }

    /// A garbage first message (e.g. a TLS ClientHello reaching a plaintext source)
    /// produces a parser error rather than a huge allocation.
    #[test]
    fn test_garbage_startup_errors() {
        let (mut decoder, _) = source_codec();
        let mut bytes = BytesMut::new();
        bytes.put_slice(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01]);
        assert!(matches!(
            decoder.decode(&mut bytes),
            Err(CodecReadError::Parser(_))
        ));
    }

    /// Streaming: a train past the threshold is emitted in several chunks, each holding WHOLE
    /// backend messages, and the chunks concatenate back to exactly the bytes the server sent.
    /// A chunk boundary inside a message would desync the client permanently.
    #[test]
    fn test_sink_chunks_on_message_boundaries() {
        let (mut decoder, mut encoder) = sink_codec_with_threshold(64);
        let mut sent = BytesMut::new();
        let query = query_message("SELECT n FROM t");
        let query_id = query.id();
        encoder.encode(vec![query], &mut sent).unwrap();

        let train = row_stream_train(20);
        let mut response = train.clone();
        let mut messages = decoder.decode(&mut response).unwrap().unwrap();
        assert!(response.is_empty());

        // Every chunk parses as a run of backend messages. A chunk cut inside a message could not.
        for message in &mut messages {
            match message.frame().unwrap() {
                Frame::Postgres(PostgresFrame::Response(train)) => assert!(!train.is_empty()),
                other => panic!("expected Response, got {other:?}"),
            }
        }
        assert_chunked_train(messages, query_id, &train);
    }

    /// Streaming: THE load bearing rule. Only the chunk that completes the train carries the
    /// request id — an id on a partial would end `exchange()`'s drain loop before the real
    /// response arrived, silently desyncing the client.
    #[test]
    fn test_sink_partial_chunks_carry_no_request_id() {
        let (mut decoder, mut encoder) = sink_codec_with_threshold(64);
        let mut sent = BytesMut::new();
        let query = query_message("SELECT n FROM t");
        let query_id = query.id();
        encoder.encode(vec![query], &mut sent).unwrap();

        let train = row_stream_train(20);
        let mut response = train.clone();
        let mut messages = decoder.decode(&mut response).unwrap().unwrap();

        // The id lands on the chunk that actually completes the train, not merely on the last one
        // to arrive: it is the chunk carrying the ReadyForQuery that ends it.
        match messages.last_mut().unwrap().frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => assert_eq!(
                train.last().unwrap(),
                &BackendMessage::ReadyForQuery { status: b'I' }
            ),
            other => panic!("expected Response, got {other:?}"),
        }
        assert_chunked_train(messages, query_id, &train);
    }

    /// Streaming: discard-until-sync is untouched. With the threshold as low as it goes, the
    /// extended protocol error path pairs exactly as it does with streaming off, and chunks
    /// nothing — the requests it answers are dummies, and a Sync train is not streamable.
    #[test]
    fn test_sink_discard_until_sync_unaffected_by_streaming() {
        assert_error_skips_to_sync(sink_codec_with_threshold(1));
    }

    /// The decoder records the trailing ReadyForQuery status as it closes a train, so asking for it
    /// costs a field read. Without the record every caller parses the whole result to learn a byte.
    #[test]
    fn test_sink_records_trailing_ready_status() {
        let (mut decoder, mut encoder) = sink_codec();
        let mut sent = BytesMut::new();
        encoder
            .encode(vec![query_message("SELECT n FROM t")], &mut sent)
            .unwrap();

        let mut response = encode_backend(vec![
            row_description("n"),
            BackendMessage::DataRow {
                values: vec![Some(Bytes::from_static(b"1"))],
            },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'T' },
        ]);
        let mut messages = decoder.decode(&mut response).unwrap().unwrap();

        assert_eq!(
            messages[0].codec_state.as_postgres().trailing_ready_status,
            TrailingReadyStatus::Present(b'T')
        );
        assert_eq!(trailing_ready_status(&mut messages[0]), Some(b'T'));
    }

    /// A train with no ReadyForQuery records that fact, rather than leaving callers unable to tell
    /// "no ReadyForQuery" from "nobody looked" — which would have them parse it to find out.
    #[test]
    fn test_sink_records_absent_ready_status() {
        let (mut decoder, mut encoder) = sink_codec();
        let mut sent = BytesMut::new();
        let parse = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Parse {
                statement_name: "".to_owned(),
                query: "SELECT 1".to_owned(),
                parameter_data_types: vec![],
            },
        )));
        encoder.encode(vec![parse], &mut sent).unwrap();

        let mut response = encode_backend(vec![BackendMessage::ParseComplete]);
        let mut messages = decoder.decode(&mut response).unwrap().unwrap();

        assert_eq!(
            messages[0].codec_state.as_postgres().trailing_ready_status,
            TrailingReadyStatus::Absent
        );
        assert_eq!(trailing_ready_status(&mut messages[0]), None);
    }

    /// THE safety property: a transform that rewrites a ReadyForQuery must not leave the decoder's
    /// record readable, or the next reader gets the status the response USED to carry.
    /// `RequestThrottling::set_postgres_rfq_status` does exactly this rewrite.
    #[test]
    fn test_trailing_ready_status_is_invalidated_by_a_frame_change() {
        let (mut decoder, mut encoder) = sink_codec();
        let mut sent = BytesMut::new();
        encoder
            .encode(vec![query_message("SELECT n FROM t")], &mut sent)
            .unwrap();

        let mut response = encode_backend(vec![
            BackendMessage::CommandComplete {
                tag: "SELECT 0".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let mut messages = decoder.decode(&mut response).unwrap().unwrap();
        assert_eq!(trailing_ready_status(&mut messages[0]), Some(b'I'));

        match messages[0].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => {
                for message in train.iter_mut() {
                    if let BackendMessage::ReadyForQuery { status } = message {
                        *status = b'T';
                    }
                }
            }
            other => panic!("expected Response, got {other:?}"),
        }
        messages[0].invalidate_cache();

        assert_eq!(
            trailing_ready_status(&mut messages[0]),
            Some(b'T'),
            "the rewritten status must be read, not the decoder's record of the original"
        );
    }

    /// Streaming: a train that only crosses the threshold on its TERMINATING message is not
    /// split. Splitting it would emit a pointless chunk and stamp the result as a chunked tail,
    /// making a result that fitted perfectly well uncacheable upstream.
    #[test]
    fn test_sink_does_not_chunk_on_the_terminating_message() {
        let mut backend = vec![row_description("n")];
        backend.extend((0..20).map(|i| BackendMessage::DataRow {
            values: vec![Some(Bytes::from(i.to_string()))],
        }));
        backend.push(BackendMessage::CommandComplete {
            tag: "SELECT 20".to_owned(),
        });
        // Everything up to the terminator fits the threshold exactly, so only the ReadyForQuery
        // that ends the train can cross it.
        let threshold = encode_backend(backend.clone()).len();
        backend.push(BackendMessage::ReadyForQuery { status: b'I' });
        let train = encode_backend(backend);
        assert!(train.len() > threshold);

        let (mut decoder, mut encoder) = sink_codec_with_threshold(threshold);
        let mut sent = BytesMut::new();
        let query = query_message("SELECT n FROM t");
        let query_id = query.id();
        encoder.encode(vec![query], &mut sent).unwrap();

        let mut response = train.clone();
        let messages = decoder.decode(&mut response).unwrap().unwrap();

        assert_eq!(messages.len(), 1, "the terminator must not split the train");
        assert_eq!(messages[0].request_id(), Some(query_id));
        assert!(!is_partial(&messages[0]));
        assert!(!is_chunked_train_tail(&messages[0]));
        assert_eq!(message_bytes(messages.into_iter().next().unwrap()), train);
    }

    /// Streaming: a startup train is never chunked, however low the threshold. Auth trains are
    /// small and several transforms depend on receiving them whole.
    #[test]
    fn test_sink_startup_never_chunks() {
        let (mut decoder, mut encoder) = sink_codec_with_threshold(1);
        let mut sent = BytesMut::new();
        let startup =
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(startup_message())));
        let startup_id = startup.id();
        encoder.encode(vec![startup], &mut sent).unwrap();

        let mut response = encode_backend(vec![
            BackendMessage::Authentication(AuthenticationMessage::Ok),
            BackendMessage::ParameterStatus {
                name: "server_version".to_owned(),
                value: "18.0".to_owned(),
            },
            BackendMessage::ParameterStatus {
                name: "client_encoding".to_owned(),
                value: "UTF8".to_owned(),
            },
            BackendMessage::BackendKeyData {
                process_id: 42,
                secret_key: Bytes::from_static(&[1, 2, 3, 4]),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let mut messages = decoder.decode(&mut response).unwrap().unwrap();

        assert_eq!(messages.len(), 1, "a startup train must arrive whole");
        assert_eq!(messages[0].request_id(), Some(startup_id));
        assert!(!is_partial(&messages[0]));
        match messages[0].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => assert_eq!(train.len(), 5),
            other => panic!("expected Response, got {other:?}"),
        }
    }

    /// Streaming: COPY TO STDOUT chunks. Its CopyOutResponse/CopyData/CopyDone continue the train
    /// of the query that started the copy, so it streams on that request's eligibility.
    #[test]
    fn test_sink_copy_out_chunks() {
        let (mut decoder, mut encoder) = sink_codec_with_threshold(64);
        let mut sent = BytesMut::new();
        let query = query_message("COPY t TO STDOUT");
        let query_id = query.id();
        encoder.encode(vec![query], &mut sent).unwrap();

        let mut backend_messages = vec![BackendMessage::CopyOutResponse {
            overall_format: 0,
            column_formats: vec![0],
        }];
        backend_messages
            .extend((0..20).map(|i| BackendMessage::CopyData(Bytes::from(format!("row {i}\n")))));
        backend_messages.push(BackendMessage::CopyDone);
        backend_messages.push(BackendMessage::CommandComplete {
            tag: "COPY 20".to_owned(),
        });
        backend_messages.push(BackendMessage::ReadyForQuery { status: b'I' });
        let train = encode_backend(backend_messages);

        let mut response = train.clone();
        let messages = decoder.decode(&mut response).unwrap().unwrap();
        assert_chunked_train(messages, query_id, &train);
    }
}
