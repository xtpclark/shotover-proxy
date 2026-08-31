use super::{CodecWriteError, Direction, message_latency};
use crate::codec::{CodecBuilder, CodecReadError, CodecState};
use crate::frame::postgres::{
    CANCEL_REQUEST_CODE, GSSENC_REQUEST_CODE, SSL_REQUEST_CODE, message_wire_length,
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

/// Per message connection level state needed to parse and reencode postgres messages.
#[derive(Debug, Clone, PartialEq, Copy)]
pub struct PostgresCodecState {
    /// Tag parsing is direction aware: several tag bytes mean different messages
    /// depending on whether the client or the server sent them.
    pub is_request: bool,
    /// The message uses the tag-less startup framing (StartupMessage/CancelRequest).
    pub startup: bool,
}

#[derive(Clone)]
pub struct PostgresCodecBuilder {
    direction: Direction,
    message_latency: Histogram,
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
            PostgresDecoder::new(rx, self.direction),
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

#[derive(Debug)]
pub struct RequestInfo {
    kind: RequestKind,
    id: MessageId,
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
    /// Sink only: when the train started accumulating.
    train_started_at: Option<Instant>,
    /// Sink only: an error was returned for an extended protocol request, the server is
    /// discarding until the next Sync. Queued non-Sync requests receive dummy responses.
    discarding_until_sync: bool,
    /// Sink only: Some while a COPY FROM STDIN is in progress.
    copy_mode: Option<CopyMode>,
}

impl PostgresDecoder {
    pub fn new(request_rx: Option<mpsc::Receiver<RequestInfo>>, direction: Direction) -> Self {
        Self {
            direction,
            seen_startup: false,
            request_rx,
            pending: VecDeque::new(),
            train: BytesMut::new(),
            train_started_at: None,
            discarding_until_sync: false,
            copy_mode: None,
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
                CodecState::Postgres(PostgresCodecState {
                    is_request: true,
                    startup,
                }),
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
            let bytes = src.split_to(length);
            tracing::debug!(
                "{}: incoming postgres message:\n{}",
                self.direction,
                pretty_hex::pretty_hex(&bytes)
            );

            let head_kind = match self.pending.front() {
                Some(info) => info.kind,
                None => {
                    // No request is awaiting a response: async server traffic
                    // (notices, notifications, parameter changes, or a dying gasp error).
                    // Forward each as its own unrequested response message.
                    messages.push(Message::from_bytes_at_instant(
                        bytes.freeze(),
                        CodecState::Postgres(PostgresCodecState {
                            is_request: false,
                            startup: false,
                        }),
                        Some(received_at),
                    ));
                    continue;
                }
            };

            if self.train.is_empty() {
                self.train_started_at = Some(received_at);
            }
            self.train.extend_from_slice(&bytes);

            let action = train_action(head_kind, tag, auth_code, self.copy_mode);
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
                    let mut message = Message::from_bytes_at_instant(
                        self.train.split().freeze(),
                        CodecState::Postgres(PostgresCodecState {
                            is_request: false,
                            startup: false,
                        }),
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
                tx.send(RequestInfo { kind, id })
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
        PostgresCodecBuilder::new(Direction::Sink, "postgres".to_owned()).build()
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
        let (mut decoder, mut encoder) = sink_codec();
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

        // Parse gets the error train.
        assert_eq!(messages[0].request_id(), Some(ids[0]));
        match messages[0].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => {
                assert!(train[0].error_message().unwrap().contains("missing_table"));
            }
            other => panic!("expected Response, got {other:?}"),
        }
        // Bind and Execute get dummies.
        assert_eq!(messages[1].request_id(), Some(ids[1]));
        assert!(messages[1].is_dummy());
        assert_eq!(messages[2].request_id(), Some(ids[2]));
        assert!(messages[2].is_dummy());
        // Sync gets the ReadyForQuery.
        assert_eq!(messages[3].request_id(), Some(ids[3]));
        match messages[3].frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => {
                assert_eq!(train[0], BackendMessage::ReadyForQuery { status: b'I' });
            }
            other => panic!("expected Response, got {other:?}"),
        }
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
}
