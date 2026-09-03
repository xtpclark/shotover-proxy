use crate::codec::{CodecBuilder, Direction, postgres::PostgresCodecBuilder};
use crate::connection::SinkConnection;
use crate::frame::postgres::{
    AuthenticationMessage, BackendMessage, FrontendMessage, PostgresFrame,
};
use crate::frame::{Frame, MessageType};
use crate::message::{Message, MessageId, Messages};
use crate::tls::{TlsConnector, TlsConnectorConfig};
use crate::transforms::{
    ChainState, DownChainProtocol, Transform, TransformBuilder, TransformConfig,
    TransformContextBuilder, TransformContextConfig, UpChainProtocol,
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Notify;

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PostgresSinkSingleConfig {
    pub name: String,
    #[serde(rename = "remote_address")]
    pub address: String,
    pub tls: Option<TlsConnectorConfig>,
    pub connect_timeout_ms: u64,
    /// Milliseconds to wait for the next chunk of a backend response before abandoning a stalled
    /// backend and returning an error to the client. It is an IDLE timeout — reset whenever data
    /// arrives — so a large legitimately-streaming result is never cut off; only a backend that stops
    /// producing trips it. If unset, a stalled backend can hang the client indefinitely.
    #[serde(default)]
    pub read_timeout_ms: Option<u64>,
    /// Bytes of an in-progress response train past which the sink codec emits the accumulated whole
    /// backend messages as a partial chunk, instead of holding the entire result in memory. `0`,
    /// the default, never chunks.
    ///
    /// Transforms that cannot handle partial trains are refused at startup with an error naming
    /// them, rather than silently misbehaving — see
    /// [`PostgresCodecBuilder::with_stream_threshold`]. Still undocumented in the user guide, and
    /// still defaulted off, until the remaining steps bound memory end to end.
    #[serde(default)]
    pub stream_threshold_bytes: usize,
}

const NAME: &str = "PostgresSinkSingle";
#[typetag::serde(name = "PostgresSinkSingle")]
#[async_trait(?Send)]
impl TransformConfig for PostgresSinkSingleConfig {
    fn get_name(&self) -> &str {
        &self.name
    }

    async fn get_builder(
        &self,
        transform_context: TransformContextConfig,
    ) -> Result<Box<dyn TransformBuilder>> {
        let tls = self.tls.as_ref().map(TlsConnector::new).transpose()?;
        let _ = &transform_context;
        Ok(Box::new(PostgresSinkSingleBuilder::new(
            self.name.clone(),
            self.address.clone(),
            tls,
            self.connect_timeout_ms,
            self.read_timeout_ms,
            self.stream_threshold_bytes,
        )))
    }

    fn up_chain_protocol(&self) -> UpChainProtocol {
        UpChainProtocol::MustBeOneOf(vec![MessageType::Postgres])
    }

    fn down_chain_protocol(&self) -> DownChainProtocol {
        DownChainProtocol::Terminating
    }

    fn get_sub_chain_configs(&self) -> Vec<(&crate::config::chain::TransformChainConfig, String)> {
        vec![]
    }

    fn emits_partial_responses(&self) -> bool {
        self.stream_threshold_bytes > 0
    }

    fn accepts_partial_responses(&self) -> bool {
        true
    }
}

pub struct PostgresSinkSingleBuilder {
    name: String,
    address: String,
    tls: Option<TlsConnector>,
    connect_timeout: Duration,
    read_timeout: Option<Duration>,
    stream_threshold_bytes: usize,
}

impl PostgresSinkSingleBuilder {
    pub fn new(
        name: String,
        address: String,
        tls: Option<TlsConnector>,
        connect_timeout_ms: u64,
        read_timeout_ms: Option<u64>,
        stream_threshold_bytes: usize,
    ) -> Self {
        PostgresSinkSingleBuilder {
            name,
            address,
            tls,
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            read_timeout: read_timeout_ms.map(Duration::from_millis),
            stream_threshold_bytes,
        }
    }
}

impl TransformBuilder for PostgresSinkSingleBuilder {
    fn build(&self, transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(PostgresSinkSingle {
            address: self.address.clone(),
            tls: self.tls.clone(),
            connection: None,
            connect_timeout: self.connect_timeout,
            read_timeout: self.read_timeout,
            stream_threshold_bytes: self.stream_threshold_bytes,
            streaming_unit: None,
            force_run_chain: transform_context.force_run_chain,
            outstanding: 0,
            source_is_tls: transform_context.source_is_tls,
            startup_complete: false,
        })
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_type_name(&self) -> &'static str {
        NAME
    }

    fn is_terminating(&self) -> bool {
        true
    }
}

pub struct PostgresSinkSingle {
    address: String,
    tls: Option<TlsConnector>,
    connection: Option<SinkConnection>,
    connect_timeout: Duration,
    /// Idle timeout for the next chunk of a backend response (see [`super::exchange`]); None disables.
    read_timeout: Option<Duration>,
    stream_threshold_bytes: usize,
    force_run_chain: Arc<Notify>,
    /// Set while a response train is still arriving, to the id of the request that batch was sent
    /// for. `exchange` returns early with chunks in hand rather than holding a whole large result,
    /// so the rest of the train is collected by the empty-request arm below — and until it is, this
    /// connection is not being watched by anything else.
    ///
    /// The id is the same approximation `exchange`'s own error path makes (the batch's first
    /// request), and it exists so a stall mid-train can answer the client with a paired error.
    streaming_unit: Option<MessageId>,
    /// Requests sent to the server that have not yet been answered — see [`super::exchange`].
    /// Carried across batches because an extended-query pipeline's responses arrive on the batch
    /// that carries the Flush/Sync, which may be a later one than the batch that sent the requests.
    outstanding: usize,
    /// Whether this connection's source terminates TLS with the client. When false (a plaintext
    /// client), SCRAM-SHA-256-PLUS is stripped from the backend's SASL offer during auth — see
    /// `strip_scram_channel_binding` and the note above.
    source_is_tls: bool,
    /// True once the client has finished authenticating (AuthenticationOk / first ReadyForQuery);
    /// after that no AuthenticationSASL can appear, so responses pass through unparsed (byte-faithful).
    startup_complete: bool,
}

// A note on SCRAM channel binding (SCRAM-SHA-256-PLUS) through a TLS terminating proxy.
//
// It cannot work transparently, and this is a property of SCRAM, not a shotover limitation.
// The client binds its SCRAM proof to shotover's TLS certificate while the server expects a
// proof bound to its own certificate, so a -PLUS exchange fails the binding check. Stripping
// -PLUS from the server's mechanism offer does not help either: a channel-binding-capable
// client that then selects plain SCRAM-SHA-256 sets its gs2 flag to 'y' ("I support binding
// but the server did not offer it"), and the server - which did offer it - treats that as a
// downgrade attack and refuses. The gs2 flag is folded into the SCRAM proof, so shotover
// cannot rewrite it without the password it deliberately never holds.
//
// The supported configuration when shotover terminates TLS in front of a channel-binding
// capable server is therefore for the client to not use channel binding
// (libpq `channel_binding=disable`), or for the deployment to use a non-SCRAM auth method.
// This is documented on the Postgres source page.

#[async_trait]
impl Transform for PostgresSinkSingle {
    fn get_name(&self) -> &'static str {
        NAME
    }

    async fn transform<'shorter, 'longer: 'shorter>(
        &mut self,
        chain_state: &'shorter mut ChainState<'longer>,
    ) -> Result<Messages> {
        // A CancelRequest is sent by the client on a dedicated connection and must be
        // delivered to the server on its own fresh connection ahead of any startup message.
        // It never travels on the pooled sink connection. BackendKeyData was passed through
        // untouched, so the pid/secret the client holds are valid at the real server and route
        // the cancel to the correct backend. A real server closes the client connection right
        // after acting on a cancel and libpq blocks until that happens, so the connection is
        // marked for close.
        let mut cancel_responses = vec![];
        let mut i = 0;
        while i < chain_state.requests.len() {
            let is_cancel = matches!(
                chain_state.requests[i].frame(),
                Some(Frame::Postgres(PostgresFrame::Request(
                    FrontendMessage::CancelRequest { .. }
                )))
            );
            if is_cancel {
                let mut request = chain_state.requests.remove(i);
                self.relay_cancel_request(&mut request).await;
                // The server sends no response to a cancel, so satisfy the one-response-per
                // request invariant with a dummy carrying the request's id.
                let mut dummy = Message::from_frame(Frame::Dummy);
                dummy.set_request_id(request.id());
                cancel_responses.push(dummy);
                chain_state.close_client_connection = true;
            } else {
                i += 1;
            }
        }
        if !cancel_responses.is_empty() && chain_state.requests.is_empty() {
            return Ok(cancel_responses);
        }

        if self.connection.is_none() {
            let codec = PostgresCodecBuilder::new(Direction::Sink, "PostgresSinkSingle".to_owned())
                .with_stream_threshold(self.stream_threshold_bytes);
            self.connection = Some(
                SinkConnection::new(
                    &self.address,
                    codec,
                    &self.tls,
                    self.connect_timeout,
                    self.force_run_chain.clone(),
                    None,
                )
                .await?,
            );
        }

        let mut responses = vec![];
        if let Some(streaming_id) = self.streaming_unit {
            // A train is still arriving. Block for more of it rather than polling: this run was
            // triggered by the connection's notify, so either data or a stall is coming, and after
            // `exchange` returned early nothing else applies a timeout to this connection — without
            // one here a backend that stops mid-train hangs the client forever.
            //
            // Any client requests that arrived meanwhile stay in `chain_state.requests` and are sent
            // below, exactly as they would be without streaming: the server runs them after the
            // in-flight query and answers them on the same ordered connection, so `outstanding`
            // accounts for them as it always has. Declining to send them would drop them — the chain
            // never re-queues what a transform leaves behind.
            let before = responses.len();
            match super::recv_under_idle_timeout(
                self.connection.as_mut().unwrap(),
                &mut responses,
                self.read_timeout,
            )
            .await
            {
                Ok(()) => {
                    let answered = super::count_answered(&responses[before..]);
                    self.outstanding = self.outstanding.saturating_sub(answered);
                    // An id-carrying response ends the train: only its last message carries one.
                    if answered > 0 {
                        self.streaming_unit = None;
                    }
                }
                Err(err) if err.downcast_ref::<super::BackendReadTimeout>().is_some() => {
                    self.connection = None;
                    self.outstanding = 0;
                    self.streaming_unit = None;
                    chain_state.close_client_connection = true;
                    responses.push(read_timeout_error_response(Some(streaming_id)));
                    return Ok(responses);
                }
                Err(err) => return Err(err),
            }
        }
        if chain_state.requests.is_empty() {
            if self.streaming_unit.is_none() {
                // No requests and no train in flight: check for unrequested responses
                // (notifications, notices) without awaiting.
                // TODO: handle errors here
                let _ = self
                    .connection
                    .as_mut()
                    .unwrap()
                    .try_recv_into(&mut responses);
            }
        } else {
            let mut requests = std::mem::take(&mut chain_state.requests);
            let first_id = requests.first_mut().map(|r| r.id());
            match super::exchange(
                self.connection.as_mut().unwrap(),
                requests,
                &mut self.outstanding,
                self.read_timeout,
            )
            .await
            {
                Ok((r, streaming)) => {
                    responses.extend(r);
                    self.streaming_unit = streaming.then_some(first_id).flatten();
                }
                Err(err) if err.downcast_ref::<super::BackendReadTimeout>().is_some() => {
                    // The backend stalled mid-answer: the connection is now desynced, so drop it, tell
                    // the client, and close — never hang the client on a response that will not come.
                    self.connection = None;
                    self.outstanding = 0;
                    self.streaming_unit = None;
                    chain_state.close_client_connection = true;
                    responses.push(read_timeout_error_response(first_id));
                }
                Err(err) => return Err(err),
            }
        }
        // A plaintext client cannot use SCRAM channel binding, so strip SCRAM-SHA-256-PLUS from the
        // backend's SASL offer before it reaches the client. A TLS sink to a channel-binding-capable
        // backend otherwise offers -PLUS to a plaintext client, which aborts the handshake
        // ("server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection"). Only the
        // auth phase can carry an AuthenticationSASL, so once startup completes responses pass through
        // untouched (byte-faithful passthrough).
        if !self.source_is_tls && !self.startup_complete {
            for response in responses.iter_mut() {
                self.strip_scram_channel_binding(response);
            }
        }
        responses.append(&mut cancel_responses);
        Ok(responses)
    }
}

impl PostgresSinkSingle {
    /// Strips SCRAM-SHA-256-PLUS from a backend AuthenticationSASL offer when the client link is
    /// plaintext (see the note above), and records when startup finishes so later responses are left
    /// untouched. A plaintext client never attempts channel binding, so removing -PLUS leaves plain
    /// SCRAM-SHA-256 and the handshake proceeds; a TLS client is unaffected because this runs only
    /// when the source is not TLS.
    fn strip_scram_channel_binding(&mut self, response: &mut Message) {
        let mut modified = false;
        {
            let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
                return;
            };
            for message in messages.iter_mut() {
                match message {
                    BackendMessage::Authentication(AuthenticationMessage::Sasl { mechanisms }) => {
                        let before = mechanisms.len();
                        mechanisms.retain(|m| m != "SCRAM-SHA-256-PLUS");
                        modified |= mechanisms.len() != before;
                    }
                    // Auth is over once the backend accepts or the session is ready; no
                    // AuthenticationSASL can follow, so stop inspecting responses.
                    BackendMessage::Authentication(AuthenticationMessage::Ok)
                    | BackendMessage::ReadyForQuery { .. } => {
                        self.startup_complete = true;
                    }
                    _ => {}
                }
            }
        }
        if modified {
            response.invalidate_cache();
        }
    }

    /// Delivers a CancelRequest to the server on a throwaway connection.
    /// Failure is logged and swallowed: a cancel is advisory and the client's own
    /// connection is unaffected by whether the cancel reached the server.
    async fn relay_cancel_request(&self, request: &mut Message) {
        let mut bytes = BytesMut::new();
        match request.frame() {
            Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::CancelRequest {
                process_id,
                secret_key,
            }))) => {
                FrontendMessage::CancelRequest {
                    process_id: *process_id,
                    secret_key: secret_key.clone(),
                }
                .encode(&mut bytes)
                .ok();
            }
            _ => return,
        }
        if let Err(err) = self.send_cancel_bytes(&bytes).await {
            tracing::warn!("failed to relay postgres CancelRequest: {err}");
        }
    }

    async fn send_cancel_bytes(&self, bytes: &[u8]) -> Result<()> {
        // TLS is not negotiated for the cancel connection: postgres allows a cancel to be
        // sent on a plaintext connection even to a TLS server, and it carries no secret
        // beyond the already-issued cancel key.
        let mut stream =
            tokio::time::timeout(self.connect_timeout, TcpStream::connect(&self.address)).await??;
        stream.write_all(bytes).await?;
        stream.flush().await?;
        // The server closes the connection after processing the cancel.
        stream.shutdown().await.ok();
        Ok(())
    }
}

/// The ErrorResponse sent to the client when a backend read timed out (read_timeout). SQLSTATE 08006
/// (connection_failure): shotover is tearing the backend connection down, not surfacing a server error.
fn read_timeout_error_response(request_id: Option<MessageId>) -> Message {
    let mut response = Message::from_frame(Frame::Postgres(PostgresFrame::Response(vec![
        BackendMessage::ErrorResponse {
            fields: vec![
                (b'S', "ERROR".to_owned()),
                (b'V', "ERROR".to_owned()),
                (b'C', "08006".to_owned()),
                (b'M', "postgres backend did not respond within read_timeout".to_owned()),
            ],
        },
    ])));
    if let Some(id) = request_id {
        response.set_request_id(id);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::postgres::FieldDescription;
    use bytes::Bytes;

    fn sink() -> PostgresSinkSingle {
        PostgresSinkSingle {
            address: "127.0.0.1:5432".to_owned(),
            tls: None,
            connection: None,
            connect_timeout: Duration::from_secs(1),
            read_timeout: None,
            stream_threshold_bytes: 0,
            streaming_unit: None,
            force_run_chain: Arc::new(Notify::new()),
            outstanding: 0,
            source_is_tls: false,
            startup_complete: false,
        }
    }

    /// THE regression gate for incremental forwarding. Once `exchange` returns early with chunks,
    /// nothing else applies a timeout to that backend connection — so a backend that goes silent
    /// mid-train must be caught by the drain arm's own idle timeout, or the client hangs forever.
    ///
    /// Drives a real socket: a fake backend writes enough of a row stream to cross the threshold,
    /// then stops without ever sending the ReadyForQuery that would end the train.
    #[tokio::test]
    async fn stalled_mid_train_backend_is_timed_out_by_the_drain_arm() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        // A backend that answers with chunks and then falls silent, holding the socket open.
        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut train = BytesMut::new();
            row_description().encode(&mut train).unwrap();
            for i in 0..200 {
                BackendMessage::DataRow {
                    values: vec![Some(Bytes::from(format!("{i:0>60}")))],
                }
                .encode(&mut train)
                .unwrap();
            }
            // No CommandComplete, no ReadyForQuery: the train never ends.
            stream.write_all(&train).await.unwrap();
            // Hold the connection open and silent until the test drops us.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let mut sink = sink();
        sink.address = format!("127.0.0.1:{port}");
        sink.stream_threshold_bytes = 256;
        sink.read_timeout = Some(Duration::from_millis(300));

        // First run: the query goes out and `exchange` comes back early with partial chunks.
        let query = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Query {
                query: "SELECT n FROM t".to_owned(),
            },
        )));
        let mut chain_state = ChainState::new_test(vec![query]);
        let responses = sink.transform(&mut chain_state).await.unwrap();
        assert!(
            !responses.is_empty(),
            "expected chunks to be forwarded before the train completed"
        );
        assert!(
            responses.iter().all(|r| r.request_id().is_none()),
            "a partial chunk must not carry a request id"
        );
        assert!(
            sink.streaming_unit.is_some(),
            "the sink must know a train is still in flight"
        );

        // Later runs carry no client requests, exactly as the source's notify-triggered runs do.
        // The drain arm forwards whatever has arrived; once the backend falls silent it must trip
        // the idle timeout rather than wait forever for a train that will never end.
        let mut forwarded = responses.len();
        let mut timed_out = None;
        for _ in 0..500 {
            let mut chain_state = ChainState::new_test(vec![]);
            let responses =
                tokio::time::timeout(Duration::from_secs(5), sink.transform(&mut chain_state))
                    .await
                    .expect("the drain arm hung instead of timing out")
                    .unwrap();
            forwarded += responses.len();
            if chain_state.close_client_connection {
                timed_out = Some(responses);
                break;
            }
        }
        let responses = timed_out.expect("the drain arm never timed the stalled backend out");
        assert!(
            forwarded > 1,
            "the chunks should have been forwarded as they arrived, not held"
        );

        assert_eq!(responses.len(), 1);
        match responses[0].clone().frame().unwrap() {
            Frame::Postgres(PostgresFrame::Response(train)) => {
                assert!(
                    train[0]
                        .error_message()
                        .unwrap()
                        .contains("did not respond within read_timeout")
                );
            }
            other => panic!("expected an error response, got {other:?}"),
        }
        assert!(sink.streaming_unit.is_none());
        assert!(
            sink.connection.is_none(),
            "the desynced connection is dropped"
        );

        backend.abort();
    }

    /// A one column int4 RowDescription, for building a fake backend's row stream.
    fn row_description() -> BackendMessage {
        BackendMessage::RowDescription {
            fields: vec![FieldDescription {
                name: "n".to_owned(),
                table_oid: 0,
                column_attribute_number: 1,
                data_type_oid: 23,
                data_type_size: 4,
                type_modifier: -1,
                format_code: 0,
            }],
        }
    }

    fn sasl_offer(mechanisms: &[&str]) -> Message {
        Message::from_frame(Frame::Postgres(PostgresFrame::Response(vec![
            BackendMessage::Authentication(AuthenticationMessage::Sasl {
                mechanisms: mechanisms.iter().map(|m| m.to_string()).collect(),
            }),
        ])))
    }

    fn mechanisms_of(m: &mut Message) -> Vec<String> {
        match m.frame() {
            Some(Frame::Postgres(PostgresFrame::Response(msgs))) => msgs
                .iter()
                .find_map(|x| match x {
                    BackendMessage::Authentication(AuthenticationMessage::Sasl { mechanisms }) => {
                        Some(mechanisms.clone())
                    }
                    _ => None,
                })
                .expect("expected a SASL message"),
            _ => panic!("expected a postgres response"),
        }
    }

    #[test]
    fn test_strip_scram_plus_for_plaintext_client() {
        // A plaintext client cannot do channel binding, so SCRAM-SHA-256-PLUS is removed, leaving
        // plain SCRAM-SHA-256 so the handshake can proceed.
        let mut s = sink();
        let mut offer = sasl_offer(&["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]);
        s.strip_scram_channel_binding(&mut offer);
        assert_eq!(mechanisms_of(&mut offer), vec!["SCRAM-SHA-256".to_owned()]);
    }

    #[test]
    fn test_strip_leaves_plain_scram_offer_untouched() {
        let mut s = sink();
        let mut offer = sasl_offer(&["SCRAM-SHA-256"]);
        s.strip_scram_channel_binding(&mut offer);
        assert_eq!(mechanisms_of(&mut offer), vec!["SCRAM-SHA-256".to_owned()]);
    }

    #[test]
    fn test_startup_complete_stops_inspection() {
        // AuthenticationOk (or a ReadyForQuery) ends the auth phase; the sink then leaves responses
        // untouched, preserving byte-faithful passthrough.
        let mut s = sink();
        let mut ok = Message::from_frame(Frame::Postgres(PostgresFrame::Response(vec![
            BackendMessage::Authentication(AuthenticationMessage::Ok),
        ])));
        s.strip_scram_channel_binding(&mut ok);
        assert!(s.startup_complete);
    }
}
