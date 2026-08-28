use crate::codec::{CodecBuilder, Direction, postgres::PostgresCodecBuilder};
use crate::connection::SinkConnection;
use crate::frame::postgres::{FrontendMessage, PostgresFrame};
use crate::frame::{Frame, MessageType};
use crate::message::{Message, Messages};
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
}

pub struct PostgresSinkSingleBuilder {
    name: String,
    address: String,
    tls: Option<TlsConnector>,
    connect_timeout: Duration,
}

impl PostgresSinkSingleBuilder {
    pub fn new(
        name: String,
        address: String,
        tls: Option<TlsConnector>,
        connect_timeout_ms: u64,
    ) -> Self {
        PostgresSinkSingleBuilder {
            name,
            address,
            tls,
            connect_timeout: Duration::from_millis(connect_timeout_ms),
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
            force_run_chain: transform_context.force_run_chain,
            outstanding: 0,
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
    force_run_chain: Arc<Notify>,
    /// Requests sent to the server that have not yet been answered — see [`super::exchange`].
    /// Carried across batches because an extended-query pipeline's responses arrive on the batch
    /// that carries the Flush/Sync, which may be a later one than the batch that sent the requests.
    outstanding: usize,
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
            let codec = PostgresCodecBuilder::new(Direction::Sink, "PostgresSinkSingle".to_owned());
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
        if chain_state.requests.is_empty() {
            // No requests, but check for unrequested responses (notifications, notices)
            // without awaiting.
            // TODO: handle errors here
            let _ = self
                .connection
                .as_mut()
                .unwrap()
                .try_recv_into(&mut responses);
        } else {
            responses = super::exchange(
                self.connection.as_mut().unwrap(),
                std::mem::take(&mut chain_state.requests),
                &mut self.outstanding,
            )
            .await?;
        }
        responses.append(&mut cancel_responses);
        Ok(responses)
    }
}

impl PostgresSinkSingle {
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
