use crate::codec::{CodecBuilder, Direction, postgres::PostgresCodecBuilder};
use crate::config::chain::TransformChainConfig;
use crate::hot_reload::protocol::GradualShutdownRequest;
use crate::source_task::SourceTask;
use crate::sources::{Source, Transport};
use crate::tls::{TlsAcceptor, TlsAcceptorConfig};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tracing::info;

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PostgresSourceConfig {
    pub name: String,
    pub listen_addr: String,
    pub connection_limit: Option<usize>,
    pub hard_connection_limit: Option<bool>,
    pub tls: Option<TlsAcceptorConfig>,
    pub timeout: Option<u64>,
    /// How many response batches may queue for the client before the transform chain has to wait
    /// for it to catch up. Unset leaves that queue unbounded, which is the behaviour of every other
    /// source and of this one before streaming existed.
    ///
    /// Set it alongside `stream_threshold_bytes` on the sink: with streaming on, a client that
    /// reads slowly otherwise accumulates the whole result here, because the chain hands responses
    /// to the writer task and returns rather than waiting for the socket. Bounding it makes the
    /// chain wait, which stops it draining the backend, which lets TCP stall the backend.
    ///
    /// Sizing: a batch queued here can hold a whole sink queue's worth of chunks, so budget about
    /// `(this + 1) * 8 * stream_threshold_bytes` per streaming connection — with 4 and a 1 MiB
    /// threshold, roughly 40 MB, not 5.
    ///
    /// Two costs. A client that stops reading entirely stalls its own requests, exactly as it would
    /// talking to PostgreSQL directly. And such a client parks the chain outside the loop that
    /// applies `timeout`, so SET `timeout` as well — without it a connection that never reads holds
    /// its slot against `connection_limit` indefinitely.
    #[serde(default)]
    pub response_buffer_batches: Option<usize>,
    pub chain: TransformChainConfig,
}

impl PostgresSourceConfig {
    pub async fn build(
        &self,
        trigger_shutdown_rx: watch::Receiver<bool>,
        hot_reload_listeners: &mut HashMap<u16, TcpListener>,
    ) -> Result<Source, Vec<String>> {
        info!("Starting Postgres source on [{}]", self.listen_addr);

        let (hot_reload_tx, hot_reload_rx) = tokio::sync::mpsc::unbounded_channel();
        let (gradual_shutdown_tx, gradual_shutdown_rx) =
            tokio::sync::mpsc::unbounded_channel::<GradualShutdownRequest>();

        let join_handle = SourceTask::start(
            &self.chain,
            self.name.clone(),
            self.listen_addr.clone(),
            self.hard_connection_limit.unwrap_or(false),
            PostgresCodecBuilder::new(Direction::Source, self.name.clone()),
            Arc::new(Semaphore::new(self.connection_limit.unwrap_or(512))),
            self.tls.as_ref().map(TlsAcceptor::new).transpose()?,
            self.timeout.map(Duration::from_secs),
            self.response_buffer_batches,
            Transport::Tcp,
            hot_reload_rx,
            hot_reload_listeners,
            trigger_shutdown_rx,
            gradual_shutdown_rx,
        )
        .await?;

        Ok(Source::new(
            join_handle,
            hot_reload_tx,
            gradual_shutdown_tx,
            self.name.clone(),
        ))
    }
}
