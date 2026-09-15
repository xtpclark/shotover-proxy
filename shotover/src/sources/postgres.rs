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
    /// Seconds of idleness after which a client connection is terminated. Unset means never.
    ///
    /// With `response_buffer_batches` set this also bounds how long the chain waits for a client to
    /// read: a connection parked on the full queue is not in the loop that re-arms the idle timeout,
    /// so this is the only thing that ends it. Required whenever `response_buffer_batches` is set.
    pub timeout: Option<u64>,
    /// How many response batches may queue for the client before the transform chain has to wait
    /// for it to catch up. Unset means a limit no source could reach before streaming existed, which
    /// is the behaviour of every other source and of this one until now.
    ///
    /// Set it alongside `stream_threshold_bytes` on the sink: with streaming on, a client that
    /// reads slowly otherwise accumulates the whole result here, because the chain hands responses
    /// to the writer task and returns rather than waiting for the socket. Bounding it makes the
    /// chain wait, which stops it draining the backend, which lets TCP stall the backend.
    ///
    /// Sizing: a batch queued here can hold a whole sink queue's worth of chunks (8), and two more
    /// are in flight in the writer task and the chain, so the buffers come to about
    /// `(this + 2) * 8 * stream_threshold_bytes`. Add the client socket buffer and allocator slack
    /// and budget roughly double that: measured peak RSS with 4 and a 1 MiB threshold is 95 MB for a
    /// 442 MB result, against 458 MB unbounded.
    ///
    /// `timeout` then implies a minimum read rate, because it bounds the wait for ONE batch of up to
    /// `8 * stream_threshold_bytes`: at a 1 MiB threshold and `timeout: 30` a client must sustain
    /// roughly 280 KB/s or be disconnected mid-result. Raise `timeout` for slower consumers.
    ///
    /// The cost is that a client which stops reading entirely stalls its own requests, exactly as it
    /// would talking to PostgreSQL directly. Because such a connection parks the chain outside the
    /// loop that re-arms the idle timeout, `timeout` is what eventually reclaims it, and setting
    /// this without `timeout` is refused at startup.
    pub response_buffer_batches: Option<usize>,
    pub chain: TransformChainConfig,
}

impl PostgresSourceConfig {
    pub async fn build(
        &self,
        trigger_shutdown_rx: watch::Receiver<bool>,
        hot_reload_listeners: &mut HashMap<u16, TcpListener>,
    ) -> Result<Source, Vec<String>> {
        if self.response_buffer_batches.is_some() && self.timeout.is_none() {
            return Err(vec![format!(
                "Postgres source {}: response_buffer_batches requires timeout to be set as well. \
                 A client that stops reading parks the chain on the full response queue, where the \
                 idle timeout is the only thing that can reclaim the connection.",
                self.name
            )]);
        }

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

#[cfg(test)]
mod tests {
    use super::PostgresSourceConfig;
    use crate::config::chain::TransformChainConfig;

    fn config(
        response_buffer_batches: Option<usize>,
        timeout: Option<u64>,
    ) -> PostgresSourceConfig {
        PostgresSourceConfig {
            name: "test".to_owned(),
            listen_addr: "127.0.0.1:0".to_owned(),
            connection_limit: None,
            hard_connection_limit: None,
            tls: None,
            timeout,
            response_buffer_batches,
            chain: TransformChainConfig(vec![]),
        }
    }

    /// A client parked on the full response queue is not in the loop that re-arms the idle timeout,
    /// so `timeout` is the only thing that can ever reclaim its connection. Pairing them is a
    /// startup error rather than a documentation note, because the failure it prevents — connection
    /// slots leaking until the source stops accepting anyone — only shows up under the slow client
    /// the bound exists to serve.
    #[tokio::test]
    async fn bounding_the_response_queue_requires_an_idle_timeout() {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let Err(errors) = config(Some(4), None)
            .build(rx, &mut Default::default())
            .await
        else {
            panic!("a bounded response queue without a timeout was accepted");
        };
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("response_buffer_batches requires timeout"),
            "unexpected error: {}",
            errors[0]
        );
    }
}
