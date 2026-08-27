use crate::codec::{CodecBuilder, Direction, postgres::PostgresCodecBuilder};
use crate::connection::SinkConnection;
use crate::frame::MessageType;
use crate::message::Messages;
use crate::tls::{TlsConnector, TlsConnectorConfig};
use crate::transforms::{
    ChainState, DownChainProtocol, Transform, TransformBuilder, TransformConfig,
    TransformContextBuilder, TransformContextConfig, UpChainProtocol,
};
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
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
}

#[async_trait]
impl Transform for PostgresSinkSingle {
    fn get_name(&self) -> &'static str {
        NAME
    }

    async fn transform<'shorter, 'longer: 'shorter>(
        &mut self,
        chain_state: &'shorter mut ChainState<'longer>,
    ) -> Result<Messages> {
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
            let requests_count = chain_state.requests.len();
            self.connection
                .as_mut()
                .unwrap()
                .send(std::mem::take(&mut chain_state.requests))?;

            let mut responses_count = 0;
            while responses_count < requests_count {
                let responses_len_old = responses.len();
                self.connection
                    .as_mut()
                    .unwrap()
                    .recv_into(&mut responses)
                    .await?;

                for response in &responses[responses_len_old..] {
                    if response.request_id().is_some() {
                        responses_count += 1;
                    }
                }
            }
        }
        Ok(responses)
    }
}
