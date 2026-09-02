use super::{DownChainProtocol, TransformContextBuilder, TransformContextConfig, UpChainProtocol};
use crate::frame::MessageType;
use crate::message::{Message, MessageIdMap, Messages};
use crate::transforms::{ChainState, Transform, TransformBuilder, TransformConfig};
use anyhow::Result;
use async_trait::async_trait;
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
};
use nonzero_ext::nonzero;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RequestThrottlingConfig {
    pub name: String,
    pub max_requests_per_second: NonZeroU32,
}

const NAME: &str = "RequestThrottling";
#[typetag::serde(name = "RequestThrottling")]
#[async_trait(?Send)]
impl TransformConfig for RequestThrottlingConfig {
    fn get_name(&self) -> &str {
        &self.name
    }

    async fn get_builder(
        &self,
        _transform_context: TransformContextConfig,
    ) -> Result<Box<dyn TransformBuilder>> {
        Ok(Box::new(RequestThrottling {
            name: self.name.clone(),
            limiter: Arc::new(RateLimiter::direct(Quota::per_second(
                self.max_requests_per_second,
            ))),
            max_requests_per_second: self.max_requests_per_second,
            throttled_requests: MessageIdMap::default(),
            last_rfq_status: b'I',
        }))
    }

    fn up_chain_protocol(&self) -> UpChainProtocol {
        // Per enabled feature: the MessageType variants are themselves cfg-gated, so a build without
        // one of these protocols must not name it.
        UpChainProtocol::MustBeOneOf(vec![
            #[cfg(feature = "cassandra")]
            MessageType::Cassandra,
            #[cfg(feature = "postgres")]
            MessageType::Postgres,
        ])
    }

    fn down_chain_protocol(&self) -> DownChainProtocol {
        DownChainProtocol::SameAsUpChain
    }

    fn get_sub_chain_configs(&self) -> Vec<(&crate::config::chain::TransformChainConfig, String)> {
        vec![]
    }

    fn accepts_partial_responses(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct RequestThrottling {
    name: String,
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>,
    max_requests_per_second: NonZeroU32,
    throttled_requests: MessageIdMap<Message>,
    /// The last ReadyForQuery status seen on this connection (postgres only), so a throttle rejection
    /// mirrors the session's real transaction state instead of always reporting idle 'I' (review F9).
    last_rfq_status: u8,
}

impl TransformBuilder for RequestThrottling {
    fn build(&self, _transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(self.clone())
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_type_name(&self) -> &'static str {
        NAME
    }

    fn validate(&self) -> Vec<String> {
        if self.max_requests_per_second < nonzero!(50u32) {
            vec![
                "RequestThrottling:".into(),
                "  max_requests_per_second has a minimum allowed value of 50".into(),
            ]
        } else {
            vec![]
        }
    }
}

#[async_trait]
impl Transform for RequestThrottling {
    fn get_name(&self) -> &'static str {
        NAME
    }

    async fn transform<'shorter, 'longer: 'shorter>(
        &mut self,
        chain_state: &'shorter mut ChainState<'longer>,
    ) -> Result<Messages> {
        for request in &mut chain_state.requests {
            if let Ok(cell_count) = request.cell_count() {
                let throttle = match self.limiter.check_n(cell_count) {
                    // occurs if all cells can be accommodated
                    Ok(Ok(())) => false,
                    // occurs if not all cells can be accommodated.
                    Ok(Err(_)) => true,
                    // occurs when the batch can never go through, meaning the rate limiter's quota's burst size is too low for the given number of cells to be ever allowed through
                    Err(_) => {
                        tracing::warn!(
                            "A message was received that could never have been successfully delivered since it contains more sub messages than can ever be allowed through via the `RequestThrottling` transforms `max_requests_per_second` configuration."
                        );
                        true
                    }
                };
                if throttle {
                    let mut backpressure = request.to_backpressure()?;
                    // Mirror the session's current transaction state so a throttled request inside a
                    // transaction does not falsely report idle to a status-tracking driver (review F9).
                    #[cfg(feature = "postgres")]
                    if self.last_rfq_status != b'I' {
                        set_postgres_rfq_status(&mut backpressure, self.last_rfq_status);
                    }
                    self.throttled_requests.insert(request.id(), backpressure);
                    request.replace_with_dummy();
                }
            }
        }

        // send allowed messages on to the sink (throttled ones were replaced with dummies)
        let mut responses = chain_state.call_next_transform().await?;

        // replace dummy responses with throttle messages
        for response in responses.iter_mut() {
            // Track the transaction state from real responses' ReadyForQuery (postgres only), so a
            // later throttle rejection can mirror it (review F9). The message_type() check is cheap and
            // avoids parsing non-postgres responses.
            // A partial chunk cannot contain a ReadyForQuery — that message completes a train,
            // so it is only ever in the final chunk — but it is skipped BEFORE the scan rather
            // than after, because the scan parses the whole message. Parsing a chunk of DataRows
            // into typed frames, which `Message::frame` then caches alongside the raw bytes, is
            // exactly the cost streaming exists to avoid.
            #[cfg(feature = "postgres")]
            if response.message_type() == MessageType::Postgres
                && !crate::codec::postgres::is_partial_response(response)
                && let Some(status) = postgres_trailing_rfq_status(response)
            {
                self.last_rfq_status = status;
            }
            if let Some(request_id) = response.request_id()
                && let Some(error_response) = self.throttled_requests.remove(&request_id)
            {
                *response = error_response;
            }
        }

        Ok(responses)
    }
}

/// The status byte of the last ReadyForQuery in a postgres response, if any.
#[cfg(feature = "postgres")]
fn postgres_trailing_rfq_status(response: &mut Message) -> Option<u8> {
    use crate::frame::Frame;
    use crate::frame::postgres::{BackendMessage, PostgresFrame};
    if let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() {
        for message in messages.iter().rev() {
            if let BackendMessage::ReadyForQuery { status } = message {
                return Some(*status);
            }
        }
    }
    None
}

/// Rewrites the ReadyForQuery status of a postgres backpressure response so it reflects the session's
/// real transaction state.
#[cfg(feature = "postgres")]
fn set_postgres_rfq_status(response: &mut Message, status: u8) {
    use crate::frame::Frame;
    use crate::frame::postgres::{BackendMessage, PostgresFrame};
    if let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() {
        let mut changed = false;
        for message in messages.iter_mut() {
            if let BackendMessage::ReadyForQuery { status: s } = message {
                *s = status;
                changed = true;
            }
        }
        if changed {
            response.invalidate_cache();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transforms::chain::TransformChainBuilder;
    use crate::transforms::null::NullSink;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_validate() {
        {
            let chain = TransformChainBuilder::new(
                vec![
                    Box::new(RequestThrottling {
                        name: "RequestThrottling".to_string(),
                        limiter: Arc::new(RateLimiter::direct(Quota::per_second(nonzero!(20u32)))),
                        max_requests_per_second: nonzero!(20u32),
                        throttled_requests: MessageIdMap::default(),
                        last_rfq_status: b'I',
                    }) as Box<dyn TransformBuilder>,
                    Box::new(NullSink::new("NullSink".to_string())),
                ],
                "test-chain",
            );

            assert_eq!(
                chain.validate(),
                vec![
                    "test-chain chain:",
                    "  RequestThrottling:",
                    "    max_requests_per_second has a minimum allowed value of 50"
                ]
            );
        }

        {
            let chain = TransformChainBuilder::new(
                vec![
                    Box::new(RequestThrottling {
                        name: "RequestThrottling".to_string(),
                        limiter: Arc::new(RateLimiter::direct(Quota::per_second(nonzero!(100u32)))),
                        max_requests_per_second: nonzero!(100u32),
                        throttled_requests: MessageIdMap::default(),
                        last_rfq_status: b'I',
                    }) as Box<dyn TransformBuilder>,
                    Box::new(NullSink::new("NullSink".to_string())),
                ],
                "test-chain",
            );

            assert_eq!(chain.validate(), Vec::<String>::new());
        }
    }
}
