use crate::frame::postgres::{BackendMessage, PostgresFrame};
use crate::frame::{Frame, MessageType};
use crate::message::Messages;
use crate::transforms::{
    ChainState, DownChainProtocol, Transform, TransformBuilder, TransformConfig,
    TransformContextBuilder, TransformContextConfig, UpChainProtocol,
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Replaces the value of a named result column with a fixed replacement string
/// in every DataRow flowing back to the client.
///
/// The column index is taken from the most recent RowDescription seen on the
/// connection, which covers both the simple query protocol (RowDescription and
/// DataRows share one response) and the extended protocol (RowDescription
/// arrives with the Describe response, DataRows with the Execute response).
///
/// NULL values stay NULL. The replacement is written as a text format value:
/// redacting a column fetched in binary format will hand the client bytes it
/// may fail to decode, which is still a redaction, just a less polite one.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PostgresRedactColumnConfig {
    pub name: String,
    /// The result column name to redact, matched exactly.
    pub column: String,
    pub replacement: String,
}

const NAME: &str = "PostgresRedactColumn";
#[typetag::serde(name = "PostgresRedactColumn")]
#[async_trait(?Send)]
impl TransformConfig for PostgresRedactColumnConfig {
    fn get_name(&self) -> &str {
        &self.name
    }

    async fn get_builder(
        &self,
        _transform_context: TransformContextConfig,
    ) -> Result<Box<dyn TransformBuilder>> {
        Ok(Box::new(PostgresRedactColumnBuilder {
            name: self.name.clone(),
            column: self.column.clone(),
            replacement: self.replacement.clone(),
        }))
    }

    fn up_chain_protocol(&self) -> UpChainProtocol {
        UpChainProtocol::MustBeOneOf(vec![MessageType::Postgres])
    }

    fn down_chain_protocol(&self) -> DownChainProtocol {
        DownChainProtocol::SameAsUpChain
    }

    fn get_sub_chain_configs(&self) -> Vec<(&crate::config::chain::TransformChainConfig, String)> {
        vec![]
    }
}

pub struct PostgresRedactColumnBuilder {
    name: String,
    column: String,
    replacement: String,
}

impl TransformBuilder for PostgresRedactColumnBuilder {
    fn build(&self, _transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(PostgresRedactColumn {
            column: self.column.clone(),
            replacement: self.replacement.clone(),
            active_column_index: None,
        })
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_type_name(&self) -> &'static str {
        NAME
    }

    fn is_terminating(&self) -> bool {
        false
    }
}

pub struct PostgresRedactColumn {
    column: String,
    replacement: String,
    /// The redacted column's index in the row shape described by the most
    /// recent RowDescription, None when that shape does not contain it.
    active_column_index: Option<usize>,
}

#[async_trait]
impl Transform for PostgresRedactColumn {
    fn get_name(&self) -> &'static str {
        NAME
    }

    async fn transform<'shorter, 'longer: 'shorter>(
        &mut self,
        chain_state: &'shorter mut ChainState<'longer>,
    ) -> Result<Messages> {
        let mut responses = chain_state.call_next_transform().await?;
        for response in &mut responses {
            if let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() {
                let mut modified = false;
                for message in messages.iter_mut() {
                    match message {
                        BackendMessage::RowDescription { fields } => {
                            self.active_column_index =
                                fields.iter().position(|field| field.name == self.column);
                        }
                        BackendMessage::DataRow { values } => {
                            if let Some(index) = self.active_column_index
                                && let Some(value) = values.get_mut(index)
                                && value.is_some()
                            {
                                *value = Some(Bytes::copy_from_slice(self.replacement.as_bytes()));
                                modified = true;
                            }
                        }
                        _ => {}
                    }
                }
                if modified {
                    response.invalidate_cache();
                }
            }
        }
        Ok(responses)
    }
}
