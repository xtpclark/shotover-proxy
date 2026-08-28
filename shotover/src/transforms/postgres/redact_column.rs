use crate::frame::postgres::{BackendMessage, PostgresFrame};
use crate::frame::{Frame, MessageType};
use crate::message::{Message, MessageErrorType, Messages};
use crate::transforms::{
    ChainState, DownChainProtocol, Transform, TransformBuilder, TransformConfig,
    TransformContextBuilder, TransformContextConfig, UpChainProtocol,
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Replaces the value of a named result column with a fixed replacement string in every DataRow
/// flowing back to the client.
///
/// # Fail-closed
/// This is a security control, so it fails CLOSED: if it cannot determine the row shape for a set
/// of DataRows it is about to pass to the client, it replaces the whole response with an error
/// rather than risk leaking an unredacted value. The row shape comes from a RowDescription. In the
/// simple query protocol the RowDescription and its DataRows share one response, so the shape is
/// always known. In the extended protocol the RowDescription arrives with the Describe response and
/// the DataRows with the Execute response; the shape is carried across from Describe to Execute and
/// reset at each result boundary, so a driver that CACHES a prepared statement and skips Describe on
/// re-execution produces DataRows with no established shape — those queries error rather than leak.
/// COPY output (which carries rows outside DataRow messages) and any server response that cannot be
/// parsed also fail closed. The correct fix that keeps cached statements working is per-portal shape
/// tracking; that is a deferred follow-up.
///
/// NULL values stay NULL. The replacement is written as a text-format value: redacting a column
/// fetched in binary format hands the client bytes it may fail to decode — still redacted.
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
            shape: Shape::Unknown,
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

/// The row shape for the DataRows currently being returned.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Shape {
    /// No RowDescription has established the shape for the upcoming rows — cannot redact safely.
    Unknown,
    /// Shape known; the redacted column is absent from this result.
    Absent,
    /// Shape known; redact this column index.
    At(usize),
}

pub struct PostgresRedactColumn {
    column: String,
    replacement: String,
    /// The row shape for the result currently in flight. Persists across response trains so an
    /// extended-protocol Describe establishes the shape for the following Execute, and resets at
    /// each result boundary so a cached statement that skips Describe fails closed.
    shape: Shape,
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
            // Only postgres server responses are candidates; skip Dummy and anything else.
            if response.message_type() != MessageType::Postgres {
                continue;
            }
            if let Err(reason) = self.redact_response(response) {
                // Fail closed: never let an unredactable result reach the client. Replace it with
                // an error carrying the same request id so the client sees a failure, not data.
                match response.from_response_to_error_response(
                    format!("PostgresRedactColumn: {reason}"),
                    MessageErrorType::Internal,
                ) {
                    Ok(error) => *response = error,
                    // If we cannot even build an error response, drop the message rather than leak.
                    Err(_) => response.replace_with_dummy(),
                }
            }
        }
        Ok(responses)
    }
}

impl PostgresRedactColumn {
    /// Redacts a single server response in place, or returns Err with a reason if the result cannot
    /// be redacted safely (the caller then fails the response closed).
    fn redact_response(&mut self, response: &mut Message) -> Result<(), String> {
        let mut modified = false;
        let mut fail: Option<String> = None;
        {
            let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
                return Err("could not parse server response".to_owned());
            };
            for message in messages.iter_mut() {
                match message {
                    BackendMessage::RowDescription { fields } => {
                        self.shape = match fields.iter().position(|f| f.name == self.column) {
                            Some(index) => Shape::At(index),
                            None => Shape::Absent,
                        };
                    }
                    BackendMessage::DataRow { values } => match self.shape {
                        Shape::At(index) => {
                            if let Some(value) = values.get_mut(index)
                                && value.is_some()
                            {
                                *value = Some(Bytes::copy_from_slice(self.replacement.as_bytes()));
                                modified = true;
                            }
                        }
                        Shape::Absent => {}
                        Shape::Unknown => {
                            if fail.is_none() {
                                fail = Some(
                                    "cannot redact a result whose row shape was not described \
                                     (a cached prepared statement skipped Describe)"
                                        .to_owned(),
                                );
                            }
                        }
                    },
                    // COPY output carries rows outside DataRow messages and cannot be redacted here.
                    BackendMessage::CopyOutResponse { .. }
                    | BackendMessage::CopyBothResponse { .. } => {
                        if fail.is_none() {
                            fail = Some("cannot redact COPY output".to_owned());
                        }
                    }
                    // A result boundary: the next result must establish its own shape.
                    BackendMessage::CommandComplete { .. }
                    | BackendMessage::EmptyQueryResponse
                    | BackendMessage::PortalSuspended
                    | BackendMessage::ReadyForQuery { .. } => {
                        self.shape = Shape::Unknown;
                    }
                    _ => {}
                }
            }
        }
        if let Some(reason) = fail {
            return Err(reason);
        }
        if modified {
            response.invalidate_cache();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::postgres::FieldDescription;
    use crate::message::Message;

    fn redactor() -> PostgresRedactColumn {
        PostgresRedactColumn {
            column: "ssn".to_owned(),
            replacement: "[REDACTED]".to_owned(),
            shape: Shape::Unknown,
        }
    }

    fn field(name: &str) -> FieldDescription {
        FieldDescription {
            name: name.to_owned(),
            table_oid: 0,
            column_attribute_number: 0,
            data_type_oid: 25,
            data_type_size: -1,
            type_modifier: -1,
            format_code: 0,
        }
    }

    fn response(messages: Vec<BackendMessage>) -> Message {
        Message::from_frame(Frame::Postgres(PostgresFrame::Response(messages)))
    }

    fn data_row_value(message: &mut Message, row: usize, col: usize) -> Vec<u8> {
        match message.frame() {
            Some(Frame::Postgres(PostgresFrame::Response(messages))) => match &messages[row] {
                BackendMessage::DataRow { values } => values[col].as_ref().unwrap().to_vec(),
                other => panic!("expected DataRow, got {other:?}"),
            },
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn test_simple_query_redacts_the_named_column() {
        let mut r = redactor();
        let mut m = response(vec![
            BackendMessage::RowDescription {
                fields: vec![field("id"), field("ssn")],
            },
            BackendMessage::DataRow {
                values: vec![
                    Some(Bytes::from_static(b"1")),
                    Some(Bytes::from_static(b"111-22-3333")),
                ],
            },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        assert!(r.redact_response(&mut m).is_ok());
        assert_eq!(data_row_value(&mut m, 1, 1), b"[REDACTED]");
        assert_eq!(data_row_value(&mut m, 1, 0), b"1"); // other columns untouched
    }

    #[test]
    fn test_cached_statement_without_describe_fails_closed() {
        let mut r = redactor();
        // An Execute train with DataRows but no RowDescription (the driver cached the statement and
        // skipped Describe) MUST fail closed rather than leak the real value.
        let mut m = response(vec![
            BackendMessage::DataRow {
                values: vec![
                    Some(Bytes::from_static(b"1")),
                    Some(Bytes::from_static(b"111-22-3333")),
                ],
            },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        assert!(r.redact_response(&mut m).is_err());
    }

    #[test]
    fn test_column_absent_is_not_an_error() {
        let mut r = redactor();
        let mut m = response(vec![
            BackendMessage::RowDescription {
                fields: vec![field("id"), field("name")],
            },
            BackendMessage::DataRow {
                values: vec![
                    Some(Bytes::from_static(b"1")),
                    Some(Bytes::from_static(b"alice")),
                ],
            },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        assert!(r.redact_response(&mut m).is_ok());
        assert_eq!(data_row_value(&mut m, 1, 1), b"alice");
    }

    #[test]
    fn test_extended_describe_then_execute_carries_shape() {
        let mut r = redactor();
        // Describe train establishes the shape (no result boundary, so it persists).
        let mut describe = response(vec![BackendMessage::RowDescription {
            fields: vec![field("ssn")],
        }]);
        assert!(r.redact_response(&mut describe).is_ok());
        // Execute train (a separate message) redacts using the carried shape.
        let mut execute = response(vec![
            BackendMessage::DataRow {
                values: vec![Some(Bytes::from_static(b"111-22-3333"))],
            },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        assert!(r.redact_response(&mut execute).is_ok());
        assert_eq!(data_row_value(&mut execute, 0, 0), b"[REDACTED]");
    }

    #[test]
    fn test_copy_output_fails_closed() {
        let mut r = redactor();
        let mut m = response(vec![BackendMessage::CopyOutResponse {
            overall_format: 0,
            column_formats: vec![0],
        }]);
        assert!(r.redact_response(&mut m).is_err());
    }
}
