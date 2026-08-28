use crate::frame::postgres::{BackendMessage, FrontendMessage, PostgresFrame};
use crate::frame::{Frame, MessageType};
use crate::message::{Message, MessageId, Messages};
use crate::transforms::{
    ChainState, DownChainProtocol, Transform, TransformBuilder, TransformConfig,
    TransformContextBuilder, TransformContextConfig, UpChainProtocol,
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Replaces the value of a named result column with a fixed replacement string in every DataRow
/// flowing back to the client.
///
/// # Row-shape tracking
/// To redact by column name the transform needs the row shape (which column index carries the
/// name). In the simple query protocol the RowDescription and its DataRows share one response, so
/// the shape is always present. In the extended protocol the RowDescription arrives with a Describe
/// response while DataRows arrive with Execute responses — and a driver that caches a prepared
/// statement (asyncpg, psycopg3, pgjdbc past prepareThreshold) sends Describe only once, then
/// re-executes with no Describe. So the transform watches the request stream too: a Describe
/// establishes a statement's shape, Bind records portal→statement, and each Execute's response is
/// redacted using its statement's remembered shape (matched to the request by id). This keeps cached
/// statements and paginated portals (JDBC setFetchSize) working.
///
/// # Fail-closed
/// It is a security control, so when it genuinely cannot determine the shape for a set of DataRows —
/// an Execute of a statement it never saw Described — it replaces the whole response with an error
/// rather than risk leaking an unredacted value. COPY output (rows outside DataRow messages) and any
/// unparseable response also fail closed.
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
            statement_shapes: HashMap::new(),
            portal_statements: HashMap::new(),
            pending: HashMap::new(),
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

/// A known row shape for a statement's result. Absence from the map means the shape is unknown.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Shape {
    /// The redacted column is absent from this statement's result.
    Absent,
    /// Redact this column index.
    At(usize),
}

/// What a request in flight will produce, so its response can be interpreted when it comes back.
#[derive(Debug, Clone)]
enum Awaiting {
    /// A Describe: its RowDescription (or NoData) establishes the shape of this statement.
    Describe(String),
    /// An Execute: its DataRows are redacted using this statement's remembered shape.
    Execute(String),
    /// A simple Query: its response train carries its own RowDescription.
    SimpleQuery,
}

pub struct PostgresRedactColumn {
    column: String,
    replacement: String,
    /// Remembered result shape per prepared statement name, learned from a Describe/RowDescription.
    statement_shapes: HashMap<String, Shape>,
    /// Portal name -> prepared statement name, from Bind, so an Execute can find its shape.
    portal_statements: HashMap<String, String>,
    /// Requests in flight that produce a shape-relevant response, keyed by request id.
    pending: HashMap<MessageId, Awaiting>,
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
        // On the way down, learn what each request will produce (which statement a Describe
        // establishes, which statement an Execute reads, portal→statement from Bind).
        for request in chain_state.requests.iter_mut() {
            self.note_request(request);
        }

        let mut responses = chain_state.call_next_transform().await?;
        for response in &mut responses {
            // Only postgres server responses are candidates; skip Dummy and anything else.
            if response.message_type() != MessageType::Postgres {
                continue;
            }
            if let Err(reason) = self.redact_response(response) {
                // Fail closed: never let an unredactable result reach the client. Replace it with
                // an error carrying the same request id so the client sees a failure, not data.
                *response = fail_closed_response(response, &reason);
            }
        }
        Ok(responses)
    }
}

/// Builds the error that replaces an unredactable response.
///
/// It appends a ReadyForQuery ONLY when the response being replaced carried one (a simple-query
/// train), so the client's transaction-state machine stays in sync. An extended-protocol Execute
/// train carries no ReadyForQuery — that comes with the client's Sync — so replacing it with an
/// error+ReadyForQuery would deliver two ReadyForQuery for one Sync and desync the client.
fn fail_closed_response(original: &mut Message, reason: &str) -> Message {
    let had_ready_for_query = matches!(
        original.frame(),
        Some(Frame::Postgres(PostgresFrame::Response(messages)))
            if messages.iter().any(|m| matches!(m, BackendMessage::ReadyForQuery { .. }))
    );
    let mut messages = vec![BackendMessage::ErrorResponse {
        fields: vec![
            (b'S', "ERROR".to_owned()),
            (b'V', "ERROR".to_owned()),
            (b'C', "XX000".to_owned()),
            (b'M', format!("PostgresRedactColumn: {reason}")),
        ],
    }];
    if had_ready_for_query {
        messages.push(BackendMessage::ReadyForQuery { status: b'I' });
    }
    let mut response = Message::from_frame(Frame::Postgres(PostgresFrame::Response(messages)));
    if let Some(id) = original.request_id() {
        response.set_request_id(id);
    }
    response
}

impl PostgresRedactColumn {
    /// Records, from a request travelling down the chain, what its response will mean.
    fn note_request(&mut self, request: &mut Message) {
        let id = request.id();
        let Some(Frame::Postgres(PostgresFrame::Request(message))) = request.frame() else {
            return;
        };
        match message {
            // A re-Parse of a name invalidates any remembered shape for it.
            FrontendMessage::Parse { statement_name, .. } => {
                self.statement_shapes.remove(statement_name);
            }
            FrontendMessage::Bind {
                portal_name,
                statement_name,
                ..
            } => {
                self.portal_statements
                    .insert(portal_name.clone(), statement_name.clone());
            }
            FrontendMessage::Describe { kind, name } => {
                // 'S' describes a statement directly; 'P' describes a portal — resolve to its
                // statement so all portals of a statement share the one remembered shape.
                let statement = if *kind == b'S' {
                    name.clone()
                } else {
                    self.portal_statements
                        .get(name)
                        .cloned()
                        .unwrap_or_default()
                };
                self.pending.insert(id, Awaiting::Describe(statement));
            }
            FrontendMessage::Execute { portal_name, .. } => {
                let statement = self
                    .portal_statements
                    .get(portal_name)
                    .cloned()
                    .unwrap_or_default();
                self.pending.insert(id, Awaiting::Execute(statement));
            }
            FrontendMessage::Query { .. } => {
                self.pending.insert(id, Awaiting::SimpleQuery);
            }
            FrontendMessage::Close { kind, name } => {
                if *kind == b'S' {
                    self.statement_shapes.remove(name);
                } else {
                    self.portal_statements.remove(name);
                }
            }
            _ => {}
        }
    }

    /// Redacts a single server response in place, or returns Err with a reason if the result cannot
    /// be redacted safely (the caller then fails the response closed).
    fn redact_response(&mut self, response: &mut Message) -> Result<(), String> {
        // What request produced this response tells us which statement's shape applies.
        let awaiting = response
            .request_id()
            .and_then(|id| self.pending.remove(&id));
        let statement = match &awaiting {
            Some(Awaiting::Describe(s)) | Some(Awaiting::Execute(s)) => Some(s.clone()),
            _ => None,
        };
        // An Execute starts from its statement's remembered shape; everything else starts unknown
        // and relies on a RowDescription within the response itself.
        let mut shape: Option<Shape> = match &awaiting {
            Some(Awaiting::Execute(s)) => self.statement_shapes.get(s).copied(),
            _ => None,
        };

        let mut modified = false;
        let mut fail: Option<String> = None;
        {
            let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
                return Err("could not parse server response".to_owned());
            };
            for message in messages.iter_mut() {
                match message {
                    BackendMessage::RowDescription { fields } => {
                        let resolved = match fields.iter().position(|f| f.name == self.column) {
                            Some(index) => Shape::At(index),
                            None => Shape::Absent,
                        };
                        shape = Some(resolved);
                        if let Some(statement) = &statement {
                            self.statement_shapes.insert(statement.clone(), resolved);
                        }
                    }
                    // A described statement that returns no rows: remember it as having no columns.
                    BackendMessage::NoData => {
                        shape = Some(Shape::Absent);
                        if let Some(statement) = &statement {
                            self.statement_shapes
                                .insert(statement.clone(), Shape::Absent);
                        }
                    }
                    BackendMessage::DataRow { values } => match shape {
                        Some(Shape::At(index)) => {
                            if let Some(value) = values.get_mut(index)
                                && value.is_some()
                            {
                                *value = Some(Bytes::copy_from_slice(self.replacement.as_bytes()));
                                modified = true;
                            }
                        }
                        Some(Shape::Absent) => {}
                        None => {
                            if fail.is_none() {
                                fail = Some(
                                    "cannot redact a result whose row shape is unknown \
                                     (a statement executed without ever being described)"
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
                    // A result boundary within THIS response: a following result set (simple query
                    // with several statements) must present its own RowDescription. PortalSuspended
                    // is deliberately absent — it continues the same result. The per-statement shape
                    // in `statement_shapes` is untouched, so a later Execute still redacts.
                    BackendMessage::CommandComplete { .. }
                    | BackendMessage::EmptyQueryResponse
                    | BackendMessage::ReadyForQuery { .. } => {
                        shape = None;
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
            statement_shapes: HashMap::new(),
            portal_statements: HashMap::new(),
            pending: HashMap::new(),
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

    /// Notes a request travelling down the chain and returns its id, so a response can be built that
    /// pairs to it (as the codec would via the request id).
    fn note(r: &mut PostgresRedactColumn, message: FrontendMessage) -> MessageId {
        let mut request = Message::from_frame(Frame::Postgres(PostgresFrame::Request(message)));
        let id = request.id();
        r.note_request(&mut request);
        id
    }

    fn response_for(id: MessageId, messages: Vec<BackendMessage>) -> Message {
        let mut m = response(messages);
        m.set_request_id(id);
        m
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
    fn test_execute_of_undescribed_statement_fails_closed() {
        let mut r = redactor();
        // An Execute of a statement that was never described -> shape genuinely unknown -> fail
        // closed rather than leak.
        note(&mut r, bind("p", "s"));
        let e = note(
            &mut r,
            FrontendMessage::Execute {
                portal_name: "p".to_owned(),
                max_rows: 0,
            },
        );
        let mut m = response_for(
            e,
            vec![
                BackendMessage::DataRow {
                    values: vec![Some(Bytes::from_static(b"111-22-3333"))],
                },
                BackendMessage::CommandComplete {
                    tag: "SELECT 1".to_owned(),
                },
            ],
        );
        assert!(r.redact_response(&mut m).is_err());
    }

    #[test]
    fn test_cached_statement_redacts_from_remembered_shape() {
        // The C2/R7 fix: once a statement has been described, later Executes with NO Describe
        // (cached prepared statements) redact from the remembered shape instead of failing closed.
        let mut r = redactor();
        note(
            &mut r,
            FrontendMessage::Parse {
                statement_name: "s".to_owned(),
                query: "SELECT ssn FROM t".to_owned(),
                parameter_data_types: vec![],
            },
        );
        let d = note(
            &mut r,
            FrontendMessage::Describe {
                kind: b'S',
                name: "s".to_owned(),
            },
        );
        let mut describe = response_for(
            d,
            vec![BackendMessage::RowDescription {
                fields: vec![field("ssn")],
            }],
        );
        assert!(r.redact_response(&mut describe).is_ok());

        // Now a cached re-execution: Bind + Execute, no Describe.
        note(&mut r, bind("p", "s"));
        let e = note(
            &mut r,
            FrontendMessage::Execute {
                portal_name: "p".to_owned(),
                max_rows: 0,
            },
        );
        let mut execute = response_for(
            e,
            vec![
                BackendMessage::DataRow {
                    values: vec![Some(Bytes::from_static(b"111-22-3333"))],
                },
                BackendMessage::CommandComplete {
                    tag: "SELECT 1".to_owned(),
                },
            ],
        );
        assert!(r.redact_response(&mut execute).is_ok());
        assert_eq!(data_row_value(&mut execute, 0, 0), b"[REDACTED]");
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
    fn test_copy_output_fails_closed() {
        let mut r = redactor();
        let mut m = response(vec![BackendMessage::CopyOutResponse {
            overall_format: 0,
            column_formats: vec![0],
        }]);
        assert!(r.redact_response(&mut m).is_err());
    }

    #[test]
    fn test_portal_resumed_after_sync_still_redacts() {
        // JDBC setFetchSize inside a transaction: Describe/Execute(max_rows)+Sync, then
        // Execute(max_rows)+Sync on the SAME portal. The portal survives the Sync, the second
        // Execute has no Describe, and the ReadyForQuery of the first Sync must not lose the shape.
        let mut r = redactor();
        note(
            &mut r,
            FrontendMessage::Parse {
                statement_name: "s".to_owned(),
                query: "SELECT ssn FROM t".to_owned(),
                parameter_data_types: vec![],
            },
        );
        note(&mut r, bind("p", "s"));
        let d = note(
            &mut r,
            FrontendMessage::Describe {
                kind: b'P',
                name: "p".to_owned(),
            },
        );
        let e1 = note(
            &mut r,
            FrontendMessage::Execute {
                portal_name: "p".to_owned(),
                max_rows: 1,
            },
        );
        // Responses: Describe -> RowDescription; Execute -> DataRow + PortalSuspended; Sync -> RFQ.
        let mut describe = response_for(
            d,
            vec![BackendMessage::RowDescription {
                fields: vec![field("ssn")],
            }],
        );
        assert!(r.redact_response(&mut describe).is_ok());
        let mut exec1 = response_for(
            e1,
            vec![
                BackendMessage::DataRow {
                    values: vec![Some(Bytes::from_static(b"111-22-3333"))],
                },
                BackendMessage::PortalSuspended,
            ],
        );
        assert!(r.redact_response(&mut exec1).is_ok());
        assert_eq!(data_row_value(&mut exec1, 0, 0), b"[REDACTED]");
        // The Sync's ReadyForQuery arrives (its own response), resetting only the local shape.
        let mut ready = response(vec![BackendMessage::ReadyForQuery { status: b'T' }]);
        assert!(r.redact_response(&mut ready).is_ok());

        // Second Execute on the same portal, no Describe: must still redact from the statement shape.
        let e2 = note(
            &mut r,
            FrontendMessage::Execute {
                portal_name: "p".to_owned(),
                max_rows: 1,
            },
        );
        let mut exec2 = response_for(
            e2,
            vec![
                BackendMessage::DataRow {
                    values: vec![Some(Bytes::from_static(b"444-55-6666"))],
                },
                BackendMessage::PortalSuspended,
            ],
        );
        assert!(
            r.redact_response(&mut exec2).is_ok(),
            "a portal resumed after a Sync must not fail closed"
        );
        assert_eq!(data_row_value(&mut exec2, 0, 0), b"[REDACTED]");
    }

    fn bind(portal: &str, statement: &str) -> FrontendMessage {
        FrontendMessage::Bind {
            portal_name: portal.to_owned(),
            statement_name: statement.to_owned(),
            parameter_format_codes: vec![],
            parameter_values: vec![],
            result_format_codes: vec![],
        }
    }

    #[test]
    fn test_fail_closed_response_matches_ready_for_query_of_original() {
        // Replacing a simple-query train (which carries ReadyForQuery) keeps a ReadyForQuery.
        let mut simple = response(vec![
            BackendMessage::DataRow { values: vec![] },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let mut replaced = fail_closed_response(&mut simple, "x");
        assert!(matches!(
            replaced.frame(),
            Some(Frame::Postgres(PostgresFrame::Response(m)))
                if m.iter().any(|x| matches!(x, BackendMessage::ReadyForQuery { .. }))
        ));
        // Replacing an extended Execute train (no ReadyForQuery) must NOT add one, or the client
        // would see two ReadyForQuery for one Sync.
        let mut extended = response(vec![
            BackendMessage::DataRow { values: vec![] },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
        ]);
        let mut replaced = fail_closed_response(&mut extended, "x");
        assert!(matches!(
            replaced.frame(),
            Some(Frame::Postgres(PostgresFrame::Response(m)))
                if !m.iter().any(|x| matches!(x, BackendMessage::ReadyForQuery { .. }))
        ));
    }
}
