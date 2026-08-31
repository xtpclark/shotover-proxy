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
/// # NOT a security control — read this before relying on it
/// Redaction is keyed on the result column LABEL carried in `RowDescription`, and that label is
/// entirely client-controlled. It therefore CANNOT protect a value against the user writing the query
/// — anyone who writes their own SQL defeats it in one keystroke. Its only honest value is preventing
/// ACCIDENTAL exposure by queries that happen to select the column by its plain name.
///
/// Concretely (live `RowDescription` provenance, configured column "ssn"):
/// * `SELECT ssn FROM patients`      → label `ssn`,      table_oid 16384, attnum 2 — REDACTED
/// * `SELECT ssn AS x FROM patients` → label `x`,        table_oid 16384, attnum 2 — LEAKS (label differs)
/// * `SELECT * FROM v_patients`      → label `social`,   table_oid 16389 (the VIEW's oid) — LEAKS
/// * `SELECT ssn||'' FROM patients`  → label `?column?`, table_oid 0 (no provenance) — LEAKS
/// * two output columns both labelled `ssn` → only the first is redacted; the second LEAKS
///
/// The failure differs by construction: an alias PRESERVES (table_oid, attnum), so matching on those
/// WOULD catch it; but a renaming view reports the VIEW's oid (a base-table match still misses it
/// without catalog resolution), and a computed column carries no provenance at all. So there is no
/// complete fix at the proxy layer — an (table_oid, attnum) match would be a partial improvement only,
/// and is deferred.
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
/// # Fail-closed on unknown shape
/// When it cannot determine the shape for a set of DataRows — an Execute of a statement it never saw
/// Described — it replaces the whole response with an error rather than emit rows it could not inspect.
/// COPY output (rows outside DataRow messages) and any unparseable response also fail closed. This
/// keeps the redaction it CAN do honest; it is not a substitute for the guarantee that label-matching
/// cannot provide (see above).
///
/// A fail-close inside a transaction reports the aborted status ('E') so a client that rolls back on
/// error — as most drivers do — undoes the statement's real effect and the two ends reconverge. Its
/// limits, by construction: (1) the statement ALREADY executed on the server (a fail-close hides the
/// result, it does not prevent the statement), so a client that instead COMMITs an apparently-aborted
/// transaction commits it on the server — the status agrees, the outcome may not; and (2) the abort
/// marker is applied to the next ReadyForQuery, so a fail-close on a Flush-terminated Execute followed
/// by an explicit simple-query ROLLBACK briefly reports that ROLLBACK as 'E' (it self-corrects on the
/// next statement). Both are the residue of a response-side transform being unable to abort a server
/// transaction — not fixable at this layer.
///
/// NULL values stay NULL. The replacement is written as a text-format value: redacting a column
/// fetched in binary format hands the client bytes it may fail to decode — still redacted.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PostgresRedactColumnConfig {
    pub name: String,
    /// The result column LABEL to redact, matched exactly against `RowDescription`. This label is
    /// client-controlled — an `AS` alias, an expression, or a renaming view changes it and the value
    /// is NOT redacted. See the type doc: this is accidental-exposure hygiene, not a security control.
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
            in_transaction: false,
            pending_abort: false,
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
/// The statement name is `None` when a portal could not be resolved to a statement — the shape is
/// then unknown, and an Execute of it fails closed rather than defaulting to the unnamed statement.
#[derive(Debug, Clone)]
enum Awaiting {
    /// A Describe: its RowDescription (or NoData) establishes the shape of this statement.
    Describe(Option<String>),
    /// An Execute: its DataRows are redacted using this statement's remembered shape.
    Execute(Option<String>),
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
    /// Whether the session is currently inside a transaction, tracked from the ReadyForQuery status
    /// the redactor ultimately emits (any status other than 'I' means in a transaction).
    in_transaction: bool,
    /// Set when an extended-protocol Execute failed closed inside a transaction: the next
    /// ReadyForQuery (arriving with the client's Sync) is rewritten to the aborted state 'E' so the
    /// client and server agree the transaction failed.
    pending_abort: bool,
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
            // Remove the pending entry for this response whatever its kind, so entries for requests
            // answered by a synthesised Dummy (e.g. requests discarded after an extended-protocol
            // error) do not accumulate on a long-lived connection.
            let awaiting = response
                .request_id()
                .and_then(|id| self.pending.remove(&id));
            // Only postgres server responses carry rows to redact; Dummy and anything else pass on.
            if response.message_type() != MessageType::Postgres {
                continue;
            }
            if let Err(reason) = self.redact_response(response, awaiting) {
                // Fail closed: never let an unredactable result reach the client. Replace it with
                // an error carrying the same request id so the client sees a failure, not data.
                *response = self.fail_closed_response(response, &reason);
            }
            // Track transaction state from this response's ReadyForQuery, drive the client to the
            // aborted state after an extended-protocol fail-close, and reclaim portal state at
            // transaction end. Runs for every postgres response, redacted or not.
            self.observe_transaction_state(response);
        }
        Ok(responses)
    }
}

/// The most result shapes the redactor remembers per connection. Named prepared statements live until
/// session end, so their shapes cannot be dropped at transaction end like portals; this bounds the map
/// instead. An evicted shape simply fails closed and is re-learned on the next Describe.
const MAX_STATEMENT_SHAPES: usize = 1024;

impl PostgresRedactColumn {
    /// Builds the error that replaces an unredactable response, keeping the client's transaction
    /// state coherent.
    ///
    /// A simple-query train carries its own ReadyForQuery, so the replacement carries one too, with
    /// the status Postgres would send after a statement error: 'E' (aborted) when inside a
    /// transaction, else 'I'. An extended-protocol Execute train carries NO ReadyForQuery — it comes
    /// with the client's Sync — so none is appended (appending one would deliver two ReadyForQuery for
    /// one Sync and desync the client); instead, when inside a transaction, `pending_abort` is set so
    /// the Sync's ReadyForQuery is reported aborted when it passes through.
    fn fail_closed_response(&mut self, original: &mut Message, reason: &str) -> Message {
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
            messages.push(BackendMessage::ReadyForQuery {
                status: if self.in_transaction { b'E' } else { b'I' },
            });
        } else if self.in_transaction {
            self.pending_abort = true;
        }
        let mut response = Message::from_frame(Frame::Postgres(PostgresFrame::Response(messages)));
        if let Some(id) = original.request_id() {
            response.set_request_id(id);
        }
        response
    }

    /// Records a statement's shape, evicting an arbitrary entry first when the map is at its cap, so a
    /// client that Parses unbounded distinct named statements cannot grow it without limit.
    fn remember_shape(&mut self, statement: &str, shape: Shape) {
        if self.statement_shapes.len() >= MAX_STATEMENT_SHAPES
            && !self.statement_shapes.contains_key(statement)
            && let Some(evict) = self.statement_shapes.keys().next().cloned()
        {
            self.statement_shapes.remove(&evict);
        }
        self.statement_shapes.insert(statement.to_owned(), shape);
    }

    /// Keeps transaction state coherent with a fail-close and reclaims per-statement state.
    ///
    /// A `pending_abort` (set when an extended-protocol Execute failed closed inside a transaction)
    /// rewrites the next ReadyForQuery to the aborted state 'E', so the client rolls back exactly what
    /// the server will. `in_transaction` is then read from the status ULTIMATELY EMITTED, so a
    /// self-synthesised 'E'/'I' never drives tracking to a state the server does not share. At
    /// transaction end ('I') the non-holdable portals Postgres itself drops are reclaimed, bounding
    /// per-connection state (a WITH HOLD cursor then fails closed on its next fetch — safe).
    fn observe_transaction_state(&mut self, response: &mut Message) {
        let mut latest_status = None;
        let mut changed = false;
        {
            let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
                return;
            };
            for message in messages.iter_mut() {
                if let BackendMessage::ReadyForQuery { status } = message {
                    if self.pending_abort {
                        *status = b'E';
                        self.pending_abort = false;
                        changed = true;
                    }
                    latest_status = Some(*status);
                }
            }
        }
        if changed {
            response.invalidate_cache();
        }
        if let Some(status) = latest_status {
            self.in_transaction = status != b'I';
            if status == b'I' {
                self.portal_statements.clear();
            }
        }
    }
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
                // statement so all portals of a statement share the one remembered shape. An
                // unresolvable portal stays None (unknown) rather than defaulting to "".
                let statement = if *kind == b'S' {
                    Some(name.clone())
                } else {
                    self.portal_statements.get(name).cloned()
                };
                self.pending.insert(id, Awaiting::Describe(statement));
            }
            FrontendMessage::Execute { portal_name, .. } => {
                // An unresolvable portal stays None (unknown), so redaction fails closed rather than
                // defaulting to the unnamed statement's shape.
                let statement = self.portal_statements.get(portal_name).cloned();
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
    /// be redacted safely (the caller then fails the response closed). `awaiting` says what request
    /// produced this response, and therefore which statement's shape applies.
    fn redact_response(
        &mut self,
        response: &mut Message,
        awaiting: Option<Awaiting>,
    ) -> Result<(), String> {
        let statement = match &awaiting {
            Some(Awaiting::Describe(s)) | Some(Awaiting::Execute(s)) => s.clone(),
            _ => None,
        };
        // An Execute starts from its statement's remembered shape; everything else starts unknown
        // and relies on a RowDescription within the response itself.
        let mut shape: Option<Shape> = match &awaiting {
            Some(Awaiting::Execute(Some(s))) => self.statement_shapes.get(s).copied(),
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
                            self.remember_shape(statement, resolved);
                        }
                    }
                    // A described statement that returns no rows: remember it as having no columns.
                    BackendMessage::NoData => {
                        shape = Some(Shape::Absent);
                        if let Some(statement) = &statement {
                            self.remember_shape(statement, Shape::Absent);
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
            in_transaction: false,
            pending_abort: false,
        }
    }

    fn trailing_rfq(message: &mut Message) -> Option<u8> {
        match message.frame() {
            Some(Frame::Postgres(PostgresFrame::Response(messages))) => {
                messages.iter().rev().find_map(|m| match m {
                    BackendMessage::ReadyForQuery { status } => Some(*status),
                    _ => None,
                })
            }
            _ => None,
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

    /// Mirrors the transform's response handling: pop the pending entry for this response and redact.
    fn redact(r: &mut PostgresRedactColumn, response: &mut Message) -> Result<(), String> {
        let awaiting = response.request_id().and_then(|id| r.pending.remove(&id));
        r.redact_response(response, awaiting)
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
        assert!(redact(&mut r, &mut m).is_ok());
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
        assert!(redact(&mut r, &mut m).is_err());
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
        assert!(redact(&mut r, &mut describe).is_ok());

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
        assert!(redact(&mut r, &mut execute).is_ok());
        assert_eq!(data_row_value(&mut execute, 0, 0), b"[REDACTED]");
    }

    #[test]
    fn test_execute_of_unbound_portal_fails_closed() {
        // An Execute of a portal that was never Bound cannot be resolved to a statement. It must
        // fail closed, NOT default to the unnamed statement's shape (which every driver reuses).
        let mut r = redactor();
        // Give the unnamed statement a real shape, to prove an unresolvable portal does not borrow it.
        r.statement_shapes.insert(String::new(), Shape::At(0));
        let e = note(
            &mut r,
            FrontendMessage::Execute {
                portal_name: "never_bound".to_owned(),
                max_rows: 0,
            },
        );
        let mut m = response_for(
            e,
            vec![BackendMessage::DataRow {
                values: vec![Some(Bytes::from_static(b"111-22-3333"))],
            }],
        );
        assert!(redact(&mut r, &mut m).is_err());
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
        assert!(redact(&mut r, &mut m).is_ok());
        assert_eq!(data_row_value(&mut m, 1, 1), b"alice");
    }

    #[test]
    fn test_copy_output_fails_closed() {
        let mut r = redactor();
        let mut m = response(vec![BackendMessage::CopyOutResponse {
            overall_format: 0,
            column_formats: vec![0],
        }]);
        assert!(redact(&mut r, &mut m).is_err());
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
        assert!(redact(&mut r, &mut describe).is_ok());
        let mut exec1 = response_for(
            e1,
            vec![
                BackendMessage::DataRow {
                    values: vec![Some(Bytes::from_static(b"111-22-3333"))],
                },
                BackendMessage::PortalSuspended,
            ],
        );
        assert!(redact(&mut r, &mut exec1).is_ok());
        assert_eq!(data_row_value(&mut exec1, 0, 0), b"[REDACTED]");
        // The Sync's ReadyForQuery arrives (its own response), resetting only the local shape.
        let mut ready = response(vec![BackendMessage::ReadyForQuery { status: b'T' }]);
        assert!(redact(&mut r, &mut ready).is_ok());

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
            redact(&mut r, &mut exec2).is_ok(),
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
        let mut r = redactor();
        // Replacing a simple-query train (which carries ReadyForQuery) keeps a ReadyForQuery.
        let mut simple = response(vec![
            BackendMessage::DataRow { values: vec![] },
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        let mut replaced = r.fail_closed_response(&mut simple, "x");
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
        let mut replaced = r.fail_closed_response(&mut extended, "x");
        assert!(matches!(
            replaced.frame(),
            Some(Frame::Postgres(PostgresFrame::Response(m)))
                if !m.iter().any(|x| matches!(x, BackendMessage::ReadyForQuery { .. }))
        ));
    }

    #[test]
    fn test_simple_query_fail_close_reports_abort_inside_transaction() {
        // Finding 4: a fail-close inside a transaction must report the aborted state 'E', not the
        // server's 'T'/'I', or the client and server disagree about the transaction. Outside a
        // transaction the status is 'I'.
        let mut r = redactor();
        let train = || {
            response(vec![
                BackendMessage::DataRow { values: vec![] },
                BackendMessage::CommandComplete {
                    tag: "SELECT 1".to_owned(),
                },
                BackendMessage::ReadyForQuery { status: b'T' },
            ])
        };
        r.in_transaction = true;
        let mut in_txn = r.fail_closed_response(&mut train(), "x");
        assert_eq!(trailing_rfq(&mut in_txn), Some(b'E'));
        r.in_transaction = false;
        let mut no_txn = r.fail_closed_response(&mut train(), "x");
        assert_eq!(trailing_rfq(&mut no_txn), Some(b'I'));
    }

    #[test]
    fn test_extended_fail_close_drives_client_to_abort_and_reconverges() {
        // Finding 4 + the Finding-1/Finding-4 feedback loop: an extended Execute failing closed inside
        // a transaction carries no ReadyForQuery (that comes with Sync). It sets pending_abort and adds
        // no RFQ; the Sync's ReadyForQuery('T') is then rewritten to 'E' so the client rolls back what
        // the server will. in_transaction is read from the EMITTED status, so the synthesised 'E' keeps
        // tracking correct; the client's ROLLBACK ('I') clears it and reclaims portals (Finding 5).
        let mut r = redactor();
        r.in_transaction = true;

        let mut execute = response(vec![BackendMessage::DataRow {
            values: vec![Some(Bytes::from_static(b"111-22-3333"))],
        }]);
        let mut failed = r.fail_closed_response(&mut execute, "x");
        assert!(r.pending_abort);
        assert_eq!(trailing_rfq(&mut failed), None);
        // The fail-closed Execute response carries no RFQ, so pending_abort survives to the Sync.
        r.observe_transaction_state(&mut failed);
        assert!(r.pending_abort);

        let mut sync = response(vec![BackendMessage::ReadyForQuery { status: b'T' }]);
        r.observe_transaction_state(&mut sync);
        assert_eq!(trailing_rfq(&mut sync), Some(b'E'));
        assert!(!r.pending_abort);
        assert!(r.in_transaction); // 'E' != 'I' -> still inside a (failed) transaction

        r.portal_statements.insert("p".to_owned(), "s".to_owned());
        let mut rollback = response(vec![BackendMessage::ReadyForQuery { status: b'I' }]);
        r.observe_transaction_state(&mut rollback);
        assert!(!r.in_transaction);
        assert!(r.portal_statements.is_empty());
    }

    #[test]
    fn test_statement_shapes_are_bounded() {
        // Finding 5: named prepared statements Parsed without Close cannot grow the shape map forever.
        let mut r = redactor();
        for i in 0..(MAX_STATEMENT_SHAPES + 100) {
            r.remember_shape(&format!("stmt{i}"), Shape::Absent);
        }
        assert!(r.statement_shapes.len() <= MAX_STATEMENT_SHAPES);
    }
}
