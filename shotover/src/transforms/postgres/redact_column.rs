use crate::codec::postgres::{
    is_chunked_train_tail, is_partial_response, partial_train_request_id,
};
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
/// A fail-close INSIDE a transaction closes the client connection (after delivering the error, so the
/// client learns why). A response-side transform cannot roll back a statement that already executed on
/// the server, but dropping the connection makes the server do it: the sink connection closes with the
/// client's, the server rolls the transaction back, and every driver reads a dropped connection as
/// "transaction lost, nothing committed" — which is then exactly true. This is the honest resolution of
/// a limitation a status-byte rewrite could only paper over (a client that COMMITs an apparently-
/// aborted transaction would otherwise commit it on the server). Outside a transaction there is nothing
/// to abort: the error is self-coherent (idle 'I' for a simple query) and the connection stays open.
///
/// # Streaming
/// With `stream_threshold_bytes` set on the sink, a large result arrives as several messages instead
/// of one, and only the first can carry the RowDescription. Two things make that work:
///
/// * the shape is carried across chunk boundaries (`train_shape`), resuming where the previous chunk
///   stopped — including the reset at a `CommandComplete`, so the second statement of a
///   multi-statement query still has to present its own RowDescription rather than inherit an index;
/// * the first chunk of an EXTENDED-protocol train carries neither a RowDescription (it arrived
///   earlier, on the Describe's own train) nor a request id, so it is matched to its statement
///   through `PostgresCodecState::train_request_id` — a stamp the decoder applies because it, alone,
///   holds the queue of requests awaiting responses. Nothing here reconstructs that from what went
///   past; see the warning on `PostgresCodecState::chunked_tail` for why a transform must not try.
///
/// **The guarantee is narrower than it is for a whole train, and the difference is real.** Whole
/// trains are held in full, so an unredactable result can be replaced outright and nothing escapes.
/// A chunked train has already delivered its earlier chunks. What still holds: no row is ever
/// forwarded unredacted or under an unknown shape, because each chunk is inspected completely before
/// it is forwarded and a chunk that cannot be redacted is replaced before any of its rows go out.
/// What is given up: a failure discovered at chunk 5 cannot recall chunks 1-4 — so a fail-close on a
/// chunked train also closes the connection, in or out of a transaction, rather than pretend the
/// stream can continue coherently. Nothing stronger is available without buffering the whole result,
/// which is the cost streaming exists to remove.
///
/// Streaming does NOT widen the label-matching weakness above: `SELECT ssn AS x` leaked before and
/// leaks now, identically. It changes when a shape is learned, not what a shape can see.
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

    /// `true`: see the "Streaming" section of the module doc. The shape is carried across chunk
    /// boundaries, and the first chunk of an extended-protocol train — which carries neither a
    /// RowDescription nor a request id — is matched to its statement through the decoder's
    /// `train_request_id` stamp. Anything that cannot be resolved still fails closed.
    fn accepts_partial_responses(&self) -> bool {
        true
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
            train_shape: None,
            poisoned: false,
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
    /// the server emits (any status other than 'I' means in a transaction). A fail-close inside a
    /// transaction closes the connection so the server rolls back — see the transform loop.
    in_transaction: bool,
    /// The row shape in force for a response train currently arriving in CHUNKS.
    ///
    /// Only the first chunk of a train can carry a RowDescription, so the shape has to survive from
    /// one chunk to the next. This is exactly the `shape` local that `redact_response` already walks
    /// a response with, lifted out so a chunked train resumes where the previous chunk stopped: seeded
    /// from here for a partial or a tail, written back after a partial, cleared by the tail.
    ///
    /// `None` means either "no chunked train open" or "open, shape not yet known" — the two are only
    /// ever consulted through a message that says which it is.
    train_shape: Option<Shape>,
    /// Set when a chunked train has failed closed. The connection is being torn down at that point
    /// (see the transform loop), so nothing should reach the chain again — but if anything ever did,
    /// the remaining chunks of that train would resolve their shape from the decoder stamp and be
    /// forwarded, which is the leak the fail-close just prevented. Poisoning drops them instead.
    poisoned: bool,
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
            // Should be unreachable: a chunked train that failed closed set this AND asked for the
            // connection to be closed, and `run_loop` returns as soon as it has sent that run's
            // responses. But if anything ever did run the chain again, the remaining chunks of that
            // train would resolve their shape from the decoder stamp and be forwarded — exactly the
            // rows the fail-close just withheld. So refuse to redact anything more on this
            // connection rather than rely on a teardown owned by another file.
            if self.poisoned {
                *response = self.fail_closed_response(
                    response,
                    "connection is closing after a redaction failure",
                );
                chain_state.close_client_connection = true;
                continue;
            }
            // Whether this response is part of a train delivered in chunks, which changes what a
            // fail-close can achieve — read before `redact_response` borrows the frame.
            let chunked = is_partial_response(response) || is_chunked_train_tail(response);
            if let Err(reason) = self.redact_response(response, awaiting) {
                // Fail closed: never let an unredactable result reach the client. Replace it with
                // an error carrying the same request id so the client sees a failure, not data.
                *response = self.fail_closed_response(response, &reason);
                // Inside a transaction, make the abort REAL: the statement already executed on the
                // server and a response-side transform cannot roll it back, so close the client
                // connection. The chain sends this error to the client FIRST, then closes (see
                // send_receive_chain), and closing drops the sink connection with it — the server rolls
                // the transaction back, so "transaction lost, nothing committed" is true, not merely
                // reported. Outside a transaction there is nothing to abort and the error alone is
                // coherent, so the connection stays open.
                //
                // A CHUNKED train closes either way. Rows of it have already gone to the client, the
                // replacement error is unpaired (a partial carries no request id to copy), and the
                // rest of the train is still arriving from the backend — forwarding it would leak
                // precisely what this fail-close withheld. There is no coherent way to continue.
                if self.in_transaction || chunked {
                    chain_state.close_client_connection = true;
                }
                if chunked {
                    self.train_shape = None;
                    self.poisoned = true;
                }
            }
            // Track transaction state from this response's ReadyForQuery and reclaim portal state at
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
    /// Builds the error that replaces an unredactable response.
    ///
    /// Outside a transaction the error is self-coherent and the connection stays open: a simple-query
    /// train carries its own ReadyForQuery so the replacement carries one too (idle 'I'); an
    /// extended-protocol Execute train carries none (its ReadyForQuery comes with the client's Sync),
    /// so none is appended — appending one would deliver two ReadyForQuery for one Sync and desync the
    /// client. Inside a transaction NO ReadyForQuery is appended in either case: the caller closes the
    /// connection (see the transform loop), so the client should receive the error and then the close —
    /// a ReadyForQuery would falsely say "ready for the next query" as we are about to disconnect.
    fn fail_closed_response(&self, original: &mut Message, reason: &str) -> Message {
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
        if had_ready_for_query && !self.in_transaction {
            messages.push(BackendMessage::ReadyForQuery { status: b'I' });
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

    /// Tracks transaction state from a response's trailing ReadyForQuery and reclaims per-statement
    /// state. `in_transaction` decides whether a later fail-close closes the connection. At transaction
    /// end ('I') the non-holdable portals Postgres itself drops are reclaimed, bounding per-connection
    /// state (a WITH HOLD cursor then fails closed on its next fetch — safe).
    fn observe_transaction_state(&mut self, response: &mut Message) {
        let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
            return;
        };
        let latest_status = messages.iter().rev().find_map(|m| match m {
            BackendMessage::ReadyForQuery { status } => Some(*status),
            _ => None,
        });
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
        let partial = is_partial_response(response);
        let chunked = partial || is_chunked_train_tail(response);
        // An Execute starts from its statement's remembered shape; everything else starts unknown
        // and relies on a RowDescription within the response itself.
        let from_awaiting: Option<Shape> = match &awaiting {
            Some(Awaiting::Execute(Some(s))) => self.statement_shapes.get(s).copied(),
            _ => None,
        };
        // A chunk resumes the train the previous chunk left off in. Three sources, in order of
        // authority: the shape carried from an earlier chunk; the statement the decoder stamped this
        // chunk with, which is how the FIRST chunk of an extended-protocol train finds its shape
        // (that chunk carries neither a RowDescription nor a request id); and finally the request
        // this response answers, which only a tail has. A whole response uses the last of these
        // alone, exactly as before.
        let mut shape: Option<Shape> = if chunked {
            self.train_shape
                .or_else(|| self.stamped_train_shape(response))
                .or(from_awaiting)
        } else {
            from_awaiting
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
        if partial {
            // More of this train is coming and only the first chunk could have carried a
            // RowDescription, so the shape this chunk ended on is what the next one starts from.
            self.train_shape = shape;
        } else if chunked {
            // The tail ends the train.
            self.train_shape = None;
        }
        if let Some(reason) = fail {
            return Err(reason);
        }
        if modified {
            response.invalidate_cache();
        }
        Ok(())
    }

    /// The shape of the train this PARTIAL chunk belongs to, found through the request id the
    /// decoder stamped on it.
    ///
    /// This is what lets the first chunk of an extended-protocol Execute redact at all: its
    /// RowDescription arrived earlier, on the Describe's own train, and the chunk itself carries no
    /// request id to look up. The decoder knows which request is being answered because it holds the
    /// queue of requests awaiting responses; nothing above it does, which is why this is a stamp
    /// rather than something reconstructed here from what went past (see
    /// `PostgresCodecState::chunked_tail`).
    ///
    /// The entry is still in `pending` because entries are removed by `request_id`, which a partial
    /// does not have — only the tail ends up removing it.
    fn stamped_train_shape(&self, response: &Message) -> Option<Shape> {
        match self.pending.get(&partial_train_request_id(response)?) {
            Some(Awaiting::Execute(Some(statement))) => {
                self.statement_shapes.get(statement).copied()
            }
            // A simple query carries its own RowDescription in its first chunk, and a Describe train
            // is too small to chunk. Neither needs this, and neither should fabricate a shape.
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::CodecState;
    use crate::codec::postgres::PostgresCodecState;
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
            train_shape: None,
            poisoned: false,
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

    /// A partial chunk, exactly as the sink codec emits one: no request id, and stamped with the
    /// id of the request whose train it belongs to.
    fn partial_chunk(train: MessageId, messages: Vec<BackendMessage>) -> Message {
        let mut m = response(messages);
        m.codec_state = CodecState::Postgres(PostgresCodecState::partial_response(train));
        m
    }

    /// The message that completes a chunked train: carries the request id, marked as a tail.
    fn chunked_tail(id: MessageId, messages: Vec<BackendMessage>) -> Message {
        let mut m = response_for(id, messages);
        m.codec_state = CodecState::Postgres(PostgresCodecState::chunked_response_tail());
        m
    }

    fn row(id: &str, ssn: &str) -> BackendMessage {
        BackendMessage::DataRow {
            values: vec![
                Some(Bytes::copy_from_slice(id.as_bytes())),
                Some(Bytes::copy_from_slice(ssn.as_bytes())),
            ],
        }
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

    /// Streaming, simple query. Only the FIRST chunk can carry the RowDescription, so every later
    /// chunk depends on the shape surviving the boundary. Before this the second chunk had no shape
    /// and failed closed, which turned every large redacted read into an error.
    #[test]
    fn a_streamed_simple_query_redacts_every_chunk() {
        let mut r = redactor();
        let q = note(
            &mut r,
            FrontendMessage::Query {
                query: "SELECT id, ssn FROM t".to_owned(),
            },
        );

        let mut first = partial_chunk(
            q,
            vec![
                BackendMessage::RowDescription {
                    fields: vec![field("id"), field("ssn")],
                },
                row("1", "111-22-3333"),
            ],
        );
        assert!(redact(&mut r, &mut first).is_ok());
        assert_eq!(data_row_value(&mut first, 1, 1), b"[REDACTED]");

        // Rows alone, no RowDescription anywhere in this message.
        let mut middle = partial_chunk(q, vec![row("2", "222-33-4444")]);
        assert!(redact(&mut r, &mut middle).is_ok());
        assert_eq!(data_row_value(&mut middle, 0, 1), b"[REDACTED]");

        let mut tail = chunked_tail(
            q,
            vec![
                row("3", "333-44-5555"),
                BackendMessage::CommandComplete {
                    tag: "SELECT 3".to_owned(),
                },
                BackendMessage::ReadyForQuery { status: b'I' },
            ],
        );
        assert!(redact(&mut r, &mut tail).is_ok());
        assert_eq!(data_row_value(&mut tail, 0, 1), b"[REDACTED]");
        assert_eq!(
            data_row_value(&mut tail, 0, 0),
            b"3",
            "other columns untouched"
        );
        assert_eq!(r.train_shape, None, "the tail must close the train");
    }

    /// Streaming, extended protocol — the case that needs the decoder's stamp. A cached prepared
    /// statement re-executes with no Describe, so the RowDescription is long gone; the first chunk
    /// of the Execute train carries neither it nor a request id, and the only thing that says which
    /// statement is being answered is `train_request_id`.
    #[test]
    fn a_streamed_execute_resolves_its_shape_from_the_decoder_stamp() {
        let mut r = redactor();
        note(
            &mut r,
            FrontendMessage::Parse {
                statement_name: "s".to_owned(),
                query: "SELECT id, ssn FROM t".to_owned(),
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
                fields: vec![field("id"), field("ssn")],
            }],
        );
        assert!(redact(&mut r, &mut describe).is_ok());

        note(&mut r, bind("p", "s"));
        let e = note(
            &mut r,
            FrontendMessage::Execute {
                portal_name: "p".to_owned(),
                max_rows: 0,
            },
        );

        let mut first = partial_chunk(e, vec![row("1", "111-22-3333")]);
        assert!(
            redact(&mut r, &mut first).is_ok(),
            "the first chunk of an Execute train has no RowDescription and no request id; \
             without the decoder stamp it can only fail closed"
        );
        assert_eq!(data_row_value(&mut first, 0, 1), b"[REDACTED]");

        let mut middle = partial_chunk(e, vec![row("2", "222-33-4444")]);
        assert!(redact(&mut r, &mut middle).is_ok());
        assert_eq!(data_row_value(&mut middle, 0, 1), b"[REDACTED]");

        let mut tail = chunked_tail(
            e,
            vec![
                row("3", "333-44-5555"),
                BackendMessage::CommandComplete {
                    tag: "SELECT 3".to_owned(),
                },
            ],
        );
        assert!(redact(&mut r, &mut tail).is_ok());
        assert_eq!(data_row_value(&mut tail, 0, 1), b"[REDACTED]");
    }

    /// The stamp names a request whose shape is genuinely unknown, so the chunk still fails closed.
    /// Streaming widens what CAN be redacted; it must not widen what is GUESSED.
    #[test]
    fn a_streamed_chunk_with_no_resolvable_shape_still_fails_closed() {
        let mut r = redactor();
        // Executed without ever being described.
        note(&mut r, bind("p", "s"));
        let e = note(
            &mut r,
            FrontendMessage::Execute {
                portal_name: "p".to_owned(),
                max_rows: 0,
            },
        );
        let mut first = partial_chunk(e, vec![row("1", "111-22-3333")]);
        assert!(redact(&mut r, &mut first).is_err());
    }

    /// A chunk boundary that lands between two result sets of a multi-statement simple query: the
    /// shape carried forward is the RESET one, so the second statement's rows must wait for their
    /// own RowDescription rather than inherit the first statement's column index.
    #[test]
    fn a_chunk_boundary_between_result_sets_does_not_carry_the_old_shape() {
        let mut r = redactor();
        let q = note(
            &mut r,
            FrontendMessage::Query {
                query: "SELECT id, ssn FROM t; SELECT ssn, id FROM t".to_owned(),
            },
        );

        let mut first = partial_chunk(
            q,
            vec![
                BackendMessage::RowDescription {
                    fields: vec![field("id"), field("ssn")],
                },
                row("1", "111-22-3333"),
                BackendMessage::CommandComplete {
                    tag: "SELECT 1".to_owned(),
                },
            ],
        );
        assert!(redact(&mut r, &mut first).is_ok());
        assert_eq!(
            r.train_shape, None,
            "CommandComplete ends the result set, so no shape may cross the boundary"
        );

        // The second statement puts the redacted column FIRST. Inheriting index 1 would blank the
        // wrong column and leak the ssn.
        let mut second = partial_chunk(
            q,
            vec![
                BackendMessage::RowDescription {
                    fields: vec![field("ssn"), field("id")],
                },
                row("444-55-6666", "1"),
            ],
        );
        assert!(redact(&mut r, &mut second).is_ok());
        assert_eq!(data_row_value(&mut second, 1, 0), b"[REDACTED]");
        assert_eq!(data_row_value(&mut second, 1, 1), b"1");
    }

    /// COPY output cannot be redacted, and its first message opens the train — so the fail-close
    /// fires on the chunk that carries CopyOutResponse, before any CopyData is forwarded.
    #[test]
    fn a_streamed_copy_fails_closed_on_its_first_chunk() {
        let mut r = redactor();
        let q = note(
            &mut r,
            FrontendMessage::Query {
                query: "COPY (SELECT ssn FROM t) TO STDOUT".to_owned(),
            },
        );
        let mut first = partial_chunk(
            q,
            vec![BackendMessage::CopyOutResponse {
                overall_format: 0,
                column_formats: vec![0],
            }],
        );
        assert!(redact(&mut r, &mut first).is_err());
    }

    #[test]
    fn test_fail_closed_response_matches_ready_for_query_of_original() {
        let r = redactor();
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
    fn test_in_transaction_fail_close_omits_ready_for_query() {
        // A fail-close INSIDE a transaction closes the connection (the transform loop sets
        // close_client_connection so the server rolls back). Its replacement must NOT carry a
        // ReadyForQuery — the client receives the error and then the close, not "ready for the next
        // query". Outside a transaction the connection stays open and a simple-query fail-close keeps
        // its ReadyForQuery (idle 'I'); an extended Execute train never carries one.
        let mut r = redactor();
        let simple = || {
            response(vec![
                BackendMessage::DataRow { values: vec![] },
                BackendMessage::CommandComplete {
                    tag: "SELECT 1".to_owned(),
                },
                BackendMessage::ReadyForQuery { status: b'T' },
            ])
        };
        let extended = || {
            response(vec![BackendMessage::DataRow {
                values: vec![Some(Bytes::from_static(b"111-22-3333"))],
            }])
        };

        r.in_transaction = true;
        assert_eq!(trailing_rfq(&mut r.fail_closed_response(&mut simple(), "x")), None);
        assert_eq!(
            trailing_rfq(&mut r.fail_closed_response(&mut extended(), "x")),
            None
        );

        r.in_transaction = false;
        assert_eq!(
            trailing_rfq(&mut r.fail_closed_response(&mut simple(), "x")),
            Some(b'I')
        );
        assert_eq!(
            trailing_rfq(&mut r.fail_closed_response(&mut extended(), "x")),
            None
        );
    }

    #[test]
    fn test_observe_tracks_transaction_and_reclaims_portals() {
        // in_transaction (what decides whether a later fail-close closes the connection) follows the
        // server's ReadyForQuery; at transaction end ('I') the non-holdable portals are reclaimed.
        let mut r = redactor();
        r.portal_statements.insert("p".to_owned(), "s".to_owned());

        let mut in_txn = response(vec![BackendMessage::ReadyForQuery { status: b'T' }]);
        r.observe_transaction_state(&mut in_txn);
        assert!(r.in_transaction);
        assert!(!r.portal_statements.is_empty()); // portals survive inside a transaction

        let mut idle = response(vec![BackendMessage::ReadyForQuery { status: b'I' }]);
        r.observe_transaction_state(&mut idle);
        assert!(!r.in_transaction);
        assert!(r.portal_statements.is_empty()); // reclaimed at transaction end
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
