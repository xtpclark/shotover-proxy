//! SPIKE — a TTL read-through result cache for the postgres simple-query protocol.
//!
//! This is an experimental exploration (feature `alpha-transforms`), not a production cache. It
//! serves the cached response for an identical, cacheable read within a TTL window instead of
//! forwarding it to the backend.
//!
//! ## What it does
//! For a client's simple `Query` that the grammar analysis proves is a pure, replica-safe read (no
//! writes, no session-state, no `FOR UPDATE`) AND that contains no obviously volatile construct
//! (`now()`, `random()`, `nextval`, `current_user`, …), it caches the WHOLE response train
//! (RowDescription + DataRows + CommandComplete + ReadyForQuery — the codec already bundles these into
//! one Message) keyed by `(database, user, query text)`. A later identical read from any connection is
//! answered from that cache — the backend is never contacted — until the entry's TTL elapses.
//!
//! ## UNSAFE for multi-tenant / untrusted / per-connection-search_path use
//! This is a convenience cache, NOT a correctness boundary. It is keyed by (database, user, query) and
//! assumes DEFAULT session state. It hardens against the state it CAN see — a session-pinning statement
//! via the simple OR extended protocol (`SET search_path`/`SET role`/PREPARE/temp tables) and a
//! state-affecting startup parameter (`options`/`search_path`/`role`/`session_authorization`) turn the
//! cache OFF for that connection — but it CANNOT see server-side per-role defaults (`ALTER ROLE … SET
//! search_path`). Do not enable it for untrusted clients or any deployment that relies on per-role or
//! otherwise-invisible search_path/role customisation: a cached result could then be served across
//! tenants. (Reviewer F1.)
//!
//! ## What it deliberately does NOT do — the SPIKE's finding
//! - **No write invalidation (the hard part).** A write to a table does NOT evict cached reads of that
//!   table. Staleness is bounded ONLY by `ttl_ms`. Coherent invalidation needs per-query table-
//!   dependency analysis plus write interception (or WAL/trigger/LISTEN-NOTIFY sourced invalidation),
//!   which is the real work and is deferred. This is why it is keyed by TTL, not correctness.
//!
//! ## Bounds and gates
//! - **Simple query only.** Extended-protocol (Parse/Bind/Execute) reads are never cached.
//! - **Never inside a transaction.** Transaction boundaries are tracked from the REQUEST stream too, so
//!   a pipelined `[BEGIN, SELECT, COMMIT]` is not mistaken for idle (F7); a train is stored only if its
//!   trailing ReadyForQuery is idle ('I'), never 'T'.
//! - **Never an error.** A train containing an ErrorResponse is not cached, so a transient error is not
//!   replayed to other sessions (F8).
//! - **Bounded by BOTH `max_entries` AND `max_bytes`** (estimated payload), so a few large results
//!   cannot size the proxy's memory (F2). NOTE the proxy already buffers a whole response train in
//!   memory regardless of the cache (a separate architectural limit), so keep `max_bytes` modest.

use crate::frame::postgres::{BackendMessage, FrontendMessage, PostgresFrame, analyze_sql};
use crate::frame::{Frame, MessageType};
use crate::message::{Message, MessageIdMap, Messages};
use crate::transforms::{
    ChainState, DownChainProtocol, Transform, TransformBuilder, TransformConfig,
    TransformContextBuilder, TransformContextConfig, UpChainProtocol,
};
use anyhow::Result;
use async_trait::async_trait;
use metrics::{Counter, counter};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// (database, user, query text) — the cache key. See the module doc for why identity is part of it.
type CacheKey = (String, String, String);

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PostgresReadCacheConfig {
    pub name: String,
    /// How long a cached read stays served before it is re-fetched. This is the ONLY bound on
    /// staleness (there is no write invalidation) — keep it short.
    pub ttl_ms: u64,
    /// Upper bound on cached entries; when full, expired entries are dropped and otherwise new
    /// entries are skipped rather than growing without bound.
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// Upper bound on TOTAL cached bytes (estimated from response payloads). Without it a few large
    /// result sets from an unprivileged client size the proxy's memory (review F2). Default 64 MiB.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

fn default_max_entries() -> usize {
    1024
}

fn default_max_bytes() -> usize {
    64 * 1024 * 1024
}

const NAME: &str = "PostgresReadCache";
#[typetag::serde(name = "PostgresReadCache")]
#[async_trait(?Send)]
impl TransformConfig for PostgresReadCacheConfig {
    fn get_name(&self) -> &str {
        &self.name
    }

    async fn get_builder(
        &self,
        transform_context: TransformContextConfig,
    ) -> Result<Box<dyn TransformBuilder>> {
        let chain = transform_context.chain_name;
        Ok(Box::new(PostgresReadCacheBuilder {
            name: self.name.clone(),
            ttl: Duration::from_millis(self.ttl_ms),
            max_entries: self.max_entries,
            max_bytes: self.max_bytes,
            cache: Arc::new(Mutex::new(CacheStore::default())),
            hits: counter!("shotover_postgres_read_cache_hits_count", "chain" => chain.clone(), "transform" => NAME),
            misses: counter!("shotover_postgres_read_cache_misses_count", "chain" => chain, "transform" => NAME),
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

struct CacheEntry {
    expiry: Instant,
    response: Message,
    size: usize,
}

/// The shared cache plus a running byte total, so the store can be bounded by bytes as well as entries.
#[derive(Default)]
struct CacheStore {
    entries: HashMap<CacheKey, CacheEntry>,
    total_bytes: usize,
}

type SharedCache = Arc<Mutex<CacheStore>>;

pub struct PostgresReadCacheBuilder {
    name: String,
    ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    cache: SharedCache,
    hits: Counter,
    misses: Counter,
}

impl TransformBuilder for PostgresReadCacheBuilder {
    fn build(&self, _transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(PostgresReadCache {
            ttl: self.ttl,
            max_entries: self.max_entries,
            max_bytes: self.max_bytes,
            cache: self.cache.clone(),
            hits: self.hits.clone(),
            misses: self.misses.clone(),
            user: None,
            database: None,
            in_transaction: false,
            session_stateful: false,
        })
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_type_name(&self) -> &'static str {
        NAME
    }
}

pub struct PostgresReadCache {
    ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    cache: SharedCache,
    hits: Counter,
    misses: Counter,
    // Per-connection state:
    user: Option<String>,
    database: Option<String>,
    in_transaction: bool,
    /// Latched true once this connection issues a session-pinning statement; the cache is then off for
    /// this connection (its query results may depend on search_path/role the shared cache cannot know).
    session_stateful: bool,
}

/// What a request means to the cache, extracted so the request's frame borrow is released before the
/// request is mutated (replace_with_dummy).
enum Kind {
    Startup(Vec<(String, String)>),
    Query(String),
    Parse(String),
    Other,
}

#[async_trait]
impl Transform for PostgresReadCache {
    fn get_name(&self) -> &'static str {
        NAME
    }

    async fn transform<'shorter, 'longer: 'shorter>(
        &mut self,
        chain_state: &'shorter mut ChainState<'longer>,
    ) -> Result<Messages> {
        let mut serve_from_cache: MessageIdMap<Message> = MessageIdMap::default();
        let mut cache_on_response: MessageIdMap<CacheKey> = MessageIdMap::default();

        // Transaction state tracked across THIS batch from the request stream, seeded from the
        // session's last-seen ReadyForQuery, so a pipelined [BEGIN, SELECT, COMMIT] is never treated as
        // idle (review F7).
        let mut in_txn = self.in_transaction;
        for request in &mut chain_state.requests {
            let rid = request.id();
            let kind = match request.frame() {
                Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::Startup {
                    parameters,
                    ..
                }))) => Kind::Startup(parameters.clone()),
                Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::Query { query }))) => {
                    Kind::Query(query.clone())
                }
                Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::Parse {
                    query, ..
                }))) => Kind::Parse(query.clone()),
                _ => Kind::Other,
            };
            match kind {
                Kind::Startup(parameters) => {
                    for (name, value) in parameters {
                        match name.as_str() {
                            "user" => self.user = Some(value),
                            "database" => self.database = Some(value),
                            // Any per-connection state customisation the cache key cannot capture turns
                            // the cache off for this session — a custom search_path/role would make a
                            // shared cached result wrong (review F1).
                            "options" | "search_path" | "role" | "session_authorization"
                                if !value.is_empty() =>
                            {
                                self.session_stateful = true;
                            }
                            _ => {}
                        }
                    }
                }
                Kind::Parse(query) => {
                    // A session-state statement issued via the EXTENDED protocol (how every major driver
                    // sends SET) must also turn the cache off; the simple-query latch alone missed it and
                    // leaked another session's search_path (review F1).
                    if analyze_sql(&query).pins_session {
                        self.session_stateful = true;
                    }
                }
                Kind::Query(query) => {
                    let analysis = analyze_sql(&query);
                    if analysis.pins_session {
                        // SET search_path/role, PREPARE, temp tables, …: turn the cache off for this
                        // connection so a state-dependent result is never served from a shared cache.
                        self.session_stateful = true;
                        continue;
                    }
                    if is_txn_begin(&query) {
                        in_txn = true;
                    } else if is_txn_end(&query) {
                        in_txn = false;
                    }
                    if self.session_stateful || in_txn || !analysis.replica_safe || looks_volatile(&query)
                    {
                        continue;
                    }
                    let (user, database) = match (&self.user, &self.database) {
                        (Some(u), Some(d)) => (u.clone(), d.clone()),
                        _ => continue,
                    };
                    let key = (database, user, query);
                    if let Some(mut response) = self.cache_get(&key) {
                        response.set_request_id(rid);
                        serve_from_cache.insert(rid, response);
                        request.replace_with_dummy();
                        self.hits.increment(1);
                    } else {
                        cache_on_response.insert(rid, key);
                        self.misses.increment(1);
                    }
                }
                Kind::Other => {}
            }
        }

        let mut responses = chain_state.call_next_transform().await?;

        for response in responses.iter_mut() {
            if let Some(status) = trailing_ready_status(response) {
                self.in_transaction = status != b'I';
            }
            if let Some(rid) = response.request_id() {
                if let Some(cached) = serve_from_cache.remove(&rid) {
                    // A cache hit: the dummy the sink produced for the suppressed request is replaced
                    // with the cached response train.
                    *response = cached;
                } else if let Some(key) = cache_on_response.remove(&rid) {
                    // A cache miss just answered by the backend: remember it ONLY if it is a clean,
                    // self-contained, idle result — no ErrorResponse (F8) and a trailing
                    // ReadyForQuery('I'), never an in-transaction train ending in 'T' (F7).
                    if response_is_cacheable(response) {
                        let size = estimate_response_size(response);
                        self.cache_put(key, response.clone(), size);
                    }
                }
            }
        }
        Ok(responses)
    }
}

impl PostgresReadCache {
    fn cache_get(&self, key: &CacheKey) -> Option<Message> {
        let mut store = self.cache.lock().ok()?;
        match store.entries.get(key) {
            Some(entry) if entry.expiry <= Instant::now() => {
                if let Some(removed) = store.entries.remove(key) {
                    store.total_bytes = store.total_bytes.saturating_sub(removed.size);
                }
                None
            }
            Some(entry) => Some(entry.response.clone()),
            None => None,
        }
    }

    fn cache_put(&self, key: CacheKey, response: Message, size: usize) {
        // Never cache an unmeasurable result, or one larger than the whole budget.
        if size == 0 || size > self.max_bytes {
            return;
        }
        if let Ok(mut store) = self.cache.lock() {
            let now = Instant::now();
            // Prune expired entries first, reclaiming their bytes.
            let mut freed = 0usize;
            store.entries.retain(|_, e| {
                if e.expiry > now {
                    true
                } else {
                    freed += e.size;
                    false
                }
            });
            store.total_bytes = store.total_bytes.saturating_sub(freed);
            // Replacing an existing key reclaims its bytes before we re-count.
            if let Some(old) = store.entries.remove(&key) {
                store.total_bytes = store.total_bytes.saturating_sub(old.size);
            }
            // Bounded by BOTH entries and bytes; when full, skip this entry rather than evict others.
            if store.entries.len() >= self.max_entries || store.total_bytes + size > self.max_bytes {
                return;
            }
            store.total_bytes += size;
            store.entries.insert(
                key,
                CacheEntry {
                    expiry: now + self.ttl,
                    response,
                    size,
                },
            );
        }
    }
}

/// True if a query begins a transaction.
fn is_txn_begin(query: &str) -> bool {
    let q = query.trim_start().to_ascii_lowercase();
    q.starts_with("begin") || q.starts_with("start transaction")
}

/// True if a query ends a transaction.
fn is_txn_end(query: &str) -> bool {
    let q = query.trim_start().to_ascii_lowercase();
    q.starts_with("commit") || q.starts_with("rollback") || q.starts_with("end") || q.starts_with("abort")
}

/// A response train may be cached only if it is a clean idle result: it contains NO ErrorResponse (a
/// cached error would be replayed to other sessions — F8) and its trailing ReadyForQuery reports idle
/// ('I'), never an in-transaction 'T'/'E' (F7).
fn response_is_cacheable(response: &mut Message) -> bool {
    if let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() {
        let mut trailing_idle = false;
        for message in messages.iter() {
            match message {
                BackendMessage::ErrorResponse { .. } => return false,
                BackendMessage::ReadyForQuery { status } => trailing_idle = *status == b'I',
                _ => {}
            }
        }
        trailing_idle
    } else {
        false
    }
}

/// Estimates a response train's payload size (dominated by DataRow values) for the byte bound.
fn estimate_response_size(response: &mut Message) -> usize {
    match response.frame() {
        Some(Frame::Postgres(PostgresFrame::Response(messages))) => {
            messages.iter().map(backend_message_size).sum()
        }
        _ => 0,
    }
}

fn backend_message_size(message: &BackendMessage) -> usize {
    match message {
        BackendMessage::DataRow { values } => {
            values
                .iter()
                .map(|v| v.as_ref().map_or(0, |b| b.len()) + 4)
                .sum::<usize>()
                + 8
        }
        // Rough fixed overhead for RowDescription / CommandComplete / ReadyForQuery / etc.
        _ => 64,
    }
}

/// A conservative denylist of tokens that make a read non-deterministic even at a single instant, so
/// its result must never be cached. Substring matching is intentionally over-broad (it will also skip
/// a column literally named `random_note`) — safe over sorry for a cache.
fn looks_volatile(query: &str) -> bool {
    const MARKERS: &[&str] = &[
        "now(",
        "current_timestamp",
        "current_time",
        "localtime",
        "clock_timestamp",
        "statement_timestamp",
        "transaction_timestamp",
        "random(",
        "nextval",
        "currval",
        "lastval",
        "uuid_generate",
        "gen_random",
        "current_user",
        "session_user",
        "current_role",
        "txid_",
        "pg_backend_pid",
        "inet_client",
        "inet_server",
        "pg_sleep",
    ];
    let lowered = query.to_ascii_lowercase();
    MARKERS.iter().any(|m| lowered.contains(m))
}

/// The status byte of the last ReadyForQuery in a response, if any.
fn trailing_ready_status(response: &mut Message) -> Option<u8> {
    if let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() {
        for message in messages.iter().rev() {
            if let BackendMessage::ReadyForQuery { status } = message {
                return Some(*status);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        Frame, Message, PostgresFrame, is_txn_begin, is_txn_end, looks_volatile, response_is_cacheable,
    };
    use crate::frame::postgres::BackendMessage;

    #[test]
    fn volatile_reads_are_not_cacheable() {
        assert!(looks_volatile("SELECT now()"));
        assert!(looks_volatile("select RANDOM()"));
        assert!(looks_volatile("SELECT nextval('s')"));
        assert!(looks_volatile("SELECT current_user"));
        assert!(!looks_volatile("SELECT id, name FROM accounts WHERE id = 1"));
        assert!(!looks_volatile("SELECT count(*) FROM orders"));
    }

    #[test]
    fn transaction_boundaries() {
        assert!(is_txn_begin("BEGIN"));
        assert!(is_txn_begin("  begin transaction"));
        assert!(is_txn_begin("START TRANSACTION"));
        assert!(!is_txn_begin("SELECT 1"));
        assert!(is_txn_end("COMMIT"));
        assert!(is_txn_end("rollback"));
        assert!(is_txn_end("END"));
        assert!(!is_txn_end("SELECT 1"));
    }

    fn response(messages: Vec<BackendMessage>) -> Message {
        Message::from_frame(Frame::Postgres(PostgresFrame::Response(messages)))
    }

    #[test]
    fn only_clean_idle_results_are_cacheable() {
        // A normal idle result (ends in ReadyForQuery('I')) is cacheable.
        let mut ok = response(vec![BackendMessage::ReadyForQuery { status: b'I' }]);
        assert!(response_is_cacheable(&mut ok));

        // A train ending inside a transaction ('T') is NOT cacheable (review F7).
        let mut in_txn = response(vec![BackendMessage::ReadyForQuery { status: b'T' }]);
        assert!(!response_is_cacheable(&mut in_txn));

        // A train containing an ErrorResponse is NOT cacheable (review F8).
        let mut err = response(vec![
            BackendMessage::ErrorResponse {
                fields: vec![(b'C', "42P01".to_owned())],
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ]);
        assert!(!response_is_cacheable(&mut err));
    }
}
