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
//! This is a convenience cache, NOT a correctness boundary. The key is (database, user, rendering
//! fingerprint, query), where the rendering fingerprint is the server-reported rendering GUCs
//! (client_encoding/DateStyle/TimeZone/IntervalStyle/…), so two clients with different timezone/
//! encoding/date formatting never share a result (F1c). It hardens against the rest of the state it CAN
//! see — a session-pinning statement via the simple OR extended protocol (`SET search_path`/`SET
//! role`/PREPARE/temp tables) and a state-affecting startup parameter (`options`/`search_path`/`role`/
//! `session_authorization`/`extra_float_digits`) turn the cache OFF for that connection. But it CANNOT
//! see what the server never reports: per-role search_path/role defaults (`ALTER ROLE … SET
//! search_path` — search_path is not a reported GUC). Do not enable it for untrusted clients or any
//! deployment that relies on per-role/otherwise-invisible search_path/role customisation: a cached
//! result could then be served across tenants. (Reviewer F1/F1c.)
//!
//! ## Write invalidation (best-effort, request-path)
//! A write seen on the REQUEST stream evicts the cached reads it could have made stale, BEFORE it is
//! forwarded, so a subsequent read cannot be answered from a now-stale entry (`invalidate_on_write`,
//! default on). The grammar analysis names the write's target tables (`analyze_sql().writes`) and the
//! cache keeps a reverse index table -> cached keys; a write whose targets cannot be enumerated (a
//! stored-procedure `CALL`, a `DO` block, `COPY ... FROM`, or an unparseable statement — `opaque_write`)
//! evicts the WHOLE cache. Writes arriving via the extended protocol (Parse) invalidate too, even though
//! extended-protocol READS are never cached. Table names are matched by bare (schema-stripped,
//! lowercased) name, so a write is over-eager across schemas rather than ever missing an eviction.
//!
//! A race guard bounds the classic read-after-write window: a read whose response is produced but whose
//! request was issued at or before the most recent invalidation is NOT stored (it may pre-date the
//! write). Two residuals remain, bounded by `ttl_ms` and documented rather than solved:
//!   1. **Eviction is at the write REQUEST, not its COMMIT.** A concurrent read issued *after* the write
//!      evicts but *before* the write commits can fetch and cache the pre-commit value.
//!   2. **Views are invalidated by their own name, not their base tables.** A cached `SELECT FROM a_view`
//!      is evicted by a write naming the view, but NOT by a write to the view's underlying table — the
//!      proxy has no catalog connection to resolve view -> base tables (`relkind`). Deferred.
//!
//! WAL / LISTEN-NOTIFY sourced invalidation and extended-protocol read caching remain out of scope.
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
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// (database, user, rendering fingerprint, query text) — the cache key. The rendering fingerprint is
/// the server-reported rendering GUCs (client_encoding/DateStyle/TimeZone/…) so two clients with
/// different timezone/encoding/date formatting never share a cached result (review F1c). See the
/// module doc for why identity is part of the key.
type CacheKey = (String, String, String, String);

/// (database, bare table name) — a relation a cached read depends on / a write targets. The name is
/// schema-stripped and lowercased so a write is over-eager across schemas rather than ever missing an
/// eviction; the database scopes it so a write in one database never evicts another's cached reads.
type Relation = (String, String);

/// The bare, lowercased table name pg_query reports, for reverse-index keying. Schema-stripped on
/// purpose: the proxy does not know the connection's search_path, so `public.t`, `t`, and `other.t` all
/// fold to `t` — a write to any of them evicts cached reads of all (safe over-eviction, never a miss).
fn relation_name(raw: &str) -> String {
    raw.rsplit('.').next().unwrap_or(raw).to_ascii_lowercase()
}

/// The reported GUCs that change how result VALUES render; two clients differing on any of these must
/// not share cached bytes. These are all in the postgres startup ParameterStatus set.
const RENDERING_GUCS: &[&str] = &[
    "client_encoding",
    "datestyle",
    "intervalstyle",
    "timezone",
    "integer_datetimes",
    "standard_conforming_strings",
];

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
    /// Evict cached reads of a table when a write to it is seen on the request stream (default true).
    /// Turning this OFF reverts to pure TTL staleness — only for a read-only replica the cache sits in
    /// front of, where no write can arrive on the same chain.
    #[serde(default = "default_invalidate_on_write")]
    pub invalidate_on_write: bool,
}

fn default_max_entries() -> usize {
    1024
}

fn default_invalidate_on_write() -> bool {
    true
}

fn default_max_bytes() -> usize {
    // Deliberately modest: the proxy already buffers each whole response train in memory (~several
    // times its wire size), so a large cache budget on top compounds that. 16 MiB is a sane start.
    16 * 1024 * 1024
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
            invalidate_on_write: self.invalidate_on_write,
            cache: Arc::new(Mutex::new(CacheStore::default())),
            hits: counter!("shotover_postgres_read_cache_hits_count", "chain" => chain.clone(), "transform" => NAME),
            misses: counter!("shotover_postgres_read_cache_misses_count", "chain" => chain.clone(), "transform" => NAME),
            evictions: counter!("shotover_postgres_read_cache_evictions_count", "chain" => chain, "transform" => NAME),
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
    /// The relations this cached read depends on, so the reverse index can be cleaned when the entry
    /// is removed for any reason (eviction, expiry, replacement).
    relations: Vec<Relation>,
}

/// The shared cache plus a running byte total, a reverse index (relation -> the cached keys that read
/// it) for write invalidation, and the instant of the most recent invalidation (the race guard).
#[derive(Default)]
struct CacheStore {
    entries: HashMap<CacheKey, CacheEntry>,
    total_bytes: usize,
    /// relation -> the set of cache keys whose read depends on it. Kept in lockstep with each entry's
    /// `relations`, so a write to a relation evicts exactly the reads that touched it.
    by_relation: HashMap<Relation, std::collections::HashSet<CacheKey>>,
    /// The instant of the most recent invalidation (a targeted or whole-cache eviction). A response
    /// whose request was issued at or before this must not be stored — it may pre-date the write.
    last_invalidation: Option<Instant>,
}

impl CacheStore {
    /// Inserts an entry and links it into the reverse index and byte total. The one path by which an
    /// entry ever enters `entries`, mirror of `remove_entry`, so `by_relation` and `total_bytes` stay
    /// in step. The caller has already enforced the size/count bounds.
    fn insert_entry(&mut self, key: CacheKey, entry: CacheEntry) {
        self.total_bytes += entry.size;
        for relation in &entry.relations {
            self.by_relation
                .entry(relation.clone())
                .or_default()
                .insert(key.clone());
        }
        self.entries.insert(key, entry);
    }

    /// Removes an entry and unlinks it from the reverse index and byte total. The one path by which an
    /// entry ever leaves `entries`, so `by_relation` and `total_bytes` can never drift.
    fn remove_entry(&mut self, key: &CacheKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.size);
            for relation in &entry.relations {
                if let Some(keys) = self.by_relation.get_mut(relation) {
                    keys.remove(key);
                    if keys.is_empty() {
                        self.by_relation.remove(relation);
                    }
                }
            }
        }
    }

    /// Evicts every cached read that depends on `relation`; returns how many entries were dropped.
    fn evict_relation(&mut self, relation: &Relation, now: Instant) -> u64 {
        self.last_invalidation = Some(now);
        let Some(keys) = self.by_relation.get(relation) else {
            return 0;
        };
        let keys: Vec<CacheKey> = keys.iter().cloned().collect();
        for key in &keys {
            self.remove_entry(key);
        }
        keys.len() as u64
    }

    /// Evicts the entire cache (a write whose targets could not be enumerated); returns how many
    /// entries were dropped.
    fn evict_all(&mut self, now: Instant) -> u64 {
        self.last_invalidation = Some(now);
        let dropped = self.entries.len() as u64;
        self.entries.clear();
        self.by_relation.clear();
        self.total_bytes = 0;
        dropped
    }
}

type SharedCache = Arc<Mutex<CacheStore>>;

pub struct PostgresReadCacheBuilder {
    name: String,
    ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    invalidate_on_write: bool,
    cache: SharedCache,
    hits: Counter,
    misses: Counter,
    evictions: Counter,
}

impl TransformBuilder for PostgresReadCacheBuilder {
    fn build(&self, _transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(PostgresReadCache {
            ttl: self.ttl,
            max_entries: self.max_entries,
            max_bytes: self.max_bytes,
            invalidate_on_write: self.invalidate_on_write,
            cache: self.cache.clone(),
            hits: self.hits.clone(),
            misses: self.misses.clone(),
            evictions: self.evictions.clone(),
            user: None,
            database: None,
            rendering_gucs: BTreeMap::new(),
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
    invalidate_on_write: bool,
    cache: SharedCache,
    hits: Counter,
    misses: Counter,
    evictions: Counter,
    // Per-connection state:
    user: Option<String>,
    database: Option<String>,
    /// The server-reported rendering GUCs (from startup ParameterStatus); part of the cache key so a
    /// result rendered under one timezone/encoding/date style is never served to a client using
    /// another (review F1c). Captured canonically from the server, so per-role defaults (ALTER ROLE …
    /// SET) that the client never sent are covered.
    rendering_gucs: BTreeMap<String, String>,
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
        // rid -> (key, relations the read depends on, instant the read was issued). The last two feed
        // the reverse index and the race guard when the response comes back.
        let mut cache_on_response: MessageIdMap<(CacheKey, Vec<Relation>, Instant)> =
            MessageIdMap::default();

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
                            // extra_float_digits changes float rendering but is NOT reported in
                            // ParameterStatus, so it cannot be keyed — latch off if the client sets it.
                            "options" | "search_path" | "role" | "session_authorization"
                            | "extra_float_digits"
                                if !value.is_empty() =>
                            {
                                self.session_stateful = true;
                            }
                            _ => {}
                        }
                    }
                }
                Kind::Parse(query) => {
                    let analysis = analyze_sql(&query);
                    // A session-state statement issued via the EXTENDED protocol (how every major driver
                    // sends SET) must also turn the cache off; the simple-query latch alone missed it and
                    // leaked another session's search_path (review F1).
                    if analysis.pins_session {
                        self.session_stateful = true;
                    }
                    // A WRITE via the extended protocol invalidates too, even though extended-protocol
                    // READS are never cached — a driver INSERTing via Parse/Bind/Execute must still evict
                    // the simple-query reads it made stale.
                    if self.invalidate_on_write {
                        self.apply_invalidation(&analysis);
                    }
                }
                Kind::Query(query) => {
                    let analysis = analyze_sql(&query);
                    // Evict what this statement makes stale BEFORE it is forwarded, so a later read in
                    // the same batch cannot be served a now-stale entry. A no-op for a pure read.
                    if self.invalidate_on_write {
                        self.apply_invalidation(&analysis);
                    }
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
                    let key = (
                        database.clone(),
                        user,
                        rendering_fingerprint(&self.rendering_gucs),
                        query,
                    );
                    if let Some(mut response) = self.cache_get(&key) {
                        response.set_request_id(rid);
                        serve_from_cache.insert(rid, response);
                        request.replace_with_dummy();
                        self.hits.increment(1);
                    } else {
                        // Remember what this read depends on (reverse index) and when it was issued
                        // (race guard), so a write racing it cannot leave a stale entry behind.
                        let relations: Vec<Relation> = analysis
                            .reads
                            .iter()
                            .map(|table| (database.clone(), relation_name(table)))
                            .collect();
                        cache_on_response.insert(rid, (key, relations, Instant::now()));
                        self.misses.increment(1);
                    }
                }
                Kind::Other => {}
            }
        }

        let mut responses = chain_state.call_next_transform().await?;

        for response in responses.iter_mut() {
            self.capture_rendering_gucs(response);
            if let Some(status) = trailing_ready_status(response) {
                self.in_transaction = status != b'I';
            }
            if let Some(rid) = response.request_id() {
                if let Some(cached) = serve_from_cache.remove(&rid) {
                    // A cache hit: the dummy the sink produced for the suppressed request is replaced
                    // with the cached response train.
                    *response = cached;
                } else if let Some((key, relations, issued_at)) = cache_on_response.remove(&rid) {
                    // A cache miss just answered by the backend: remember it ONLY if it is a clean,
                    // self-contained, idle result — no ErrorResponse (F8) and a trailing
                    // ReadyForQuery('I'), never an in-transaction train ending in 'T' (F7).
                    if response_is_cacheable(response) {
                        let size = estimate_response_size(response);
                        self.cache_put(key, response.clone(), size, relations, issued_at);
                    }
                }
            }
        }
        Ok(responses)
    }
}

impl PostgresReadCache {
    /// Records the server's rendering GUCs from a ParameterStatus (sent at startup, and on any change)
    /// so they can key the cache (review F1c).
    fn capture_rendering_gucs(&mut self, response: &mut Message) {
        if let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() {
            for message in messages.iter() {
                if let BackendMessage::ParameterStatus { name, value } = message {
                    let name = name.to_ascii_lowercase();
                    if RENDERING_GUCS.contains(&name.as_str()) {
                        self.rendering_gucs.insert(name, value.clone());
                    }
                }
            }
        }
    }

    /// Evicts the cached reads a write makes stale. `opaque_write` (a CALL/DO/COPY FROM/unparseable
    /// statement whose targets are unknown) drops the whole cache; otherwise each named target relation
    /// is evicted. A no-op for a pure read (empty `writes`, `opaque_write` false).
    fn apply_invalidation(&self, analysis: &crate::frame::postgres::SqlAnalysis) {
        if !analysis.opaque_write && analysis.writes.is_empty() {
            return;
        }
        let Ok(mut store) = self.cache.lock() else {
            return;
        };
        let now = Instant::now();
        // A write's database is this connection's; without it a relation cannot be keyed, so fall back
        // to dropping everything. In practice a write only arrives on a started connection.
        let evicted = match (analysis.opaque_write, &self.database) {
            (true, _) | (false, None) => store.evict_all(now),
            (false, Some(database)) => {
                let database = database.clone();
                let mut evicted = 0;
                for table in &analysis.writes {
                    evicted += store.evict_relation(&(database.clone(), relation_name(table)), now);
                }
                evicted
            }
        };
        if evicted > 0 {
            self.evictions.increment(evicted);
        }
    }

    fn cache_get(&self, key: &CacheKey) -> Option<Message> {
        let mut store = self.cache.lock().ok()?;
        match store.entries.get(key) {
            Some(entry) if entry.expiry <= Instant::now() => {
                store.remove_entry(key);
                None
            }
            Some(entry) => Some(entry.response.clone()),
            None => None,
        }
    }

    fn cache_put(
        &self,
        key: CacheKey,
        response: Message,
        size: usize,
        relations: Vec<Relation>,
        issued_at: Instant,
    ) {
        // Never cache an unmeasurable result, or one larger than the whole budget.
        if size == 0 || size > self.max_bytes {
            return;
        }
        if let Ok(mut store) = self.cache.lock() {
            // Race guard: if a write invalidated at or after this read was issued, the response may
            // pre-date the write — do not store it. Staleness then falls back to a fresh fetch.
            if store.last_invalidation.is_some_and(|t| issued_at <= t) {
                return;
            }
            let now = Instant::now();
            // Prune expired entries first (through remove_entry, so the reverse index stays in step).
            let expired: Vec<CacheKey> = store
                .entries
                .iter()
                .filter(|(_, e)| e.expiry <= now)
                .map(|(k, _)| k.clone())
                .collect();
            for key in &expired {
                store.remove_entry(key);
            }
            // Replacing an existing key reclaims its bytes and reverse-index links before we re-count.
            store.remove_entry(&key);
            // Bounded by BOTH entries and bytes; when full, skip this entry rather than evict others.
            if store.entries.len() >= self.max_entries || store.total_bytes + size > self.max_bytes {
                return;
            }
            store.insert_entry(
                key,
                CacheEntry {
                    expiry: now + self.ttl,
                    response,
                    size,
                    relations,
                },
            );
        }
    }
}

/// A stable string of the rendering GUCs (BTreeMap iterates sorted), used as part of the cache key.
fn rendering_fingerprint(gucs: &BTreeMap<String, String>) -> String {
    let mut fingerprint = String::new();
    for (name, value) in gucs {
        fingerprint.push_str(name);
        fingerprint.push('=');
        fingerprint.push_str(value);
        fingerprint.push(';');
    }
    fingerprint
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
        CacheEntry, CacheStore, Frame, Message, PostgresFrame, Relation, is_txn_begin, is_txn_end,
        looks_volatile, relation_name, response_is_cacheable,
    };
    use crate::frame::postgres::BackendMessage;
    use std::time::{Duration, Instant};

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

    fn key(query: &str) -> super::CacheKey {
        ("db".to_owned(), "u".to_owned(), String::new(), query.to_owned())
    }

    fn rel(name: &str) -> Relation {
        ("db".to_owned(), name.to_owned())
    }

    fn entry(size: usize, relations: Vec<Relation>) -> CacheEntry {
        CacheEntry {
            expiry: Instant::now() + Duration::from_secs(60),
            response: response(vec![BackendMessage::ReadyForQuery { status: b'I' }]),
            size,
            relations,
        }
    }

    #[test]
    fn relation_name_is_schema_stripped_and_lowercased() {
        assert_eq!(relation_name("orders"), "orders");
        assert_eq!(relation_name("public.orders"), "orders");
        assert_eq!(relation_name("Sales.Orders"), "orders");
    }

    #[test]
    fn evict_relation_drops_only_dependents_and_keeps_index_consistent() {
        let mut store = CacheStore::default();
        store.insert_entry(key("select from orders"), entry(100, vec![rel("orders")]));
        store.insert_entry(key("select from customers"), entry(200, vec![rel("customers")]));
        // A read joining both tables depends on both.
        store.insert_entry(
            key("select from orders join customers"),
            entry(50, vec![rel("orders"), rel("customers")]),
        );
        assert_eq!(store.entries.len(), 3);
        assert_eq!(store.total_bytes, 350);

        let now = Instant::now();
        let dropped = store.evict_relation(&rel("orders"), now);
        assert_eq!(dropped, 2, "both orders-dependent reads evicted");
        assert!(store.entries.contains_key(&key("select from customers")));
        assert!(!store.entries.contains_key(&key("select from orders")));
        assert_eq!(store.total_bytes, 200, "byte total tracks the survivors");
        // The reverse index no longer lists orders, and customers still lists only the survivor.
        assert!(!store.by_relation.contains_key(&rel("orders")));
        assert_eq!(store.by_relation.get(&rel("customers")).unwrap().len(), 1);
        assert_eq!(store.last_invalidation, Some(now));
    }

    #[test]
    fn evict_all_clears_everything() {
        let mut store = CacheStore::default();
        store.insert_entry(key("a"), entry(100, vec![rel("orders")]));
        store.insert_entry(key("b"), entry(100, vec![rel("customers")]));
        let now = Instant::now();
        let dropped = store.evict_all(now);
        assert_eq!(dropped, 2);
        assert!(store.entries.is_empty());
        assert!(store.by_relation.is_empty());
        assert_eq!(store.total_bytes, 0);
        assert_eq!(store.last_invalidation, Some(now));
    }

    #[test]
    fn remove_entry_unlinks_from_every_relation_bucket() {
        let mut store = CacheStore::default();
        store.insert_entry(key("j"), entry(10, vec![rel("orders"), rel("customers")]));
        store.remove_entry(&key("j"));
        assert!(store.entries.is_empty());
        assert!(store.by_relation.is_empty(), "no dangling reverse-index buckets");
        assert_eq!(store.total_bytes, 0);
    }
}
