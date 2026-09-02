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
//! A write seen on the REQUEST stream evicts the cached reads it could have made stale, so a subsequent
//! read cannot be answered from a now-stale entry (`invalidate_on_write`, default on). The grammar
//! analysis names the write's target tables (`analyze_sql().writes`) and the cache keeps a reverse index
//! table -> cached keys; a write whose targets cannot be enumerated (a stored-procedure `CALL`, a `DO`
//! block, `COPY ... FROM`, or an unparseable statement — `opaque_write`) evicts the WHOLE cache. Table
//! names are matched by bare (schema-stripped, lowercased) name, so a write is over-eager across schemas
//! rather than ever missing an eviction.
//!
//! Three subtler write shapes are covered:
//!   - **A read that calls an unproven function is treated as a possible writer** (review F-INV-1). A
//!     `SELECT my_proc(...)` whose function is neither a known-pure builtin nor operator-listed in
//!     `pure_functions` might INSERT/UPDATE; caching it would silently lose the write on the next call,
//!     so such a read is never cached AND invalidates the whole cache. Known non-table side effects
//!     (nextval/advisory/set_config) are excluded from the evict-all so they do not gut the cache.
//!   - **Extended-protocol prepared writes invalidate at Execute, not Parse** (review F-INV-2). A driver
//!     Parses once and Bind/Executes many; each statement's effect is recorded at Parse (bounded,
//!     approximately-LRU so a hot statement survives cold churn — F-INV-8/Y9) and COPIED into the portal
//!     at Bind (so a `Close(S)` cannot orphan it — F-INV-7), then applied at every Execute. An Execute of
//!     an untracked portal evicts everything (counted).
//!   - **Transaction boundaries are tracked in BOTH protocols** (review F-INV-4/5). BEGIN/COMMIT/ROLLBACK
//!     are classified from the parse tree (`analyze_sql().txn`), so `BEGIN`/`COMMIT` sent as extended
//!     Parse/Bind/Execute — how pgjdbc/npgsql/pgx work — are seen, and `ROLLBACK TO SAVEPOINT` / SAVEPOINT
//!     / RELEASE are correctly NOT treated as transaction ends.
//!   - **Invalidation is deferred to the commit point** (review F-INV-3/6). A write's relations are
//!     accumulated and evicted at `COMMIT`/`END` inside an explicit transaction (discarded on `ROLLBACK`),
//!     or at the `Sync` that commits an implicit (un-BEGUN) extended transaction — never before the
//!     backend commits, so a concurrent read cannot cache a pre-commit value. A simple-protocol
//!     autocommit write, which commits immediately, still evicts at once.
//!
//! A race guard bounds the classic read-after-write window: a read whose response is produced but whose
//! request was issued at or before the most recent invalidation is NOT stored (it may pre-date the
//! write). Residuals remain, bounded by `ttl_ms` and documented rather than solved: a cached
//! `SELECT FROM a_view` is evicted by a write naming the view, but NOT by a write to the view's
//! underlying table, and likewise a cached read of a partitioned/inherited parent is not evicted by a
//! write to a child — the proxy has no catalog connection to resolve view/partition -> base tables
//! (`relkind`/`pg_inherits`). A trigger-driven write to another table is invisible to the analysis for
//! the same reason. `COMMIT PREPARED` on THIS proxy evicts everything (review Y7), but a two-phase txn
//! committed through a DIFFERENT proxy instance is not seen (no shared state). All deferred.
//!
//! WAL / LISTEN-NOTIFY sourced invalidation and extended-protocol read caching remain out of scope.
//!
//! ## Bounds and gates
//! - **Simple query only, for SERVING.** Extended-protocol (Parse/Bind/Execute) reads are never cached;
//!   extended-protocol WRITES still invalidate (see above).
//! - **Never inside a transaction.** Transaction boundaries are tracked from the REQUEST stream too, so
//!   a pipelined `[BEGIN, SELECT, COMMIT]` is not mistaken for idle (F7); a train is stored only if its
//!   trailing ReadyForQuery is idle ('I'), never 'T'.
//! - **Never an error.** A train containing an ErrorResponse is not cached, so a transient error is not
//!   replayed to other sessions (F8).
//! - **Bounded by BOTH `max_entries` AND `max_bytes`** (estimated payload), so a few large results
//!   cannot size the proxy's memory (F2). NOTE the proxy already buffers a whole response train in
//!   memory regardless of the cache (a separate architectural limit), so keep `max_bytes` modest.

use crate::frame::postgres::{
    BackendMessage, FrontendMessage, PostgresFrame, SqlAnalysis, TxnControl, analyze_sql,
    is_writing_function,
};
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

/// Built-in functions certified PURE — deterministic given their arguments and free of writes. A read
/// calling ONLY these (plus operator-listed `pure_functions`) can be cached; a read calling anything
/// else might be a `SELECT my_writing_proc()` (review F-INV-1: silent write loss when such a read is
/// cached), so it is refused and invalidates. Deliberately EXCLUDES now()/random()/nextval()/… — those
/// are non-deterministic or writing (also caught by `looks_volatile` / `is_writing_function`). Not
/// exhaustive: a missed builtin only costs a cache miss, and the operator can widen via `pure_functions`.
const PURE_BUILTINS: &[&str] = &[
    // Aggregates.
    "count", "sum", "avg", "min", "max", "array_agg", "string_agg", "bool_and", "bool_or", "every",
    "bit_and", "bit_or", "json_agg", "jsonb_agg", "json_object_agg", "jsonb_object_agg", "stddev",
    "stddev_pop", "stddev_samp", "variance", "var_pop", "var_samp", "corr", "covar_pop", "covar_samp",
    // Window functions.
    "row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile", "lag", "lead",
    "first_value", "last_value", "nth_value",
    // String.
    "lower", "upper", "initcap", "length", "char_length", "character_length", "octet_length", "bit_length",
    "substr", "substring", "left", "right", "trim", "btrim", "ltrim", "rtrim", "lpad", "rpad", "replace",
    "translate", "reverse", "repeat", "concat", "concat_ws", "format", "split_part", "starts_with",
    "strpos", "position", "to_hex", "md5", "sha256", "encode", "decode", "ascii", "chr", "quote_ident",
    "quote_literal", "quote_nullable", "regexp_replace", "regexp_match", "regexp_matches",
    "regexp_split_to_array", "regexp_split_to_table", "regexp_count", "regexp_instr", "regexp_substr",
    // Math.
    "abs", "ceil", "ceiling", "floor", "round", "trunc", "sign", "mod", "power", "pow", "sqrt", "cbrt",
    "exp", "ln", "log", "log10", "div", "gcd", "lcm", "degrees", "radians", "pi", "sin", "cos", "tan",
    "asin", "acos", "atan", "atan2", "sinh", "cosh", "tanh", "width_bucket", "factorial",
    // Conditionals / null handling.
    "coalesce", "nullif", "greatest", "least",
    // Type conversion / formatting (deterministic given input).
    "cast", "to_char", "to_number", "to_date", "to_timestamp", "age",
    // Date/time field extraction — pure given the argument (a volatile argument like now() is caught
    // separately by looks_volatile).
    "extract", "date_part", "date_trunc", "make_date", "make_time", "make_timestamp",
    "make_timestamptz", "make_interval", "justify_days", "justify_hours", "justify_interval",
    // JSON / JSONB.
    "to_json", "to_jsonb", "json_build_object", "jsonb_build_object", "json_build_array",
    "jsonb_build_array", "json_extract_path", "jsonb_extract_path", "json_extract_path_text",
    "jsonb_extract_path_text", "json_array_length", "jsonb_array_length", "json_typeof", "jsonb_typeof",
    "json_object_keys", "jsonb_object_keys", "row_to_json", "array_to_json", "jsonb_pretty",
    "jsonb_set", "jsonb_insert", "json_strip_nulls", "jsonb_strip_nulls",
    // Arrays.
    "array_length", "array_upper", "array_lower", "array_ndims", "cardinality", "array_append",
    "array_prepend", "array_cat", "array_remove", "array_replace", "array_position", "array_positions",
    "unnest", "array_to_string", "string_to_array", "generate_series", "generate_subscripts",
    "array_fill", "array_dims",
    // Full-text search (review X5).
    "to_tsvector", "to_tsquery", "plainto_tsquery", "phraseto_tsquery", "websearch_to_tsquery",
    "ts_rank", "ts_rank_cd", "ts_headline",
    // Set-returning / record JSON (review X5).
    "jsonb_array_elements", "jsonb_array_elements_text", "json_array_elements", "json_array_elements_text",
    "jsonb_each", "jsonb_each_text", "json_each", "json_each_text", "jsonb_path_query",
    "jsonb_path_query_first", "jsonb_path_exists", "jsonb_to_record", "jsonb_to_recordset",
    "json_to_record", "json_to_recordset", "jsonb_populate_record", "jsonb_populate_recordset",
    "json_populate_record", "json_populate_recordset", "jsonb_object",
    // Ordered-set aggregates and misc pure builtins (review X5).
    "percentile_cont", "percentile_disc", "mode", "date_bin", "timezone", "num_nonnulls", "num_nulls",
    "isfinite", "overlay", "convert_from", "convert_to", "version",
];

/// True if a called function is safe to treat as pure — a known-pure builtin or one the operator listed.
fn is_pure_function(name: &str, operator_listed: &std::collections::HashSet<String>) -> bool {
    PURE_BUILTINS.contains(&name) || operator_listed.contains(name)
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
    /// Extra function names (bare, case-insensitive) the operator certifies as PURE (no writes, no
    /// non-determinism). A read calling a function that is neither a known-pure builtin nor listed here
    /// is treated as a possible writer: it is not cached and it invalidates the whole cache. List your
    /// read-only stored functions here to let their SELECTs cache again. Default empty.
    #[serde(default)]
    pub pure_functions: Vec<String>,
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
            pure_functions: self
                .pure_functions
                .iter()
                .map(|f| f.rsplit('.').next().unwrap_or(f).to_ascii_lowercase())
                .collect(),
            cache: Arc::new(Mutex::new(CacheStore::default())),
            hits: counter!("shotover_postgres_read_cache_hits_count", "chain" => chain.clone(), "transform" => NAME),
            misses: counter!("shotover_postgres_read_cache_misses_count", "chain" => chain.clone(), "transform" => NAME),
            evictions: counter!("shotover_postgres_read_cache_evictions_count", "chain" => chain.clone(), "transform" => NAME),
            untracked_execute: counter!("shotover_postgres_read_cache_untracked_execute_count", "chain" => chain, "transform" => NAME),
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
    pure_functions: std::collections::HashSet<String>,
    cache: SharedCache,
    hits: Counter,
    misses: Counter,
    evictions: Counter,
    untracked_execute: Counter,
}

impl TransformBuilder for PostgresReadCacheBuilder {
    fn build(&self, _transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(PostgresReadCache {
            ttl: self.ttl,
            max_entries: self.max_entries,
            max_bytes: self.max_bytes,
            invalidate_on_write: self.invalidate_on_write,
            pure_functions: self.pure_functions.clone(),
            cache: self.cache.clone(),
            hits: self.hits.clone(),
            misses: self.misses.clone(),
            evictions: self.evictions.clone(),
            untracked_execute: self.untracked_execute.clone(),
            user: None,
            database: None,
            rendering_gucs: BTreeMap::new(),
            in_transaction: false,
            session_stateful: false,
            prepared: BoundedEffects::default(),
            portals: BoundedEffects::default(),
            txn_dirty: std::collections::HashSet::new(),
            txn_opaque: false,
        })
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_type_name(&self) -> &'static str {
        NAME
    }
}

/// The relations a write evicts, and whether it is opaque (evict everything). Recorded at Parse, applied
/// at Execute (review F-INV-2 — drivers Parse once and Bind/Execute many).
type PreparedWrite = (Vec<Relation>, bool);

/// What an extended-protocol statement (or the portal bound from it) does, recorded at Parse and applied
/// at Execute across the SAME transaction model as the simple protocol (review F-INV-4/5/6).
#[derive(Clone)]
enum StmtEffect {
    /// A pure read, a `SET`, or anything with no data write and no transaction effect.
    Neutral,
    /// A data write: the relations to evict, and whether it is opaque (evict everything).
    Write(Vec<Relation>, bool),
    /// Transaction control (BEGIN/COMMIT/…).
    Txn(TxnControl),
    /// A statement/portal that could not be classified — capacity-evicted, or a Bind we never saw the
    /// Parse for. Its Execute evicts everything (safe) and increments the untracked-execute counter.
    Unknown,
}

/// Upper bound on the per-connection Parse/Bind tracking maps (review F-INV-8 — raised from 1024 so a
/// driver's prepared-statement cache fits; pgjdbc defaults to 256).
const MAX_PREPARED: usize = 4096;

/// A bounded, approximately-LRU map of extended-protocol statement/portal effects, so a client that
/// Parses or Binds unbounded distinct names cannot grow it. Each entry carries a recency stamp bumped on
/// access (`get`); on overflow the LEAST-recently-used entry is dropped, NOT the oldest — a client that
/// keeps re-using a hot prepared statement while churning cold ones keeps the hot ones (review Y9). An
/// Execute that then finds nothing falls back to `StmtEffect::Unknown` (evict-all, counted).
#[derive(Default)]
struct BoundedEffects {
    map: HashMap<String, (StmtEffect, u64)>,
    clock: u64,
}

impl BoundedEffects {
    fn insert(&mut self, name: String, effect: StmtEffect) {
        self.clock += 1;
        if !self.map.contains_key(&name)
            && self.map.len() >= MAX_PREPARED
            && let Some(victim) = self
                .map
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(k, _)| k.clone())
        {
            self.map.remove(&victim);
        }
        self.map.insert(name, (effect, self.clock));
    }

    /// Returns the effect and marks it most-recently-used.
    fn get(&mut self, name: &str) -> Option<StmtEffect> {
        self.clock += 1;
        let now = self.clock;
        self.map.get_mut(name).map(|(effect, used)| {
            *used = now;
            effect.clone()
        })
    }

    fn remove(&mut self, name: &str) {
        self.map.remove(name);
    }
}

pub struct PostgresReadCache {
    ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    invalidate_on_write: bool,
    pure_functions: std::collections::HashSet<String>,
    cache: SharedCache,
    hits: Counter,
    misses: Counter,
    evictions: Counter,
    /// Executes that hit the evict-all fallback because their statement/portal was untracked (review
    /// F-INV-8 — makes the safe-but-blunt fallback visible to operators).
    untracked_execute: Counter,
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
    /// statement name -> its effect, recorded at Parse and applied at Execute (review F-INV-2/4).
    prepared: BoundedEffects,
    /// portal name -> the effect COPIED from its statement at Bind (review F-INV-7 — so a `Close(S)` of
    /// the statement cannot orphan a still-live portal into an evict-all).
    portals: BoundedEffects,
    /// Relations dirtied by writes inside the currently-open explicit transaction, plus whether any was
    /// opaque. Their invalidation is DEFERRED to COMMIT (review F-INV-3): evicting at the write request
    /// would let a concurrent read cache the not-yet-committed value; re-evicting at COMMIT closes the
    /// window to the backend's own commit latency. Cleared (discarded) on ROLLBACK. A set so a loop of
    /// writes to the same table cannot grow it.
    txn_dirty: std::collections::HashSet<Relation>,
    txn_opaque: bool,
}

/// What a request means to the cache, extracted so the request's frame borrow is released before the
/// request is mutated (replace_with_dummy).
enum Kind {
    Startup(Vec<(String, String)>),
    Query(String),
    Parse {
        statement_name: String,
        query: String,
    },
    Bind {
        portal_name: String,
        statement_name: String,
    },
    Execute(String),
    Close {
        kind: u8,
        name: String,
    },
    Sync,
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

        // Are we inside an EXPLICIT transaction (BEGIN…COMMIT)? Tracked across THIS batch from the
        // request stream, seeded from the session's last-seen ReadyForQuery, so a pipelined
        // [BEGIN, SELECT, COMMIT] is never treated as idle (review F7). Updated by transaction control
        // in BOTH the simple and extended protocols (review F-INV-4).
        let mut explicit_txn = self.in_transaction;
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
                    statement_name,
                    query,
                    ..
                }))) => Kind::Parse {
                    statement_name: statement_name.clone(),
                    query: query.clone(),
                },
                Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::Bind {
                    portal_name,
                    statement_name,
                    ..
                }))) => Kind::Bind {
                    portal_name: portal_name.clone(),
                    statement_name: statement_name.clone(),
                },
                Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::Execute {
                    portal_name,
                    ..
                }))) => Kind::Execute(portal_name.clone()),
                Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::Close {
                    kind,
                    name,
                }))) => Kind::Close {
                    kind: *kind,
                    name: name.clone(),
                },
                Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::Sync))) => Kind::Sync,
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
                Kind::Parse {
                    statement_name,
                    query,
                } => {
                    let analysis = analyze_sql(&query);
                    // A session-state statement issued via the EXTENDED protocol (how every major driver
                    // sends SET) must also turn the cache off; the simple-query latch alone missed it and
                    // leaked another session's search_path (review F1).
                    if analysis.pins_session {
                        self.session_stateful = true;
                    }
                    // Record the statement's effect (write / transaction control / neutral) so a LATER
                    // Execute — a driver reuses one Parse across many Bind/Execute — applies it (review
                    // F-INV-2/4).
                    if self.invalidate_on_write {
                        let effect = self.classify(&analysis);
                        self.prepared.insert(statement_name, effect);
                    }
                }
                Kind::Bind {
                    portal_name,
                    statement_name,
                } => {
                    // COPY the statement's effect into the portal, so a later Close(S) of the statement
                    // cannot orphan this portal into an evict-all (review F-INV-7).
                    if self.invalidate_on_write {
                        let effect = self
                            .prepared
                            .get(&statement_name)
                            .unwrap_or(StmtEffect::Unknown);
                        self.portals.insert(portal_name, effect);
                    }
                }
                Kind::Execute(portal_name) => {
                    // Apply the effect the portal was bound with (review F-INV-2/4/6). Extended writes
                    // are deferred to the implicit-transaction Sync or the explicit COMMIT.
                    if self.invalidate_on_write {
                        let effect = self.portals.get(&portal_name).unwrap_or(StmtEffect::Unknown);
                        self.apply_effect(&effect, &mut explicit_txn, true);
                    }
                }
                Kind::Close { kind, name } => match kind {
                    b'S' => self.prepared.remove(&name),
                    b'P' => self.portals.remove(&name),
                    _ => {}
                },
                Kind::Sync => {
                    // A Sync ends an IMPLICIT transaction (extended statements between Syncs commit here),
                    // so flush the deferred invalidation — but NOT while an explicit transaction is open,
                    // where only COMMIT commits (review F-INV-6).
                    if self.invalidate_on_write && !explicit_txn {
                        self.finish_transaction(true);
                    }
                }
                Kind::Query(query) => {
                    let analysis = analyze_sql(&query);
                    // A simple Query also ends any open implicit transaction, so flush its deferred
                    // writes before this statement (a no-op unless prior un-Synced extended writes are
                    // pending; review F-INV-6).
                    if self.invalidate_on_write && !explicit_txn {
                        self.finish_transaction(true);
                    }
                    // Apply this statement's effect. A simple Query string may contain BOTH a write and
                    // transaction control (`BEGIN; UPDATE t; COMMIT` in one PQexec), so apply the txn part
                    // first (BEGIN opens the txn / COMMIT flushes what precedes it) and then the write —
                    // never dropping one for the other. A simple-protocol autocommit write commits
                    // immediately (evict now); an in-explicit-txn write defers to COMMIT.
                    if self.invalidate_on_write {
                        if let Some(txn) = analysis.txn.clone() {
                            self.apply_txn_control(&txn, &mut explicit_txn);
                        }
                        if let Some(inv) = self.statement_invalidation(&analysis) {
                            self.note_write(inv, explicit_txn);
                        }
                    }
                    if analysis.pins_session {
                        // SET search_path/role, PREPARE, temp tables, …: turn the cache off for this
                        // connection so a state-dependent result is never served from a shared cache.
                        self.session_stateful = true;
                        continue;
                    }
                    if self.session_stateful
                        || explicit_txn
                        || !analysis.replica_safe
                        || looks_volatile(&query)
                        || self.read_calls_impure(&analysis)
                    {
                        // read_calls_impure: a SELECT of a function whose body we cannot see might write
                        // (review F-INV-1) — never serve it from, or store it in, the cache.
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

    /// True if a read calls a function the proxy cannot prove pure — any user function, which might
    /// write (review F-INV-1: caching `SELECT my_writing_proc()` silently loses the write). Such a read
    /// must be neither served from nor stored in the cache. Names the first offending function at debug
    /// level so an operator can decide whether to certify it via `pure_functions` (review X5).
    fn read_calls_impure(&self, analysis: &SqlAnalysis) -> bool {
        if let Some(name) = analysis
            .functions
            .iter()
            .find(|f| !is_pure_function(f, &self.pure_functions))
        {
            tracing::debug!(
                function = %name,
                "read not cached: function is not a known-pure builtin; add to pure_functions if it is read-only"
            );
            true
        } else {
            false
        }
    }

    /// The invalidation a statement performs: the relations to evict and whether it is opaque (evict
    /// everything). `None` if it writes nothing. A function whose body the proxy cannot see and that is
    /// not a known non-table side-effect (nextval/advisory/set_config — those dirty NO cached table, so
    /// excluding them keeps COMMIT/nextval from gutting the cache) makes the statement opaque.
    fn statement_invalidation(&self, analysis: &SqlAnalysis) -> Option<PreparedWrite> {
        let opaque_function = analysis
            .functions
            .iter()
            .any(|f| !is_pure_function(f, &self.pure_functions) && !is_writing_function(f));
        let opaque = analysis.opaque_write || opaque_function;
        if !opaque && analysis.writes.is_empty() {
            return None;
        }
        let database = self.database.clone().unwrap_or_default();
        let relations = analysis
            .writes
            .iter()
            .map(|table| (database.clone(), relation_name(table)))
            .collect();
        Some((relations, opaque))
    }

    /// Classify a statement into the effect the cache applies at its execution point.
    fn classify(&self, analysis: &SqlAnalysis) -> StmtEffect {
        if let Some(txn) = &analysis.txn {
            return StmtEffect::Txn(txn.clone());
        }
        match self.statement_invalidation(analysis) {
            Some((relations, opaque)) => StmtEffect::Write(relations, opaque),
            None => StmtEffect::Neutral,
        }
    }

    /// Apply a statement's effect at its execution point (a simple Query, or an extended Execute).
    /// `deferred` is true when a write must wait for a later commit point rather than evict now — always
    /// for the extended protocol (its implicit-transaction Sync), and for a simple Query only inside an
    /// explicit transaction (review F-INV-3/4/6). Transaction control updates `explicit_txn` for both
    /// protocols (review F-INV-4/5).
    fn apply_effect(&mut self, effect: &StmtEffect, explicit_txn: &mut bool, deferred: bool) {
        match effect {
            StmtEffect::Neutral => {}
            StmtEffect::Write(relations, opaque) => {
                self.note_write((relations.clone(), *opaque), *explicit_txn || deferred);
            }
            StmtEffect::Unknown => {
                self.untracked_execute.increment(1);
                self.note_write((Vec::new(), true), *explicit_txn || deferred);
            }
            StmtEffect::Txn(txn) => self.apply_txn_control(txn, explicit_txn),
        }
    }

    /// Apply a transaction-control statement's effect on the deferred set and the explicit-txn flag.
    fn apply_txn_control(&mut self, txn: &TxnControl, explicit_txn: &mut bool) {
        match txn {
            TxnControl::Begin => *explicit_txn = true,
            TxnControl::Commit { chain } => {
                self.finish_transaction(true);
                *explicit_txn = *chain;
            }
            TxnControl::Rollback { chain } => {
                self.finish_transaction(false);
                *explicit_txn = *chain;
            }
            TxnControl::CommitPrepared => {
                // Commits a two-phase txn that may have been PREPAREd on another connection; its writes
                // are unknown here, so evict everything (review Y7). It runs standalone, so evict now.
                self.evict(&[], true);
            }
            TxnControl::Nested => {}
        }
    }

    /// Apply a write's invalidation — immediately if autocommit, or DEFER it to a commit point (COMMIT,
    /// or the implicit-transaction Sync) since the write is not visible to other connections until then
    /// and evicting early would let a concurrent read cache the pre-commit value (review F-INV-3/6).
    fn note_write(&mut self, inv: PreparedWrite, defer: bool) {
        let (relations, opaque) = inv;
        if defer {
            if opaque {
                self.txn_opaque = true;
            }
            self.txn_dirty.extend(relations);
        } else {
            self.evict(&relations, opaque);
        }
    }

    /// At the end of an explicit transaction, apply the deferred invalidation (COMMIT/END) or discard it
    /// (ROLLBACK/ABORT), and reset the accumulator.
    fn finish_transaction(&mut self, committed: bool) {
        let relations: Vec<Relation> = self.txn_dirty.drain().collect();
        let opaque = std::mem::replace(&mut self.txn_opaque, false);
        if committed {
            self.evict(&relations, opaque);
        }
    }

    /// Evicts the cached reads a write makes stale: `opaque` drops the whole cache, otherwise each named
    /// relation is evicted. A no-op when invalidation is disabled or nothing matches.
    fn evict(&self, relations: &[Relation], opaque: bool) {
        if !self.invalidate_on_write || (!opaque && relations.is_empty()) {
            return;
        }
        let Ok(mut store) = self.cache.lock() else {
            return;
        };
        let now = Instant::now();
        let evicted = if opaque {
            store.evict_all(now)
        } else {
            let mut evicted = 0;
            for relation in relations {
                evicted += store.evict_relation(relation, now);
            }
            evicted
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
        BoundedEffects, CacheEntry, CacheStore, Frame, Message, PostgresFrame, PostgresReadCache,
        Relation, StmtEffect, is_pure_function, looks_volatile, relation_name, response_is_cacheable,
    };
    use crate::frame::postgres::{BackendMessage, analyze_sql};
    use std::collections::{BTreeMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// A cache instance with no-op counters and a fresh store, for exercising the per-connection write
    /// logic (classify / apply_effect / finish_transaction) directly.
    fn test_cache(pure_functions: &[&str]) -> PostgresReadCache {
        use metrics::counter;
        PostgresReadCache {
            ttl: Duration::from_secs(60),
            max_entries: 1024,
            max_bytes: 16 * 1024 * 1024,
            invalidate_on_write: true,
            pure_functions: pure_functions.iter().map(|f| f.to_string()).collect(),
            cache: Arc::new(Mutex::new(CacheStore::default())),
            hits: counter!("test_hits"),
            misses: counter!("test_misses"),
            evictions: counter!("test_evictions"),
            untracked_execute: counter!("test_untracked"),
            user: Some("u".to_owned()),
            database: Some("db".to_owned()),
            rendering_gucs: BTreeMap::new(),
            in_transaction: false,
            session_stateful: false,
            prepared: BoundedEffects::default(),
            portals: BoundedEffects::default(),
            txn_dirty: HashSet::new(),
            txn_opaque: false,
        }
    }

    /// Prime the cache with one entry depending on `relation`, then report whether it survives.
    fn prime(cache: &PostgresReadCache, key: super::CacheKey, relation: Relation) {
        let mut store = cache.cache.lock().unwrap();
        store.insert_entry(
            key,
            CacheEntry {
                expiry: Instant::now() + Duration::from_secs(60),
                response: response(vec![BackendMessage::ReadyForQuery { status: b'I' }]),
                size: 100,
                relations: vec![relation],
            },
        );
    }

    fn entries(cache: &PostgresReadCache) -> usize {
        cache.cache.lock().unwrap().entries.len()
    }

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
    fn transaction_control_classification() {
        use crate::frame::postgres::TxnControl;
        assert_eq!(analyze_sql("BEGIN").txn, Some(TxnControl::Begin));
        assert_eq!(analyze_sql("start transaction").txn, Some(TxnControl::Begin));
        assert_eq!(analyze_sql("COMMIT").txn, Some(TxnControl::Commit { chain: false }));
        assert_eq!(analyze_sql("END").txn, Some(TxnControl::Commit { chain: false }));
        assert_eq!(analyze_sql("ROLLBACK").txn, Some(TxnControl::Rollback { chain: false }));
        // The F-INV-5 hazard: ROLLBACK TO SAVEPOINT / SAVEPOINT / RELEASE do NOT end the transaction.
        assert_eq!(analyze_sql("ROLLBACK TO SAVEPOINT sp").txn, Some(TxnControl::Nested));
        assert_eq!(analyze_sql("SAVEPOINT sp").txn, Some(TxnControl::Nested));
        assert_eq!(analyze_sql("RELEASE SAVEPOINT sp").txn, Some(TxnControl::Nested));
        assert_eq!(analyze_sql("COMMIT AND CHAIN").txn, Some(TxnControl::Commit { chain: true }));
        // Y7: COMMIT PREPARED is distinct (evict-all); ROLLBACK PREPARED committed nothing (Nested).
        assert_eq!(analyze_sql("COMMIT PREPARED 'tx'").txn, Some(TxnControl::CommitPrepared));
        assert_eq!(analyze_sql("ROLLBACK PREPARED 'tx'").txn, Some(TxnControl::Nested));
        assert_eq!(analyze_sql("SELECT 1").txn, None);
        assert_eq!(analyze_sql("UPDATE t SET v=1").txn, None);
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

    #[test]
    fn pure_function_allowlist() {
        let pf: HashSet<String> = ["my_pure"].iter().map(|s| s.to_string()).collect();
        assert!(is_pure_function("count", &pf));
        assert!(is_pure_function("upper", &pf));
        assert!(is_pure_function("to_tsvector", &pf), "full-text builtin is pure (review X5)");
        assert!(is_pure_function("jsonb_array_elements", &pf), "set-returning JSON is pure (X5)");
        assert!(is_pure_function("my_pure", &pf), "operator-listed function is pure");
        assert!(!is_pure_function("log_ev", &pf), "unknown function is not pure");
        assert!(!is_pure_function("nextval", &pf), "writing builtin is not pure");
        assert!(!is_pure_function("current_setting", &pf), "session-dependent stays excluded (X5)");
    }

    #[test]
    fn writing_function_read_is_impure_and_opaque() {
        // F-INV-1: a SELECT calling an unproven function must not be cacheable, and must invalidate the
        // whole cache (it might write). A known non-table side effect (nextval) is impure-for-caching
        // but NOT opaque, so it never guts the cache.
        let cache = test_cache(&[]);
        let udf = analyze_sql("SELECT log_ev('x')");
        assert!(cache.read_calls_impure(&udf), "writing-UDF read is not cacheable");
        assert_eq!(cache.statement_invalidation(&udf), Some((Vec::new(), true)), "evicts all");

        let seq = analyze_sql("SELECT nextval('s')");
        assert!(cache.read_calls_impure(&seq), "nextval read is not cacheable");
        assert_eq!(cache.statement_invalidation(&seq), None, "nextval does not evict");

        let pure = analyze_sql("SELECT count(*), upper(name) FROM t");
        assert!(!cache.read_calls_impure(&pure), "a pure-builtin read stays cacheable");
        assert_eq!(cache.statement_invalidation(&pure), None);

        // The operator can certify a function pure to restore caching for its SELECTs.
        let listed = test_cache(&["log_ev"]);
        assert!(!listed.read_calls_impure(&udf));
        assert_eq!(listed.statement_invalidation(&udf), None);
    }

    /// Drive one extended-protocol statement through the Parse -> Bind -> Execute path the transform
    /// uses, so tests exercise the real recording/copying/apply flow (review F-INV-2/4/6/7).
    fn parse_bind_execute(
        cache: &mut PostgresReadCache,
        stmt: &str,
        portal: &str,
        sql: &str,
        explicit_txn: &mut bool,
    ) {
        let effect = cache.classify(&analyze_sql(sql));
        cache.prepared.insert(stmt.to_owned(), effect);
        let bound = cache.prepared.get(stmt).unwrap_or(StmtEffect::Unknown);
        cache.portals.insert(portal.to_owned(), bound);
        let effect = cache.portals.get(portal).unwrap_or(StmtEffect::Unknown);
        cache.apply_effect(&effect, explicit_txn, true);
    }

    #[test]
    fn named_prepared_write_invalidates_at_execute() {
        // F-INV-2: Parse records the write; the LATER Execute (reusing the statement) applies it.
        let mut cache = test_cache(&[]);
        prime(&cache, key("select v from t"), rel("t"));
        let mut explicit_txn = false;

        // Parse s_upd records; Bind copies; Execute defers (extended); the Sync commits the implicit
        // transaction and flushes the eviction.
        parse_bind_execute(&mut cache, "s_upd", "", "UPDATE t SET v=1 WHERE id=2", &mut explicit_txn);
        cache.finish_transaction(true); // Sync
        assert_eq!(entries(&cache), 0, "the prepared write evicts t at Sync");
    }

    #[test]
    fn close_statement_does_not_orphan_a_bound_portal() {
        // F-INV-7: Close(S) drops the statement, but the portal keeps its copied effect, so its Execute
        // applies the real write instead of falling back to evict-all.
        let mut cache = test_cache(&[]);
        prime(&cache, key("select a from other"), rel("other"));
        prime(&cache, key("select v from t"), rel("t"));
        let mut explicit_txn = false;

        // Parse s9 (a write to t); Bind p9<-s9; Close S s9; Execute p9.
        let s9 = cache.classify(&analyze_sql("UPDATE t SET v=1"));
        cache.prepared.insert("s9".to_owned(), s9);
        let bound = cache.prepared.get("s9").unwrap();
        cache.portals.insert("p9".to_owned(), bound);
        cache.prepared.remove("s9"); // Close(S)
        let effect = cache.portals.get("p9").unwrap_or(StmtEffect::Unknown);
        cache.apply_effect(&effect, &mut explicit_txn, true);
        cache.finish_transaction(true); // Sync

        assert!(entries(&cache) == 1, "only t evicted (targeted), not everything");
        assert!(
            cache.cache.lock().unwrap().entries.contains_key(&key("select a from other")),
            "the unrelated 'other' read survived — no evict-all orphan"
        );
    }

    #[test]
    fn extended_begin_commit_defers_then_flushes() {
        // F-INV-4: BEGIN/COMMIT via the extended protocol are tracked, so the in-txn write defers and
        // COMMIT flushes it. F-INV-6: an implicit (un-BEGUN) extended write flushes at Sync.
        let mut cache = test_cache(&[]);
        prime(&cache, key("select v from t"), rel("t"));
        let mut explicit_txn = false;

        parse_bind_execute(&mut cache, "s_begin", "", "BEGIN", &mut explicit_txn);
        assert!(explicit_txn, "extended BEGIN opened the transaction");
        parse_bind_execute(&mut cache, "s_upd", "", "UPDATE t SET v=1", &mut explicit_txn);
        assert_eq!(entries(&cache), 1, "in-txn write deferred, not evicted");
        parse_bind_execute(&mut cache, "s_commit", "", "COMMIT", &mut explicit_txn);
        assert!(!explicit_txn, "extended COMMIT left the transaction");
        assert_eq!(entries(&cache), 0, "COMMIT flushed the deferred eviction");

        // Implicit transaction: an extended write with no BEGIN defers to the Sync.
        prime(&cache, key("select v from t"), rel("t"));
        parse_bind_execute(&mut cache, "s_imp", "", "UPDATE t SET v=2", &mut explicit_txn);
        assert_eq!(entries(&cache), 1, "un-Synced extended write is not evicted yet (F-INV-6)");
        // The Sync arm: !explicit_txn -> flush the implicit transaction.
        cache.finish_transaction(true);
        assert_eq!(entries(&cache), 0, "Sync flushed the implicit-transaction write");
    }

    #[test]
    fn rollback_to_savepoint_keeps_the_deferred_set() {
        // F-INV-5: ROLLBACK TO SAVEPOINT must NOT be treated as a transaction end; the pre-savepoint
        // write stays deferred and is applied at the eventual COMMIT.
        let mut cache = test_cache(&[]);
        prime(&cache, key("select v from t"), rel("t"));
        let mut explicit_txn = true; // already inside BEGIN

        let upd = cache.classify(&analyze_sql("UPDATE t SET v=1"));
        cache.apply_effect(&upd, &mut explicit_txn, false);
        assert_eq!(cache.txn_dirty.len(), 1, "write deferred inside the txn");

        // ROLLBACK TO SAVEPOINT -> Nested -> no flush, no discard, txn stays open.
        let rb = cache.classify(&analyze_sql("ROLLBACK TO SAVEPOINT sp"));
        cache.apply_effect(&rb, &mut explicit_txn, false);
        assert!(explicit_txn, "still in the transaction");
        assert_eq!(cache.txn_dirty.len(), 1, "the deferred set was NOT discarded (F-INV-5)");

        let commit = cache.classify(&analyze_sql("COMMIT"));
        cache.apply_effect(&commit, &mut explicit_txn, false);
        assert_eq!(entries(&cache), 0, "COMMIT finally applies the eviction");
    }

    #[test]
    fn transaction_defers_invalidation_to_commit() {
        // F-INV-3: a write inside an explicit txn does not evict until COMMIT; ROLLBACK discards it.
        let mut cache = test_cache(&[]);
        prime(&cache, key("select v from t"), rel("t"));

        let inv = cache.statement_invalidation(&analyze_sql("UPDATE t SET v = 1")).unwrap();
        cache.note_write(inv, true); // deferred
        assert_eq!(entries(&cache), 1, "no eviction while the txn is open");
        assert_eq!(cache.txn_dirty.len(), 1, "the dirtied relation is remembered");

        cache.finish_transaction(true); // COMMIT
        assert_eq!(entries(&cache), 0, "COMMIT applies the deferred eviction");
        assert!(cache.txn_dirty.is_empty(), "accumulator reset");

        // ROLLBACK path: a deferred write is discarded, the cached read survives.
        prime(&cache, key("select v from t"), rel("t"));
        let inv = cache.statement_invalidation(&analyze_sql("UPDATE t SET v = 1")).unwrap();
        cache.note_write(inv, true);
        cache.finish_transaction(false); // ROLLBACK
        assert_eq!(entries(&cache), 1, "ROLLBACK discards the deferred eviction");
        assert!(cache.txn_dirty.is_empty());
    }

    #[test]
    fn multi_statement_simple_query_evicts_its_write() {
        // A single simple-Query string that both writes and commits (BEGIN; UPDATE; COMMIT in one
        // PQexec) must still evict the write — it was being dropped in favour of the txn effect.
        let mut cache = test_cache(&[]);
        prime(&cache, key("select v from t"), rel("t"));
        let mut explicit_txn = false;
        let analysis = analyze_sql("BEGIN; UPDATE t SET v=1; COMMIT");
        // Mirror the simple-Query arm: the txn part first, then the write part.
        if let Some(txn) = analysis.txn.clone() {
            cache.apply_txn_control(&txn, &mut explicit_txn);
        }
        if let Some(inv) = cache.statement_invalidation(&analysis) {
            cache.note_write(inv, explicit_txn);
        }
        assert_eq!(entries(&cache), 0, "the UPDATE inside the multi-statement string evicted t");
        assert!(!explicit_txn, "the string's COMMIT left the transaction");
    }

    #[test]
    fn commit_prepared_evicts_everything() {
        // Y7: COMMIT PREPARED commits a two-phase txn possibly PREPAREd on another connection, so its
        // writes are unknown here -> evict the whole cache (closes the same-proxy 2PC gap).
        let mut cache = test_cache(&[]);
        prime(&cache, key("read a"), rel("x"));
        prime(&cache, key("read b"), rel("y"));
        let mut explicit_txn = false;
        let cp = cache.classify(&analyze_sql("COMMIT PREPARED 'tx'"));
        cache.apply_effect(&cp, &mut explicit_txn, false);
        assert_eq!(entries(&cache), 0, "COMMIT PREPARED evicted everything");
    }

    #[test]
    fn bounded_effects_lru_keeps_the_hot_entry() {
        // Y9: a hot entry re-used while cold ones churn past the cap survives, because eviction is LRU
        // (least-recently-USED), not FIFO (oldest-inserted, which was exactly the hot one).
        use super::MAX_PREPARED;
        let mut b = BoundedEffects::default();
        b.insert("hot".to_owned(), StmtEffect::Neutral);
        for i in 0..(MAX_PREPARED + 100) {
            b.insert(format!("cold{i}"), StmtEffect::Neutral);
            assert!(b.get("hot").is_some(), "hot survives churn because each round re-uses it");
        }
    }
}
