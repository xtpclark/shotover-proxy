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
//! ## What it deliberately does NOT do — the SPIKE's findings
//! - **No write invalidation (the hard part).** A write to a table does NOT evict cached reads of that
//!   table. Staleness is bounded ONLY by `ttl_ms`. Coherent invalidation needs per-query table-
//!   dependency analysis plus write interception (or WAL/trigger/LISTEN-NOTIFY sourced invalidation),
//!   which is the real work and is deferred. This is why it is keyed by TTL, not correctness.
//! - **Session state.** The cache is keyed by user+database only, so it assumes DEFAULT session state.
//!   Any statement the analyzer flags as session-pinning (`SET search_path`, `SET role`, `PREPARE`,
//!   temp tables, …) turns the cache OFF for that connection (`session_stateful` latch), because a
//!   changed search_path/role would make a shared cached result wrong. A deployment that customises
//!   search_path per connection should not enable this cache.
//! - **Simple query only.** Extended-protocol (Parse/Bind/Execute) reads are never cached.
//! - **Reads inside a transaction are never cached** (the cached ReadyForQuery status would be wrong,
//!   and the read is not repeatable-read-isolated anyway).
//!
//! In short: this proves the mechanics (capture a response train, replay it to a later identical read,
//! bound it by TTL, gate it to safe queries) and isolates the one genuinely hard problem —
//! invalidation — as the next step.

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
}

fn default_max_entries() -> usize {
    1024
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
            cache: Arc::new(Mutex::new(HashMap::new())),
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

type SharedCache = Arc<Mutex<HashMap<CacheKey, (Instant, Message)>>>;

pub struct PostgresReadCacheBuilder {
    name: String,
    ttl: Duration,
    max_entries: usize,
    cache: SharedCache,
    hits: Counter,
    misses: Counter,
}

impl TransformBuilder for PostgresReadCacheBuilder {
    fn build(&self, _transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(PostgresReadCache {
            ttl: self.ttl,
            max_entries: self.max_entries,
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
                _ => Kind::Other,
            };
            match kind {
                Kind::Startup(parameters) => {
                    for (name, value) in parameters {
                        match name.as_str() {
                            "user" => self.user = Some(value),
                            "database" => self.database = Some(value),
                            _ => {}
                        }
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
                    if self.session_stateful
                        || self.in_transaction
                        || !analysis.replica_safe
                        || looks_volatile(&query)
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
                    // A cache miss just answered by the backend: remember its response train.
                    self.cache_put(key, response.clone());
                }
            }
        }
        Ok(responses)
    }
}

impl PostgresReadCache {
    fn cache_get(&self, key: &CacheKey) -> Option<Message> {
        let mut cache = self.cache.lock().ok()?;
        let expired = matches!(cache.get(key), Some((expiry, _)) if *expiry <= Instant::now());
        if expired {
            cache.remove(key);
            return None;
        }
        cache.get(key).map(|(_, response)| response.clone())
    }

    fn cache_put(&self, key: CacheKey, response: Message) {
        if let Ok(mut cache) = self.cache.lock() {
            let now = Instant::now();
            if cache.len() >= self.max_entries {
                cache.retain(|_, (expiry, _)| *expiry > now);
                if cache.len() >= self.max_entries {
                    return;
                }
            }
            cache.insert(key, (now + self.ttl, response));
        }
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
    use super::looks_volatile;

    #[test]
    fn volatile_reads_are_not_cacheable() {
        assert!(looks_volatile("SELECT now()"));
        assert!(looks_volatile("select RANDOM()"));
        assert!(looks_volatile("SELECT nextval('s')"));
        assert!(looks_volatile("SELECT current_user"));
        assert!(!looks_volatile("SELECT id, name FROM accounts WHERE id = 1"));
        assert!(!looks_volatile("SELECT count(*) FROM orders"));
    }
}
