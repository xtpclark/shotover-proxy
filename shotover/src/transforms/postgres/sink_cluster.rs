//! A read/write-splitting sink for PostgreSQL primary + read-replica topologies.
//!
//! Writes, DDL, transactions and session-state statements go to the primary; statements the
//! grammar analysis (see [`crate::frame::postgres::analyze_sql`]) proves to be pure reads go to a
//! read replica. Roles are discovered by probing each configured host with `pg_is_in_recovery()`,
//! exactly as the other cluster sinks discover topology by querying the server's own surfaces
//! rather than requiring anything installed in the server.
//!
//! ## Authentication model
//! The client authenticates against the primary by passthrough (the same 1:1 flow
//! `PostgresSinkSingle` uses), so no client-facing credential store is needed and client auth is
//! real. Replica connections cannot reuse that exchange (SCRAM is per-connection challenge/
//! response), so the proxy originates them itself using a backend password plus the `user`/`database`
//! it captured from the client's startup message — the standard pooler model. A replica connection
//! authenticates as the CLIENT's user; its password is looked up in `replica_users` (a pgbouncer-style
//! userlist: username -> cleartext backend password), falling back to the single configured `password`
//! for any user not in the list. Only `trust` and cleartext `password` backend auth are supported for
//! originated connections in this milestone; md5 and SCRAM origination are a follow-up.
//!
//! ## Consistency
//! A read routed to a replica may be stale by the replication lag. Reads issued after a write on
//! the same session are NOT automatically pinned to the primary, so a session that needs
//! read-your-writes should wrap the read in a transaction (transactions pin to the primary).

use crate::codec::{CodecBuilder, Direction, postgres::PostgresCodecBuilder};
use crate::connection::SinkConnection;
use crate::frame::postgres::{
    AuthenticationMessage, BackendMessage, FrontendMessage, PostgresFrame, analyze_sql,
};
use crate::frame::{Frame, MessageType};
use crate::message::{Message, MessageId, Messages};
use metrics::{Counter, counter};
use crate::tls::{TlsConnector, TlsConnectorConfig};
use crate::transforms::{
    ChainState, DownChainProtocol, Transform, TransformBuilder, TransformConfig,
    TransformContextBuilder, TransformContextConfig, UpChainProtocol,
};
use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};

/// The cancel key a client holds = the PRIMARY's BackendKeyData, passed through untouched at startup.
type CancelKey = (i32, Bytes);

/// Where to re-issue a cancel for a session that ran reads on a replica: the replica's own address
/// and its own BackendKeyData (the client never saw the replica's key, so the proxy must supply it).
#[derive(Clone)]
struct ReplicaCancelTarget {
    addr: String,
    process_id: i32,
    secret_key: Bytes,
}

/// Upper bound on how long the proxy waits for a backend to answer during topology probing and
/// replica authentication. Without it, a backend that accepts the TCP connection but never replies
/// would block a client connection (and, during probing, every client connection) indefinitely.
const BACKEND_OP_TIMEOUT: Duration = Duration::from_secs(10);

/// The protocol version literal for protocol 3.0 (major 3 in the high 16 bits).
const PROTOCOL_VERSION_3_0: i32 = 196608;

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PostgresSinkClusterConfig {
    pub name: String,
    /// Candidate backend hosts (`host:port`). Each is probed with `pg_is_in_recovery()` to decide
    /// which is the primary and which are read replicas.
    pub first_contact_points: Vec<String>,
    /// The user used to probe topology, and the default user/password for originating replica
    /// connections for any client user not present in `replica_users`.
    pub username: String,
    /// The backend password used to probe topology and as the fallback for replica origination.
    pub password: String,
    /// Optional pgbouncer-style userlist: client username -> cleartext backend password used to
    /// originate that user's replica connections (B1). The proxy never sees the client's own password
    /// (the client authenticates to the primary by passthrough, often via SCRAM), so a replica
    /// connection for user X authenticates with `replica_users[X]`; a user absent from the map falls
    /// back to the single `password`. Empty (the default) means every user uses the shared password.
    #[serde(default)]
    pub replica_users: HashMap<String, String>,
    /// The database used only for topology probing (`pg_is_in_recovery()` works in any database).
    #[serde(default = "default_probe_database")]
    pub probe_database: String,
    pub connect_timeout_ms: u64,
    /// Optional per-node idle read timeout: the longest shotover waits for the NEXT chunk of a
    /// backend's response before giving up on that connection. It resets whenever data arrives, so a
    /// large legitimately-streaming result is never cut off — only a backend that stalls without
    /// producing anything trips it. Unset (the default) waits forever, preserving prior behaviour.
    #[serde(default)]
    pub read_timeout_ms: Option<u64>,
    /// Replica addresses to PREFER when routing reads (B2, locality). A read picks a healthy
    /// preferred replica first, then any other healthy replica, then the primary. Entries should be a
    /// subset of `first_contact_points`; an entry that is not currently a replica simply never
    /// matches. Empty (the default) treats every replica equally.
    #[serde(default)]
    pub preferred_replicas: Vec<String>,
    /// How long a replica that fails to connect or authenticate is skipped before being retried (B3,
    /// health-aware selection). This is what stops a dead replica from costing a full connect_timeout
    /// on every single read: once it fails, reads route to a healthy replica (or the primary) until
    /// the cooldown elapses, then it gets one half-open retry. Default 5000ms.
    #[serde(default = "default_replica_health_cooldown_ms")]
    pub replica_health_cooldown_ms: u64,
    pub tls: Option<TlsConnectorConfig>,
}

fn default_probe_database() -> String {
    "postgres".to_owned()
}

fn default_replica_health_cooldown_ms() -> u64 {
    5000
}

const NAME: &str = "PostgresSinkCluster";
#[typetag::serde(name = "PostgresSinkCluster")]
#[async_trait(?Send)]
impl TransformConfig for PostgresSinkClusterConfig {
    fn get_name(&self) -> &str {
        &self.name
    }

    async fn get_builder(
        &self,
        transform_context: TransformContextConfig,
    ) -> Result<Box<dyn TransformBuilder>> {
        if self.first_contact_points.is_empty() {
            bail!("PostgresSinkCluster requires at least one first_contact_point");
        }
        let tls = self.tls.as_ref().map(TlsConnector::new).transpose()?;
        // Read/write-split observability: one handle per event, cloned into every per-connection
        // transform so a running split is measurable (offloaded reads, silent fallback, stalls).
        let chain_name = transform_context.chain_name;
        let reads_to_replica = counter!("shotover_postgres_reads_to_replica_count", "chain" => chain_name.clone(), "transform" => NAME);
        let replica_fallback = counter!("shotover_postgres_replica_fallback_count", "chain" => chain_name.clone(), "transform" => NAME);
        let backend_read_timeout = counter!("shotover_postgres_backend_read_timeout_count", "chain" => chain_name.clone(), "transform" => NAME);
        let primary_reprobe = counter!("shotover_postgres_primary_reprobe_count", "chain" => chain_name.clone(), "transform" => NAME);
        let replica_unhealthy = counter!("shotover_postgres_replica_unhealthy_count", "chain" => chain_name, "transform" => NAME);
        Ok(Box::new(PostgresSinkClusterBuilder {
            name: self.name.clone(),
            contact_points: self.first_contact_points.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            probe_database: self.probe_database.clone(),
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            read_timeout: self.read_timeout_ms.map(Duration::from_millis),
            preferred_replicas: self.preferred_replicas.clone(),
            replica_health_cooldown: Duration::from_millis(self.replica_health_cooldown_ms),
            replica_users: Arc::new(self.replica_users.clone()),
            reads_to_replica,
            replica_fallback,
            backend_read_timeout,
            primary_reprobe,
            replica_unhealthy,
            tls,
            topology: Arc::new(Mutex::new(TopologyState::default())),
            probe_lock: Arc::new(Mutex::new(())),
            round_robin: Arc::new(AtomicUsize::new(0)),
            replica_health: Arc::new(Mutex::new(HashMap::new())),
            cancel_registry: Arc::new(StdMutex::new(HashMap::new())),
        }))
    }

    fn up_chain_protocol(&self) -> UpChainProtocol {
        UpChainProtocol::MustBeOneOf(vec![MessageType::Postgres])
    }

    fn down_chain_protocol(&self) -> DownChainProtocol {
        DownChainProtocol::Terminating
    }

    fn get_sub_chain_configs(&self) -> Vec<(&crate::config::chain::TransformChainConfig, String)> {
        vec![]
    }
}

/// The discovered roles of the backend hosts. Probed once and shared across all client connections,
/// then RE-PROBED whenever the recorded primary turns out to be unreachable — see
/// `invalidate_topology`. That is the failover story: a broken primary link (crash or a failover that
/// promoted a replica) discards this cache so the next connection re-discovers the current primary,
/// instead of pinning a dead host until the process restarts. Mid-session failover is NOT transparent
/// (a client's open transaction / prepared statements / SET state cannot be moved to a new primary —
/// PostgreSQL itself does not do this): the affected connection is closed with an error and the client
/// reconnects onto the freshly-probed primary.
#[derive(Clone, Debug)]
struct Topology {
    primary: String,
    replicas: Vec<String>,
}

/// The shared topology plus a generation counter. `generation` increments on every successful probe,
/// so a session can remember which generation it routed against and refuse to invalidate a topology
/// that has since been re-probed by someone else — the guard that stops a slow/concurrent failure from
/// clearing fresh state or triggering a re-probe storm (review F4).
#[derive(Default)]
struct TopologyState {
    topology: Option<Topology>,
    generation: u64,
    /// The last primary this cluster selected, PRESERVED across invalidation. On a re-probe that finds
    /// more than one writable host (an un-fenced old primary that came back), the previously-selected
    /// primary is preferred so writes are never silently flipped to a returning stale node (review F5).
    last_primary: Option<String>,
}

pub struct PostgresSinkClusterBuilder {
    name: String,
    contact_points: Vec<String>,
    username: String,
    password: String,
    probe_database: String,
    connect_timeout: Duration,
    read_timeout: Option<Duration>,
    preferred_replicas: Vec<String>,
    replica_health_cooldown: Duration,
    tls: Option<TlsConnector>,
    topology: Arc<Mutex<TopologyState>>,
    /// Single-flight guard: a burst of connections that all find the topology absent runs ONE probe,
    /// held OUTSIDE the topology lock so the (potentially slow) probe never blocks a session that
    /// already has a topology.
    probe_lock: Arc<Mutex<()>>,
    /// pgbouncer-style userlist for replica origination (client username -> cleartext password).
    replica_users: Arc<HashMap<String, String>>,
    /// Rotates replica selection across client connections. Shared so it actually advances between
    /// connections (each connection builds its own Transform).
    round_robin: Arc<AtomicUsize>,
    /// Shared replica-health map: address -> instant until which the replica is skipped after a
    /// connect/auth failure. Shared so a dead replica found by one connection is skipped by all.
    replica_health: Arc<Mutex<HashMap<String, Instant>>>,
    reads_to_replica: Counter,
    replica_fallback: Counter,
    backend_read_timeout: Counter,
    primary_reprobe: Counter,
    replica_unhealthy: Counter,
    /// Shared cancel registry: a client's key (the primary's) -> the replica key to re-cancel with.
    cancel_registry: Arc<StdMutex<HashMap<CancelKey, ReplicaCancelTarget>>>,
}

impl TransformBuilder for PostgresSinkClusterBuilder {
    fn build(&self, transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(PostgresSinkCluster {
            contact_points: self.contact_points.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            probe_database: self.probe_database.clone(),
            connect_timeout: self.connect_timeout,
            read_timeout: self.read_timeout,
            preferred_replicas: self.preferred_replicas.clone(),
            replica_health_cooldown: self.replica_health_cooldown,
            replica_users: self.replica_users.clone(),
            tls: self.tls.clone(),
            topology: self.topology.clone(),
            probe_lock: self.probe_lock.clone(),
            primary_generation: 0,
            connected_primary: None,
            round_robin: self.round_robin.clone(),
            replica_health: self.replica_health.clone(),
            reads_to_replica: self.reads_to_replica.clone(),
            replica_fallback: self.replica_fallback.clone(),
            backend_read_timeout: self.backend_read_timeout.clone(),
            primary_reprobe: self.primary_reprobe.clone(),
            replica_unhealthy: self.replica_unhealthy.clone(),
            cancel_registry: self.cancel_registry.clone(),
            client_cancel_key: None,
            force_run_chain: transform_context.force_run_chain,
            primary: None,
            replica: None,
            replica_addr: None,
            replica_auth_failed: false,
            startup_complete: false,
            client_user: None,
            client_database: None,
            in_transaction: false,
            session_pinned: false,
            unit_target: None,
            outstanding_primary: 0,
            outstanding_replica: 0,
        })
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_type_name(&self) -> &'static str {
        NAME
    }

    fn is_terminating(&self) -> bool {
        true
    }
}

/// Which backend the current in-flight request unit is routed to.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Target {
    Primary,
    Replica,
}

pub struct PostgresSinkCluster {
    contact_points: Vec<String>,
    username: String,
    password: String,
    probe_database: String,
    connect_timeout: Duration,
    read_timeout: Option<Duration>,
    preferred_replicas: Vec<String>,
    replica_health_cooldown: Duration,
    tls: Option<TlsConnector>,
    topology: Arc<Mutex<TopologyState>>,
    /// Single-flight guard for re-probing (see the builder field).
    probe_lock: Arc<Mutex<()>>,
    /// The topology generation the current `primary` connection was opened against. A failure only
    /// invalidates the topology this session actually connected to — never one another session has
    /// since re-probed (review F4; keyed to CONNECT, not reads, so a fresh topology is not cleared).
    primary_generation: u64,
    /// The address the current `primary` connection was opened to. A session is evicted as stale ONLY
    /// when the topology's primary address CHANGES — a re-probe that lands on the same primary must
    /// leave healthy links alone (review F6 re-verify: keying eviction on generation mass-disconnected
    /// every session after any re-probe, even one that kept the same primary).
    connected_primary: Option<String>,
    /// pgbouncer-style userlist for replica origination (client username -> cleartext password).
    replica_users: Arc<HashMap<String, String>>,
    round_robin: Arc<AtomicUsize>,
    /// Shared replica-health map: address -> instant until which the replica is skipped after a
    /// connect/auth failure (see [`Self::select_replica_addr`]).
    replica_health: Arc<Mutex<HashMap<String, Instant>>>,
    force_run_chain: Arc<Notify>,

    /// Client-auth passthrough connection to the primary.
    primary: Option<SinkConnection>,
    /// Proxy-originated connection to one replica.
    replica: Option<SinkConnection>,
    replica_addr: Option<String>,
    /// Latched once this session's user fails to authenticate to a replica (a per-user credential
    /// problem). While set, this session routes reads to the primary and never retries the replica —
    /// so one bad `replica_users` entry costs only that user, never cools the shared host (review F6).
    replica_auth_failed: bool,

    /// True once the client has finished authenticating against the primary.
    startup_complete: bool,
    /// The user/database captured from the client's StartupMessage, reused to originate replicas.
    client_user: Option<String>,
    client_database: Option<String>,

    /// Whether the session is currently inside a transaction (from the last ReadyForQuery status).
    in_transaction: bool,
    /// Once the session issues session-state (SET / named prepare / LISTEN / DECLARE / temp table),
    /// every subsequent request pins to the primary so that state is visible.
    session_pinned: bool,
    /// The backend the current request unit is pinned to until a ReadyForQuery 'I' ends the unit.
    /// Keeps a split extended-query pipeline (Parse in one batch, Execute in the next) on one node.
    unit_target: Option<Target>,
    /// Per-node counts of requests still awaiting a response (see [`super::exchange`]). Tracked
    /// separately because each backend has its own independent pipeline.
    outstanding_primary: usize,
    outstanding_replica: usize,

    /// Read/write-split + failover counters (shared handles cloned from the builder).
    reads_to_replica: Counter,
    replica_fallback: Counter,
    backend_read_timeout: Counter,
    primary_reprobe: Counter,
    replica_unhealthy: Counter,

    /// Shared cancel registry (see [`ReplicaCancelTarget`]): the client's key (the primary's) -> the
    /// replica's own key, so a CancelRequest arriving on its own connection can be re-issued to the
    /// replica that is actually running the read.
    cancel_registry: Arc<StdMutex<HashMap<CancelKey, ReplicaCancelTarget>>>,
    /// This session's client-facing cancel key (the primary's BackendKeyData), captured at startup.
    /// Used as the registry key and removed from the registry on drop.
    client_cancel_key: Option<CancelKey>,
}

#[async_trait]
impl Transform for PostgresSinkCluster {
    fn get_name(&self) -> &'static str {
        NAME
    }

    async fn transform<'shorter, 'longer: 'shorter>(
        &mut self,
        chain_state: &'shorter mut ChainState<'longer>,
    ) -> Result<Messages> {
        if let Err(err) = self.ensure_topology().await {
            return map_startup_error(err, chain_state);
        }
        // A CancelRequest arrives on its own dedicated connection ahead of any startup, so it must be
        // routed to the backend running the query rather than run through startup/auth.
        if requests_contain_cancel(&mut chain_state.requests) {
            return self.handle_cancel(chain_state).await;
        }
        // If a failover changed the primary to a DIFFERENT host since this session opened its link,
        // that link is to a since-replaced node. Surface a clean error and close so the client
        // reconnects onto the current primary. Keyed on the primary ADDRESS, not the generation: a
        // re-probe that lands on the SAME primary (e.g. after a single pg_terminate_backend) leaves
        // healthy links untouched (review F6 re-verify — generation-keying mass-disconnected sessions).
        if self.startup_complete && self.primary.is_some() {
            let current_primary =
                { self.topology.lock().await.topology.as_ref().map(|t| t.primary.clone()) };
            if let Some(current_primary) = current_primary
                && self.connected_primary.as_deref() != Some(current_primary.as_str())
            {
                self.primary = None;
                self.connected_primary = None;
                self.outstanding_primary = 0;
                self.unit_target = None;
                chain_state.close_client_connection = true;
                let first_id = chain_state.requests.first_mut().map(|r| r.id());
                return Ok(vec![backend_link_lost_response(first_id)]);
            }
        }
        if let Err(err) = self.ensure_primary().await {
            return map_startup_error(err, chain_state);
        }

        if !self.startup_complete {
            return self.run_startup(chain_state).await;
        }

        if chain_state.requests.is_empty() {
            // Drain any unrequested async messages from whichever connections exist.
            let mut responses = vec![];
            if let Some(primary) = self.primary.as_mut() {
                let _ = primary.try_recv_into(&mut responses);
            }
            if let Some(replica) = self.replica.as_mut() {
                let _ = replica.try_recv_into(&mut responses);
            }
            return Ok(responses);
        }

        let target = self.decide_target(&mut chain_state.requests);
        let mut requests = std::mem::take(&mut chain_state.requests);
        let first_id = requests.first_mut().map(|r| r.id());
        match self.route(target, requests).await {
            Ok(responses) => Ok(responses),
            Err(err) if err.downcast_ref::<super::BackendReadTimeout>().is_some() => {
                // route() already dropped the stalled backend connection. Tell the client and close
                // so it never hangs on a response the backend will not produce.
                chain_state.close_client_connection = true;
                Ok(vec![backend_read_timeout_response(first_id)])
            }
            Err(err) => {
                // Any other route error is a broken backend link (a crash or a failover mid-batch).
                // Surface a clean FATAL 08006 and close instead of the generic "internal shotover bug"
                // text a bare Err produces (review F4/F10 family).
                tracing::warn!("postgres cluster: backend link lost: {err}");
                chain_state.close_client_connection = true;
                Ok(vec![backend_link_lost_response(first_id)])
            }
        }
    }
}

impl PostgresSinkCluster {
    /// Chooses where an incoming request batch goes.
    ///
    /// Session-state classification runs on EVERY batch, before the unit/transaction short-circuit,
    /// so a `SET` (or temp table, cursor, named prepare) issued inside a transaction still pins the
    /// session once the transaction ends. Routing itself preserves an in-progress unit's node and
    /// only re-decides at a unit boundary (session idle, no open transaction).
    fn decide_target(&mut self, requests: &mut [Message]) -> Target {
        let mut has_deciding_read = false;
        let mut has_primary_only = false;
        for request in requests.iter_mut() {
            match classify_request(request) {
                RequestRoute::ReplicaRead => has_deciding_read = true,
                RequestRoute::Neutral => {}
                RequestRoute::PinPrimary => {
                    // A lasting session-state change: pin the whole session to the primary. This
                    // must happen even mid-transaction, hence it runs before the returns below.
                    if !self.session_pinned {
                        tracing::debug!(
                            "postgres cluster: session pinned to primary by session-state statement"
                        );
                    }
                    self.session_pinned = true;
                    has_primary_only = true;
                }
                RequestRoute::Primary => has_primary_only = true,
            }
        }
        // A batch may open a replica unit ONLY if its LAST request is a Sync or a simple Query — a
        // flush point that yields a ReadyForQuery, which closes the unit within this exchange() call so
        // it never spans batches. Two shapes must NOT open one; both leave the unit open and strand the
        // next batch on the replica (the finding-2 hazard):
        //   * a trailing partial pipeline, e.g. [Parse, Bind, Describe, Execute, Sync, Parse] — the
        //     Parse after the Sync is buffered, so the last request is not a terminator;
        //   * a Flush (or CopyDone/CopyFail) terminator, e.g. [Parse, Bind, Describe, Execute, Flush] —
        //     a flush point, but it yields NO ReadyForQuery, so note_unit_boundary never closes the
        //     unit. (trailing_unanswerable == Some(0) alone admitted this, because request_triggers_flush
        //     counts Flush — a regression that spanned a replica unit into the next write.)
        let self_terminating = ends_with_sync_or_query(requests);

        // A pinned session runs on the primary. Because a replica unit never spans batches (only
        // self-terminating batches go to the replica), there is never an outstanding replica unit to
        // strand here — the override is safe and just keeps a pinned session on the primary.
        if self.session_pinned {
            self.unit_target = Some(Target::Primary);
            return Target::Primary;
        }
        if let Some(target) = self.unit_target {
            return target;
        }
        if self.in_transaction {
            return Target::Primary;
        }
        if has_deciding_read && !has_primary_only && self_terminating && self.replica_available() {
            Target::Replica
        } else {
            Target::Primary
        }
    }

    /// Sends a batch to the chosen backend, collects its responses, and updates unit/transaction
    /// state from the trailing ReadyForQuery.
    async fn route(&mut self, target: Target, mut requests: Messages) -> Result<Messages> {
        // A batch of only suppressed (dummy) requests produces dummy responses without touching a
        // backend, so it must not overwrite the session's unit_target — otherwise a throttle/cache hit
        // would pin every following read to the primary, since a dummy response carries no
        // ReadyForQuery to close the unit (F11).
        let is_dummy_only = requests
            .iter_mut()
            .all(|r| matches!(r.frame(), Some(Frame::Dummy)));
        let target = if target == Target::Replica {
            match self.ensure_replica().await {
                Ok(()) => {
                    self.reads_to_replica.increment(1);
                    Target::Replica
                }
                Err(err) => {
                    // No replica reachable: reads fall back to the primary, but say so — a silent
                    // fallback that also costs a full connect timeout per read is exactly the
                    // "splitting quietly stopped and everything is slow" failure to avoid. The
                    // counter makes that fallback visible even when nobody is watching the log.
                    self.replica_fallback.increment(1);
                    tracing::warn!(
                        "postgres cluster: replica unavailable, routing read to primary: {err}"
                    );
                    Target::Primary
                }
            }
        } else {
            target
        };
        // A dummy-only batch keeps whatever unit is open (or none) and rides the existing connection;
        // only a batch with a real request pins the unit.
        let target = if is_dummy_only {
            self.unit_target.unwrap_or(target)
        } else {
            self.unit_target = Some(target);
            target
        };

        // Send to the chosen node, tracking that node's outstanding responses. Extended-query
        // batches that carry no Flush/Sync produce no responses yet; super::exchange handles that
        // without blocking, so a split pipeline cannot deadlock the connection.
        let mut responses = match target {
            Target::Primary => {
                match super::exchange(
                    self.primary.as_mut().unwrap(),
                    requests,
                    &mut self.outstanding_primary,
                    self.read_timeout,
                )
                .await
                {
                    Ok(responses) => responses,
                    Err(err) => {
                        // Classify before reacting (review F4). A read timeout means the primary was
                        // SLOW, not dead — the connection is desynced so drop it, but do NOT invalidate
                        // shared topology (that would make one slow query re-probe for every session).
                        // Only a transport error means the primary is gone.
                        let is_timeout = err.downcast_ref::<super::BackendReadTimeout>().is_some();
                        if is_timeout {
                            self.backend_read_timeout.increment(1);
                        }
                        self.primary = None;
                        self.outstanding_primary = 0;
                        self.unit_target = None;
                        // A closed socket does not by itself mean the primary is dead (a single
                        // pg_terminate_backend, an idle-txn timeout, or one crashed backend). Only
                        // invalidate when the cached primary really is gone or demoted, so a single
                        // terminated backend does not re-probe and evict every other session (review F6
                        // re-verify).
                        if !is_timeout && !self.cached_primary_is_still_primary().await {
                            self.invalidate_topology().await;
                        }
                        return Err(err);
                    }
                }
            }
            Target::Replica => {
                match super::exchange(
                    self.replica.as_mut().unwrap(),
                    requests,
                    &mut self.outstanding_replica,
                    self.read_timeout,
                )
                .await
                {
                    Ok(responses) => responses,
                    Err(err) => {
                        // Classify before reacting (review F4). A read timeout means the replica was
                        // SLOW, not unhealthy — drop the desynced connection but do NOT cool the host
                        // (that would push every user off it for one slow read). Only a transport error
                        // cools it down and forces reselection.
                        let is_timeout = err.downcast_ref::<super::BackendReadTimeout>().is_some();
                        if is_timeout {
                            self.backend_read_timeout.increment(1);
                        }
                        self.replica = None;
                        self.outstanding_replica = 0;
                        self.unit_target = None;
                        if !is_timeout {
                            if let Some(addr) = self.replica_addr.clone() {
                                self.mark_replica_unhealthy(&addr).await;
                            }
                            self.replica_addr = None;
                        }
                        return Err(err);
                    }
                }
            }
        };
        self.note_unit_boundary(&mut responses);
        Ok(responses)
    }

    /// Updates transaction/unit state from the trailing ReadyForQuery of a response batch.
    fn note_unit_boundary(&mut self, responses: &mut [Message]) {
        for response in responses.iter_mut() {
            if let Some(status) = trailing_ready_status(response) {
                // A ReadyForQuery ends the current unit and reports transaction state.
                self.in_transaction = status != b'I';
                if status == b'I' {
                    self.unit_target = None;
                }
            }
        }
    }

    /// Routes the client's startup and authentication exchange to the primary by passthrough,
    /// capturing the user/database for later replica origination.
    async fn run_startup(&mut self, chain_state: &mut ChainState<'_>) -> Result<Messages> {
        for request in chain_state.requests.iter_mut() {
            if let Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::Startup {
                parameters,
                ..
            }))) = request.frame()
            {
                for (name, value) in parameters.iter() {
                    match name.as_str() {
                        "user" => self.client_user = Some(value.clone()),
                        "database" => self.client_database = Some(value.clone()),
                        _ => {}
                    }
                }
            }
        }

        let requests = std::mem::take(&mut chain_state.requests);
        let mut responses = match super::exchange(
            self.primary.as_mut().unwrap(),
            requests,
            &mut self.outstanding_primary,
            self.read_timeout,
        )
        .await
        {
            Ok(responses) => responses,
            Err(err) => {
                // A backend that breaks during the client's own startup gets a clean FATAL. Only a
                // transport error (not a read timeout, which just means slow) invalidates the shared
                // topology so the next connection re-probes for a new primary (review F4).
                self.primary = None;
                self.outstanding_primary = 0;
                if err.downcast_ref::<super::BackendReadTimeout>().is_none()
                    && !self.cached_primary_is_still_primary().await
                {
                    self.invalidate_topology().await;
                }
                return map_startup_error(err, chain_state);
            }
        };
        // Capture the primary's BackendKeyData as it passes through to the client: it IS the key the
        // client will present in a CancelRequest, so it is this session's client-facing cancel key and
        // the registry key used to route a cancel to the replica running the read.
        for response in responses.iter_mut() {
            if let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() {
                for message in messages.iter() {
                    if let BackendMessage::BackendKeyData {
                        process_id,
                        secret_key,
                    } = message
                    {
                        self.client_cancel_key = Some((*process_id, secret_key.clone()));
                    }
                }
            }
        }
        for response in responses.iter_mut() {
            if let Some(status) = trailing_ready_status(response) {
                // The first ReadyForQuery means authentication succeeded and the session is live.
                self.startup_complete = true;
                self.in_transaction = status != b'I';
            }
        }
        Ok(responses)
    }

    fn replica_available(&self) -> bool {
        !self.replica_auth_failed && (self.replica.is_some() || self.replica_addr.is_some())
    }

    /// Ensures a topology is known, probing if not. The probe is SINGLE-FLIGHT (a burst of connections
    /// runs one probe) and runs OUTSIDE the topology lock, so a session that already has a topology is
    /// never blocked by an unrelated re-probe — the shared lock is only held for the brief read/store,
    /// never across the (possibly slow) probe of every contact point (review F4).
    async fn ensure_topology(&mut self) -> Result<()> {
        // Fast path: a topology is already known.
        if let Some(topology) = self.current_topology().await {
            self.select_replica_addr(&topology).await;
            return Ok(());
        }
        // Slow path: cold start or just-invalidated. Serialize probers so only one runs. Lock a clone
        // of the Arc, not self.probe_lock, so holding the guard does not borrow self (we still need
        // &mut self below).
        let probe_lock = self.probe_lock.clone();
        let _probe_guard = probe_lock.lock().await;
        // Another prober may have finished while we waited for the guard.
        if let Some(topology) = self.current_topology().await {
            self.select_replica_addr(&topology).await;
            return Ok(());
        }
        let last_primary = { self.topology.lock().await.last_primary.clone() };
        let probed = self.probe_topology(last_primary.as_deref()).await?;
        tracing::info!(
            "postgres cluster topology: primary={} replicas={:?}",
            probed.primary,
            probed.replicas
        );
        {
            let mut state = self.topology.lock().await;
            state.last_primary = Some(probed.primary.clone());
            state.topology = Some(probed.clone());
            state.generation += 1;
        }
        self.select_replica_addr(&probed).await;
        Ok(())
    }

    /// Returns the current topology if known. Does NOT touch `primary_generation` — that is keyed to
    /// when this session CONNECTED its primary (see `connect_primary`), not to when it last read the
    /// topology, or a session that reads a freshly re-probed topology and then fails on its OLD primary
    /// link would wrongly clear the fresh one (review F4 re-verify).
    async fn current_topology(&self) -> Option<Topology> {
        self.topology.lock().await.topology.clone()
    }

    /// Chooses which replica this connection reads from, honouring health (B3) and locality (B2):
    /// a replica in cooldown after a recent failure is skipped; among the healthy ones a preferred
    /// replica wins, otherwise any healthy replica, round-robined. Leaves `replica_addr` None when
    /// every replica is in cooldown so reads fall back to the primary rather than stalling.
    async fn select_replica_addr(&mut self, topology: &Topology) {
        if self.replica_addr.is_some() || topology.replicas.is_empty() {
            return;
        }
        let healthy: Vec<String> = {
            let now = Instant::now();
            let mut guard = self.replica_health.lock().await;
            // Expired cooldowns make a replica eligible again (a half-open retry).
            guard.retain(|_, until| *until > now);
            topology
                .replicas
                .iter()
                .filter(|r| !guard.contains_key(*r))
                .cloned()
                .collect()
        };
        if healthy.is_empty() {
            return;
        }
        // Locality: prefer a healthy replica the operator declared preferred; else any healthy one.
        let mut preferred: Vec<String> = Vec::new();
        for r in &healthy {
            if self.preferred_replicas.contains(r) {
                preferred.push(r.clone());
            }
        }
        let pool = if preferred.is_empty() { healthy } else { preferred };
        // Shared counter so replica choice actually advances across client connections.
        let index = self.round_robin.fetch_add(1, Ordering::Relaxed) % pool.len();
        self.replica_addr = Some(pool[index].clone());
    }

    async fn mark_replica_unhealthy(&self, addr: &str) {
        self.replica_unhealthy.increment(1);
        let until = Instant::now() + self.replica_health_cooldown;
        self.replica_health
            .lock()
            .await
            .insert(addr.to_owned(), until);
    }

    async fn mark_replica_healthy(&self, addr: &str) {
        self.replica_health.lock().await.remove(addr);
    }

    /// Connects to each contact point, runs `pg_is_in_recovery()`, and classifies primary vs replica.
    async fn probe_topology(&self, last_primary: Option<&str>) -> Result<Topology> {
        let mut primaries = vec![];
        let mut replicas = vec![];
        // Hosts that are ALIVE but rejected the probe (auth rotated, hba, starting up, too many conns,
        // md5/SCRAM). A last-known primary that lands here must NOT be demoted (review F6 re-verify #2).
        let mut rejected_alive = vec![];
        // If a contact point requires md5/SCRAM (which the cluster sink cannot originate), keep that so
        // a "no primary" outcome surfaces it to the client instead of a bare "no primary found".
        let mut auth_unsupported = false;
        for host in &self.contact_points {
            match self.probe_host(host).await {
                HostProbe::Replica => replicas.push(host.clone()),
                HostProbe::Primary => primaries.push(host.clone()),
                HostProbe::ReachableButRejected {
                    message,
                    auth_unsupported: unsupported,
                } => {
                    tracing::warn!(
                        "postgres cluster: probe of {host} rejected but host is alive: {message}"
                    );
                    auth_unsupported |= unsupported;
                    rejected_alive.push(host.clone());
                }
                HostProbe::Unreachable(err) => {
                    tracing::warn!("postgres cluster: probe of {host} failed: {err}");
                }
            }
        }
        match self
            .choose_primary(&primaries, &replicas, &rejected_alive, last_primary)
            .await
        {
            Some(primary) => Ok(Topology { primary, replicas }),
            None if auth_unsupported => Err(BackendAuthUnsupported.into()),
            None => {
                tracing::warn!(
                    "postgres cluster: no primary found among {:?}",
                    self.contact_points
                );
                Err(NoPrimaryAvailable.into())
            }
        }
    }

    /// Fencing (review F5): never let contact-point ORDER decide the primary when more than one host
    /// reports itself writable — that is an un-fenced old primary that came back, a split brain.
    /// Preference order: keep the primary we were already using (do not flip writes to a returning
    /// stale node), then the host the replicas actually stream from (the true current primary), then —
    /// only if still ambiguous — the first, logged at ERROR.
    async fn choose_primary(
        &self,
        primaries: &[String],
        replicas: &[String],
        rejected_alive: &[String],
        last_primary: Option<&str>,
    ) -> Option<String> {
        match pick_primary_by_known(primaries, rejected_alive, last_primary) {
            PrimaryChoice::None => None,
            PrimaryChoice::Chosen(primary) => {
                if primaries.len() > 1 {
                    tracing::error!(
                        "postgres cluster: MORE THAN ONE host reports itself a primary ({primaries:?}) \
                         — possible un-fenced old primary / split brain; keeping {primary}"
                    );
                } else if !primaries.iter().any(|p| p == &primary) {
                    // We kept a last-known primary that only rejected the probe: it is alive, so do not
                    // let another writable host be promoted by elimination.
                    tracing::error!(
                        "postgres cluster: keeping last-known primary {primary} whose probe was \
                         rejected (alive but not probeable); NOT promoting another writable host"
                    );
                }
                Some(primary)
            }
            // Multiple primaries and the last-known one is gone: ask the replicas who they stream from.
            PrimaryChoice::Ambiguous => {
                tracing::error!(
                    "postgres cluster: MORE THAN ONE host reports itself a primary ({primaries:?}); \
                     resolving by replication source"
                );
                if let Some(sender) = self.replication_source(replicas).await
                    && let Some(primary) = primaries.iter().find(|p| host_matches(p, &sender))
                {
                    return Some(primary.clone());
                }
                Some(primaries[0].clone())
            }
        }
    }

    /// Best-effort: asks each replica which host it streams WAL from (`pg_stat_wal_receiver`) and
    /// returns the first answer — that host is the true current primary. Only used to break a
    /// multiple-primaries tie, so its cost falls only on that rare split-brain path.
    async fn replication_source(&self, replicas: &[String]) -> Option<String> {
        for replica in replicas {
            let Ok(mut connection) = self.new_backend_connection(replica).await else {
                continue;
            };
            let database = self.probe_database.clone();
            let sql = "SELECT coalesce(sender_host,'') || ':' || coalesce(sender_port::text,'') \
                       FROM pg_stat_wal_receiver LIMIT 1";
            let result = tokio::time::timeout(BACKEND_OP_TIMEOUT, async {
                authenticate_backend(&mut connection, &self.username, &database, &self.password)
                    .await?;
                query_scalar_string(&mut connection, sql).await
            })
            .await;
            if let Ok(Ok(Some(sender))) = result
                && !sender.trim_matches(':').is_empty()
            {
                return Some(sender);
            }
        }
        None
    }

    /// Bounded liveness check on the cached primary: true only if it is reachable AND still reports
    /// itself the primary. Used before invalidating on a transport error so a single closed backend
    /// socket does not trigger a full re-probe and evict every other session (review F6 re-verify).
    async fn cached_primary_is_still_primary(&self) -> bool {
        let primary_addr = {
            let state = self.topology.lock().await;
            state.topology.as_ref().map(|t| t.primary.clone())
        };
        let Some(addr) = primary_addr else {
            return false;
        };
        match self.probe_host(&addr).await {
            // Reachable and still the primary.
            HostProbe::Primary => true,
            // Reachable but the probe was rejected (rotated probe password, hba, starting up, too many
            // connections): the host is ALIVE — keep the topology and fail only this session, rather
            // than demoting a live primary (review F6 re-verify #2).
            HostProbe::ReachableButRejected { message, .. } => {
                tracing::warn!(
                    "postgres cluster: cached primary {addr} reachable but probe rejected ({message}); \
                     keeping topology"
                );
                true
            }
            // Demoted to a replica or genuinely unreachable: a real failover — invalidate.
            HostProbe::Replica | HostProbe::Unreachable(_) => false,
        }
    }

    async fn probe_host(&self, host: &str) -> HostProbe {
        let mut connection = match self.new_backend_connection(host).await {
            Ok(connection) => connection,
            // A connect failure (refused/timeout/reset) means the host is unreachable.
            Err(err) => return HostProbe::Unreachable(err.to_string()),
        };
        let database = self.probe_database.clone();
        // Bound the whole authenticate + probe exchange: a host that accepts the connection but
        // never replies must not hang topology discovery.
        let result = tokio::time::timeout(BACKEND_OP_TIMEOUT, async {
            authenticate_backend(&mut connection, &self.username, &database, &self.password).await?;
            query_scalar_bool(&mut connection, "SELECT pg_is_in_recovery()").await
        })
        .await;
        match result {
            Err(_elapsed) => HostProbe::Unreachable(format!("timed out probing {host}")),
            Ok(Ok(true)) => HostProbe::Replica,
            Ok(Ok(false)) => HostProbe::Primary,
            // A transport failure mid-probe (reset/EOF) is unreachable...
            Ok(Err(err)) if err.downcast_ref::<crate::connection::ConnectionError>().is_some() => {
                HostProbe::Unreachable(err.to_string())
            }
            // ...but the host ANSWERING with an error (rotated probe password, hba, 'database is
            // starting up', too many connections, md5/SCRAM) means it is ALIVE, just not probeable.
            // Never treat this as gone (review F6 re-verify #2).
            Ok(Err(err)) => HostProbe::ReachableButRejected {
                auth_unsupported: err.downcast_ref::<BackendAuthUnsupported>().is_some(),
                message: err.to_string(),
            },
        }
    }

    async fn ensure_primary(&mut self) -> Result<()> {
        if self.primary.is_some() {
            return Ok(());
        }
        // Try the recorded primary. If it is unreachable, a failover may have promoted a replica, so
        // discard the cached topology, re-probe every contact point, and try the freshly-discovered
        // primary once. This is what lets a NEW connection reach the new primary transparently instead
        // of failing against a dead host until the process restarts.
        match self.connect_primary().await {
            Ok(()) => Ok(()),
            Err(first_err) => {
                tracing::warn!(
                    "postgres cluster: recorded primary unreachable ({first_err}); re-probing topology"
                );
                self.invalidate_topology().await;
                self.ensure_topology().await?;
                self.connect_primary().await.map_err(|retry_err| {
                    anyhow!(
                        "postgres cluster: primary unreachable after re-probe: {retry_err} \
                         (before re-probe: {first_err})"
                    )
                })
            }
        }
    }

    /// Connects to whatever host the cached topology currently names as primary. The connection
    /// carries the client's own auth by passthrough.
    async fn connect_primary(&mut self) -> Result<()> {
        let primary_addr = {
            let state = self.topology.lock().await;
            let addr = state
                .topology
                .as_ref()
                .ok_or_else(|| anyhow!("topology not resolved"))?
                .primary
                .clone();
            self.primary_generation = state.generation;
            addr
        };
        self.primary = Some(self.new_backend_connection(&primary_addr).await?);
        self.connected_primary = Some(primary_addr);
        Ok(())
    }

    /// Discards the shared cached topology so the next `ensure_topology` re-probes every contact
    /// point. Called when the recorded primary is unreachable — the trigger that lets the cluster
    /// discover a promoted replica after a failover. Also clears THIS connection's replica choice,
    /// whose host role may have just changed, so the refreshed topology reselects it.
    async fn invalidate_topology(&mut self) {
        {
            let mut state = self.topology.lock().await;
            // Only invalidate the topology this session actually failed against. If another session
            // already re-probed (generation advanced) or already invalidated (topology None), this is
            // a stale failure — leave the fresh state alone, so a slow or concurrent failure can neither
            // clear a just-installed topology nor cause a re-probe storm (review F4).
            if state.topology.is_some() && state.generation == self.primary_generation {
                state.topology = None;
                self.primary_reprobe.increment(1);
            }
        }
        self.replica_addr = None;
    }

    async fn ensure_replica(&mut self) -> Result<()> {
        if self.replica.is_some() {
            return Ok(());
        }
        let addr = self
            .replica_addr
            .clone()
            .ok_or_else(|| anyhow!("no replica configured"))?;
        let user = self
            .client_user
            .clone()
            .ok_or_else(|| anyhow!("client user unknown"))?;
        let database = self.client_database.clone().unwrap_or_else(|| user.clone());
        // B1: originate the replica connection with the client user's own backend password from the
        // userlist, falling back to the single configured password for any user not listed.
        let password = self
            .replica_users
            .get(&user)
            .cloned()
            .unwrap_or_else(|| self.password.clone());
        match self
            .try_connect_replica(&addr, &user, &database, &password)
            .await
        {
            Ok((connection, replica_key)) => {
                self.mark_replica_healthy(&addr).await;
                // Register for cluster-side cancel routing: map the client-held key (the primary's) to
                // this replica's own key, so a later CancelRequest can be re-issued to the replica that
                // is actually running the read.
                if let (Some(client_key), Some((rpid, rsecret))) =
                    (self.client_cancel_key.clone(), replica_key)
                    && let Ok(mut reg) = self.cancel_registry.lock()
                {
                    reg.insert(
                        client_key,
                        ReplicaCancelTarget {
                            addr: addr.clone(),
                            process_id: rpid,
                            secret_key: rsecret,
                        },
                    );
                }
                self.replica = Some(connection);
                Ok(())
            }
            Err(err) => {
                self.replica_addr = None;
                if err.downcast_ref::<BackendAuthRejected>().is_some() {
                    // Classify before reacting (review F6): a rejected auth is a PER-USER credential
                    // problem (a bad/missing replica_users entry), NOT an unreachable host. Cooling the
                    // host would push every OTHER user off it too. Instead, latch this session onto the
                    // primary (it never retries the replica) and warn once; the host stays healthy.
                    tracing::warn!(
                        "postgres cluster: replica auth failed for user {user} on {addr} ({err}); \
                         routing this session's reads to the primary"
                    );
                    self.replica_auth_failed = true;
                } else {
                    // A connect/timeout failure: the HOST is unreachable — cool it down so subsequent
                    // reads (from any user) skip it without paying the per-read connect penalty.
                    self.mark_replica_unhealthy(&addr).await;
                }
                Err(err)
            }
        }
    }

    /// Connects and authenticates a replica connection, returning it along with the replica's own
    /// BackendKeyData (process_id + secret) captured during authentication, for cancel routing.
    async fn try_connect_replica(
        &self,
        addr: &str,
        user: &str,
        database: &str,
        password: &str,
    ) -> Result<(SinkConnection, Option<(i32, Bytes)>)> {
        let mut connection = self.new_backend_connection(addr).await?;
        let key = tokio::time::timeout(
            BACKEND_OP_TIMEOUT,
            authenticate_backend(&mut connection, user, database, password),
        )
        .await
        .map_err(|_| anyhow!("timed out authenticating to replica {addr}"))??;
        Ok((connection, key))
    }

    async fn new_backend_connection(&self, host: &str) -> Result<SinkConnection> {
        SinkConnection::new(
            host,
            PostgresCodecBuilder::new(Direction::Sink, "PostgresSinkCluster".to_owned()),
            &self.tls,
            self.connect_timeout,
            self.force_run_chain.clone(),
            None,
        )
        .await
    }

    /// Relays a client's CancelRequest to the backend(s) that could be running its query: verbatim to
    /// the primary (the client holds the primary's key), and — if this session's key is in the shared
    /// registry — a synthesized CancelRequest to the replica using the replica's OWN key. Both are
    /// best-effort (a cancel is advisory); the client connection is then closed, matching a real
    /// server's behaviour after acting on a cancel.
    async fn handle_cancel(&mut self, chain_state: &mut ChainState<'_>) -> Result<Messages> {
        let primary_addr = {
            let state = self.topology.lock().await;
            state.topology.as_ref().map(|t| t.primary.clone())
        };
        let mut responses = vec![];
        for request in chain_state.requests.iter_mut() {
            let (process_id, secret_key) = match request.frame() {
                Some(Frame::Postgres(PostgresFrame::Request(FrontendMessage::CancelRequest {
                    process_id,
                    secret_key,
                }))) => (*process_id, secret_key.clone()),
                _ => continue,
            };
            if let Some(addr) = &primary_addr {
                self.send_cancel(addr, process_id, secret_key.clone()).await;
            }
            let target = self
                .cancel_registry
                .lock()
                .ok()
                .and_then(|reg| reg.get(&(process_id, secret_key.clone())).cloned());
            if let Some(target) = target {
                self.send_cancel(&target.addr, target.process_id, target.secret_key)
                    .await;
            }
            // The server sends no response to a cancel; satisfy one-response-per-request with a dummy.
            let mut dummy = Message::from_frame(Frame::Dummy);
            dummy.set_request_id(request.id());
            responses.push(dummy);
        }
        chain_state.requests.clear();
        chain_state.close_client_connection = true;
        Ok(responses)
    }

    async fn send_cancel(&self, addr: &str, process_id: i32, secret_key: Bytes) {
        let mut bytes = BytesMut::new();
        let message = FrontendMessage::CancelRequest {
            process_id,
            secret_key,
        };
        if message.encode(&mut bytes).is_err() {
            return;
        }
        if let Err(err) = self.send_cancel_bytes(addr, &bytes).await {
            tracing::warn!("postgres cluster: failed to relay CancelRequest to {addr}: {err}");
        }
    }

    async fn send_cancel_bytes(&self, addr: &str, bytes: &[u8]) -> Result<()> {
        // No TLS on the cancel connection: postgres accepts a cancel on a plaintext connection even to
        // a TLS server, and it carries no secret beyond the already-issued cancel key.
        let mut stream =
            tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await??;
        stream.write_all(bytes).await?;
        stream.flush().await?;
        stream.shutdown().await.ok();
        Ok(())
    }
}

/// True if any request in the batch is a CancelRequest (which arrives alone on its own connection).
fn requests_contain_cancel(requests: &mut [Message]) -> bool {
    requests.iter_mut().any(|r| {
        matches!(
            r.frame(),
            Some(Frame::Postgres(PostgresFrame::Request(
                FrontendMessage::CancelRequest { .. }
            )))
        )
    })
}

impl Drop for PostgresSinkCluster {
    fn drop(&mut self) {
        // Remove this session's cancel registry entry so keys do not leak as sessions come and go.
        if let Some(key) = self.client_cancel_key.take()
            && let Ok(mut reg) = self.cancel_registry.lock()
        {
            reg.remove(&key);
        }
    }
}

/// How one request should be routed, independent of session state.
enum RequestRoute {
    /// A pure read that a replica can serve.
    ReplicaRead,
    /// Must go to the primary (write, DDL, transaction control, COPY, or anything unproven).
    Primary,
    /// Changes lasting session state: pins the whole session to the primary.
    PinPrimary,
    /// Carries no routing decision of its own (Bind/Execute/Sync/…): inherits the unit.
    Neutral,
}

/// True if the batch's LAST request is a Sync or a simple Query. This is the gate for opening a
/// replica unit (see decide_target): such a batch normally closes its own response unit with a
/// ReadyForQuery within one exchange() call, so the unit never spans batches. A Flush/CopyDone/CopyFail
/// terminator is a flush point too but yields NO ReadyForQuery, so it must not open a unit; a trailing
/// partial pipeline does not end in a terminator either.
///
/// The name is LITERAL — "sync or query", not "yields a ReadyForQuery" — on purpose: a simple Query
/// does not universally yield a ReadyForQuery. `COPY ... FROM STDIN` is a simple Query whose train ends
/// at CopyInResponse with NO ReadyForQuery (that comes with a later CopyDone) — exactly the
/// never-closing-unit shape. It is safe here ONLY because it is a write: analyze_sql classifies every
/// CopyStmt as a write, so classify_request returns Primary and has_primary_only blocks the replica
/// unit in decide_target BEFORE this predicate is consulted, so a replica-safe COPY-in Query never
/// reaches it. The ReadyForQuery guarantee lives in the classifier, not in this predicate — do not
/// rename this to imply otherwise.
fn ends_with_sync_or_query(requests: &mut [Message]) -> bool {
    matches!(
        requests.last_mut().and_then(|r| r.frame()),
        Some(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Sync | FrontendMessage::Query { .. }
        )))
    )
}

fn classify_request(request: &mut Message) -> RequestRoute {
    match request.frame() {
        Some(Frame::Postgres(PostgresFrame::Request(message))) => match message {
            FrontendMessage::Query { query } => {
                let analysis = analyze_sql(query);
                if analysis.pins_session {
                    RequestRoute::PinPrimary
                } else if analysis.replica_safe {
                    RequestRoute::ReplicaRead
                } else {
                    RequestRoute::Primary
                }
            }
            FrontendMessage::Parse {
                statement_name,
                query,
                ..
            } => {
                // A named prepared statement is reused across units and must stay on one node.
                if !statement_name.is_empty() {
                    RequestRoute::PinPrimary
                } else {
                    let analysis = analyze_sql(query);
                    if analysis.pins_session {
                        RequestRoute::PinPrimary
                    } else if analysis.replica_safe {
                        RequestRoute::ReplicaRead
                    } else {
                        RequestRoute::Primary
                    }
                }
            }
            FrontendMessage::Bind { .. }
            | FrontendMessage::Execute { .. }
            | FrontendMessage::Describe { .. }
            | FrontendMessage::Sync
            | FrontendMessage::Flush
            | FrontendMessage::Close { .. }
            | FrontendMessage::CopyData(_)
            | FrontendMessage::CopyDone
            | FrontendMessage::CopyFail { .. } => RequestRoute::Neutral,
            _ => RequestRoute::Primary,
        },
        // A suppressed request (a throttle/cache dummy from an upstream transform) carries no routing
        // decision of its own — it must not force the batch (or the session) onto the primary (F11).
        Some(Frame::Dummy) => RequestRoute::Neutral,
        _ => RequestRoute::Primary,
    }
}

/// Returns the status byte of the last ReadyForQuery in a response, if any.
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

/// Originates authentication to a backend using a configured password. Supports trust and
/// cleartext password only; md5 and SCRAM are a documented follow-up.
/// The backend requested md5 or SCRAM authentication, which PostgresSinkCluster cannot originate (it
/// originates probe and replica connections with trust or cleartext password only — SCRAM is
/// per-connection and cannot be forwarded to N backends). Typed so `map_startup_error` can turn it
/// into a clear client-facing ErrorResponse instead of a generic internal error. Its `Display` is the
/// message shown to the client.
#[derive(Debug)]
struct BackendAuthUnsupported;

impl std::fmt::Display for BackendAuthUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PostgresSinkCluster can only originate connections with trust or cleartext password \
             auth, but this backend requires md5/SCRAM. Use PostgresSinkSingle for a md5/SCRAM backend."
        )
    }
}

impl std::error::Error for BackendAuthUnsupported {}

/// A backend returned an ErrorResponse during authentication (e.g. "password authentication failed").
/// Typed so a REPLICA auth failure is understood as a PER-USER credential problem (a bad/missing
/// `replica_users` entry) rather than an unreachable host — the host must not be cooled down for it
/// (review F6). Carries the server's message for the log.
#[derive(Debug)]
struct BackendAuthRejected(String);

impl std::fmt::Display for BackendAuthRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "backend authentication rejected: {}", self.0)
    }
}

impl std::error::Error for BackendAuthRejected {}

/// No contact point currently reports itself a primary — every host is down or a failover is mid-flight
/// (the crash→promotion window). Typed so `map_startup_error` surfaces a clean, retryable FATAL to the
/// client instead of the generic "internal shotover bug" text (review F10).
#[derive(Debug)]
struct NoPrimaryAvailable;

impl std::fmt::Display for NoPrimaryAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no postgres primary is currently available (all contact points down or a failover is in \
             progress); please retry"
        )
    }
}

impl std::error::Error for NoPrimaryAvailable {}

/// Turns a startup-time backend failure into what the client should see. An unsupported-auth failure
/// (a md5/SCRAM backend the cluster sink cannot originate against) becomes a clean FATAL ErrorResponse
/// that names the fix, and closes the connection — instead of the generic "internal shotover bug"
/// error a client gets when a transform returns Err. Any other failure propagates unchanged.
fn map_startup_error(err: anyhow::Error, chain_state: &mut ChainState) -> Result<Messages> {
    // 0A000 = feature_not_supported (md5/SCRAM backend); 08006 = connection_failure (backend stalled
    // or no primary currently available).
    let sqlstate = if err.downcast_ref::<BackendAuthUnsupported>().is_some() {
        "0A000"
    } else if err.downcast_ref::<super::BackendReadTimeout>().is_some()
        || err.downcast_ref::<NoPrimaryAvailable>().is_some()
    {
        "08006"
    } else {
        return Err(err);
    };
    chain_state.close_client_connection = true;
    let request_id = chain_state.requests.first_mut().map(|r| r.id());
    let mut response = Message::from_frame(Frame::Postgres(PostgresFrame::Response(vec![
        BackendMessage::ErrorResponse {
            fields: vec![
                (b'S', "FATAL".to_owned()),
                (b'V', "FATAL".to_owned()),
                (b'C', sqlstate.to_owned()),
                (b'M', err.to_string()),
            ],
        },
    ])));
    if let Some(id) = request_id {
        response.set_request_id(id);
    }
    Ok(vec![response])
}

/// The ErrorResponse sent to the client when a backend read timed out mid-session (read_timeout).
/// SQLSTATE 08006 (connection_failure): the stalled backend connection has already been dropped by
/// `route`, and the caller pairs this to the batch's first request id and closes the connection.
fn backend_read_timeout_response(request_id: Option<MessageId>) -> Message {
    let mut response = Message::from_frame(Frame::Postgres(PostgresFrame::Response(vec![
        BackendMessage::ErrorResponse {
            fields: vec![
                (b'S', "ERROR".to_owned()),
                (b'V', "ERROR".to_owned()),
                (b'C', "08006".to_owned()),
                (b'M', "postgres backend did not respond within read_timeout".to_owned()),
            ],
        },
    ])));
    if let Some(id) = request_id {
        response.set_request_id(id);
    }
    response
}

/// The ErrorResponse sent to the client when the backend link is lost (a crash, a failover, or a
/// stale primary link after a re-probe). SQLSTATE 08006 (connection_failure); the caller closes the
/// connection so the client reconnects onto the current primary with a fresh session.
fn backend_link_lost_response(request_id: Option<MessageId>) -> Message {
    let mut response = Message::from_frame(Frame::Postgres(PostgresFrame::Response(vec![
        BackendMessage::ErrorResponse {
            fields: vec![
                (b'S', "FATAL".to_owned()),
                (b'V', "FATAL".to_owned()),
                (b'C', "08006".to_owned()),
                (
                    b'M',
                    "connection to postgres backend lost, please reconnect".to_owned(),
                ),
            ],
        },
    ])));
    if let Some(id) = request_id {
        response.set_request_id(id);
    }
    response
}

/// Originates a backend startup/auth and returns the backend's BackendKeyData (process_id + secret),
/// if the backend sent one, so a later CancelRequest can be re-issued to this backend.
async fn authenticate_backend(
    connection: &mut SinkConnection,
    user: &str,
    database: &str,
    password: &str,
) -> Result<Option<(i32, Bytes)>> {
    let startup = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
        FrontendMessage::Startup {
            protocol_version: PROTOCOL_VERSION_3_0,
            parameters: vec![
                ("user".to_owned(), user.to_owned()),
                ("database".to_owned(), database.to_owned()),
            ],
        },
    )));
    connection.send(vec![startup])?;

    let mut key = None;
    loop {
        let mut responses = vec![];
        connection.recv_into(&mut responses).await?;
        for response in &mut responses {
            let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
                continue;
            };
            for message in messages.iter() {
                match message {
                    BackendMessage::BackendKeyData {
                        process_id,
                        secret_key,
                    } => {
                        key = Some((*process_id, secret_key.clone()));
                    }
                    BackendMessage::Authentication(AuthenticationMessage::Ok) => {}
                    BackendMessage::Authentication(AuthenticationMessage::CleartextPassword) => {
                        let mut body = BytesMut::new();
                        body.put_slice(password.as_bytes());
                        body.put_u8(0);
                        let password_message =
                            Message::from_frame(Frame::Postgres(PostgresFrame::Request(
                                FrontendMessage::AuthenticationData(body.freeze()),
                            )));
                        connection.send(vec![password_message])?;
                    }
                    BackendMessage::Authentication(AuthenticationMessage::Md5Password {
                        ..
                    })
                    | BackendMessage::Authentication(AuthenticationMessage::Sasl { .. }) => {
                        // Typed so the transform can surface a clear client-facing ErrorResponse
                        // instead of the generic internal error a bare Err produces.
                        return Err(BackendAuthUnsupported.into());
                    }
                    BackendMessage::ErrorResponse { .. } => {
                        return Err(BackendAuthRejected(
                            message.error_message().unwrap_or("unknown error").to_owned(),
                        )
                        .into());
                    }
                    BackendMessage::ReadyForQuery { .. } => return Ok(key),
                    _ => {}
                }
            }
        }
    }
}

/// The outcome of probing one contact point, classifying reachability so a host that ANSWERS the probe
/// with an error is never mistaken for a dead one (review F6 re-verify #2).
enum HostProbe {
    /// Reachable and not in recovery.
    Primary,
    /// Reachable and in recovery.
    Replica,
    /// Reachable, but the probe itself was rejected (rotated probe password, hba, 'database is starting
    /// up', too many connections, md5/SCRAM). The host is alive.
    ReachableButRejected {
        message: String,
        auth_unsupported: bool,
    },
    /// A transport failure: connect refused/timeout/reset/EOF. Unreachable.
    Unreachable(String),
}

/// The primary decision that can be made from host roles alone, before any replication-source probe.
#[derive(Debug)]
enum PrimaryChoice {
    /// No host reports itself writable.
    None,
    /// A single primary, or a fenced choice among several.
    Chosen(String),
    /// Several hosts report themselves primary and the last-known one is not among them — the caller
    /// must break the tie with the replication source.
    Ambiguous,
}

/// The fencing decision that needs no I/O (review F5, F6 re-verify #2): a last-known primary that is
/// either confirmed primary OR alive-but-probe-rejected is KEPT (never demoted by contact-point order,
/// and never let another writable host win by elimination while the real primary is merely
/// unprobeable); otherwise one primary is taken as-is and several are Ambiguous (caller consults the
/// replication source).
fn pick_primary_by_known(
    primaries: &[String],
    rejected_alive: &[String],
    last_primary: Option<&str>,
) -> PrimaryChoice {
    if let Some(last) = last_primary
        && (primaries.iter().any(|p| p == last) || rejected_alive.iter().any(|p| p == last))
    {
        return PrimaryChoice::Chosen(last.to_owned());
    }
    match primaries.len() {
        0 => PrimaryChoice::None,
        1 => PrimaryChoice::Chosen(primaries[0].clone()),
        _ => PrimaryChoice::Ambiguous,
    }
}

/// True if a contact point and a `host:port` from pg_stat_wal_receiver name the same host. Loose by
/// design: the replica's sender_host may be an alias/IP that differs from the configured contact
/// point, so a host-part match (ignoring port) is the most that can be relied on.
fn host_matches(contact_point: &str, sender: &str) -> bool {
    let cp_host = contact_point.split(':').next().unwrap_or(contact_point);
    let sender_host = sender.split(':').next().unwrap_or(sender);
    !sender_host.is_empty() && cp_host == sender_host
}

/// Runs a query expected to return a single text value, returning None when the query yields no row
/// (e.g. `pg_stat_wal_receiver` on a host that is not streaming). Unlike `query_scalar_bool` it
/// completes at ReadyForQuery, so a zero-row result does not hang.
async fn query_scalar_string(connection: &mut SinkConnection, sql: &str) -> Result<Option<String>> {
    let query = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
        FrontendMessage::Query {
            query: sql.to_owned(),
        },
    )));
    connection.send(vec![query])?;

    let mut result = None;
    loop {
        let mut responses = vec![];
        connection.recv_into(&mut responses).await?;
        for response in &mut responses {
            let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
                continue;
            };
            for message in messages.iter() {
                match message {
                    BackendMessage::DataRow { values } => {
                        if let Some(Some(value)) = values.first() {
                            result = Some(String::from_utf8_lossy(value.as_ref()).into_owned());
                        }
                    }
                    BackendMessage::ErrorResponse { .. } => {
                        bail!(
                            "query {sql} failed: {}",
                            message.error_message().unwrap_or("unknown error")
                        );
                    }
                    BackendMessage::ReadyForQuery { .. } => return Ok(result),
                    _ => {}
                }
            }
        }
    }
}

/// Runs a query expected to return a single boolean and returns it (used for `pg_is_in_recovery()`).
async fn query_scalar_bool(connection: &mut SinkConnection, sql: &str) -> Result<bool> {
    let query = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
        FrontendMessage::Query {
            query: sql.to_owned(),
        },
    )));
    connection.send(vec![query])?;

    loop {
        let mut responses = vec![];
        connection.recv_into(&mut responses).await?;
        for response in &mut responses {
            let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
                continue;
            };
            for message in messages.iter() {
                match message {
                    BackendMessage::DataRow { values } => {
                        let value = values
                            .first()
                            .and_then(|v| v.as_ref())
                            .ok_or_else(|| anyhow!("empty scalar result for {sql}"))?;
                        return Ok(value.as_ref() == b"t");
                    }
                    BackendMessage::ErrorResponse { .. } => {
                        bail!(
                            "query {sql} failed: {}",
                            message.error_message().unwrap_or("unknown error")
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fences_primary_selection() {
        let s = |x: &str| x.to_owned();
        let none: &[String] = &[];
        // No writable host.
        assert!(matches!(
            pick_primary_by_known(&[], none, None),
            PrimaryChoice::None
        ));
        // A single primary is taken as-is.
        assert!(matches!(
            pick_primary_by_known(&[s("a:5432")], none, None),
            PrimaryChoice::Chosen(p) if p == "a:5432"
        ));
        // Two primaries (split brain), last-known among them: KEEP it, regardless of list order —
        // this is the fence that stops writes flipping to a returning stale node.
        assert!(matches!(
            pick_primary_by_known(&[s("a:5432"), s("b:5432")], none, Some("b:5432")),
            PrimaryChoice::Chosen(p) if p == "b:5432"
        ));
        // The last-known primary only REJECTED the probe (alive but not probeable) while another host
        // is writable: KEEP the last-known one, never promote the other by elimination (F6 re-verify #2).
        assert!(matches!(
            pick_primary_by_known(&[s("a:5432")], &[s("b:5432")], Some("b:5432")),
            PrimaryChoice::Chosen(p) if p == "b:5432"
        ));
        // Two primaries, last-known NOT among them (or none): ambiguous -> caller consults the
        // replication source, never contact-point order.
        assert!(matches!(
            pick_primary_by_known(&[s("a:5432"), s("b:5432")], none, Some("c:5432")),
            PrimaryChoice::Ambiguous
        ));
        assert!(matches!(
            pick_primary_by_known(&[s("a:5432"), s("b:5432")], none, None),
            PrimaryChoice::Ambiguous
        ));
    }

    #[test]
    fn host_matches_by_host_part() {
        assert!(host_matches("shotest-r1:5432", "shotest-r1:5432"));
        assert!(host_matches("shotest-pg:5432", "shotest-pg:6000")); // port differs, host wins
        assert!(!host_matches("shotest-pg:5432", "other:5432"));
        assert!(!host_matches("shotest-pg:5432", ":5432")); // empty sender host never matches
    }

    fn query(sql: &str) -> Message {
        Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Query {
                query: sql.to_owned(),
            },
        )))
    }

    fn parse(name: &str, sql: &str) -> Message {
        Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Parse {
                statement_name: name.to_owned(),
                query: sql.to_owned(),
                parameter_data_types: vec![],
            },
        )))
    }

    #[test]
    fn test_request_routing_classification() {
        assert!(matches!(
            classify_request(&mut query("SELECT * FROM t")),
            RequestRoute::ReplicaRead
        ));
        assert!(matches!(
            classify_request(&mut query("INSERT INTO t VALUES (1)")),
            RequestRoute::Primary
        ));
        // Hidden write under a leading SELECT still routes to the primary.
        assert!(matches!(
            classify_request(&mut query(
                "WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x"
            )),
            RequestRoute::Primary
        ));
        assert!(matches!(
            classify_request(&mut query("SET search_path = x")),
            RequestRoute::PinPrimary
        ));
        // An unnamed prepared read can go to a replica; a named one pins the session.
        assert!(matches!(
            classify_request(&mut parse("", "SELECT 1")),
            RequestRoute::ReplicaRead
        ));
        assert!(matches!(
            classify_request(&mut parse("stmt1", "SELECT 1")),
            RequestRoute::PinPrimary
        ));
        // Extended-protocol follow-up messages inherit the unit's node.
        let mut bind = Message::from_frame(Frame::Postgres(PostgresFrame::Request(
            FrontendMessage::Bind {
                portal_name: "".to_owned(),
                statement_name: "".to_owned(),
                parameter_format_codes: vec![],
                parameter_values: vec![],
                result_format_codes: vec![],
            },
        )));
        assert!(matches!(classify_request(&mut bind), RequestRoute::Neutral));
    }

    #[test]
    fn test_batch_opens_replica_unit_only_when_ending_in_ready_for_query() {
        // decide_target opens a replica unit only for a batch whose LAST request is a Sync or a simple
        // Query — a flush point that yields a ReadyForQuery and closes the unit within one exchange().
        // A trailing partial pipeline does NOT (finding-2 original); a Flush/CopyDone terminator does
        // NOT either (finding-2 REGRESSION — a flush point that yields no ReadyForQuery, so its unit
        // never closes and spans into the next batch).
        fn req(message: FrontendMessage) -> Message {
            Message::from_frame(Frame::Postgres(PostgresFrame::Request(message)))
        }
        fn bind() -> FrontendMessage {
            FrontendMessage::Bind {
                portal_name: "".to_owned(),
                statement_name: "".to_owned(),
                parameter_format_codes: vec![],
                parameter_values: vec![],
                result_format_codes: vec![],
            }
        }
        fn describe() -> FrontendMessage {
            FrontendMessage::Describe {
                kind: b'P',
                name: "".to_owned(),
            }
        }
        fn execute() -> FrontendMessage {
            FrontendMessage::Execute {
                portal_name: "".to_owned(),
                max_rows: 0,
            }
        }
        let opens_replica = |mut batch: Vec<Message>| ends_with_sync_or_query(&mut batch);

        // Ends in a Sync or simple Query → qualifies (offloads to a replica).
        assert!(opens_replica(vec![query("SELECT 1")]));
        assert!(opens_replica(vec![parse("", "SELECT 1"), req(FrontendMessage::Sync)]));
        assert!(opens_replica(vec![
            parse("", "SELECT 1"),
            req(bind()),
            req(describe()),
            req(execute()),
            req(FrontendMessage::Sync),
        ]));
        // A trailing Parse after the Sync → does NOT qualify (finding-2 original).
        assert!(!opens_replica(vec![
            parse("", "SELECT 1"),
            req(bind()),
            req(describe()),
            req(execute()),
            req(FrontendMessage::Sync),
            parse("", "SELECT 1"),
        ]));
        // A Flush terminator → does NOT qualify (finding-2 REGRESSION: a flush point with no RFQ).
        assert!(!opens_replica(vec![
            parse("", "SELECT 1"),
            req(bind()),
            req(describe()),
            req(execute()),
            req(FrontendMessage::Flush),
        ]));
        // A CopyDone terminator → does NOT qualify either.
        assert!(!opens_replica(vec![req(FrontendMessage::CopyDone)]));
        // No terminator at all → does not qualify.
        assert!(!opens_replica(vec![parse("", "SELECT 1")]));
    }

    #[test]
    fn test_trailing_ready_status() {
        let mut response = Message::from_frame(Frame::Postgres(PostgresFrame::Response(vec![
            BackendMessage::CommandComplete {
                tag: "SELECT 1".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'T' },
        ])));
        assert_eq!(trailing_ready_status(&mut response), Some(b'T'));
        let mut no_rfq = Message::from_frame(Frame::Postgres(PostgresFrame::Response(vec![
            BackendMessage::DataRow { values: vec![] },
        ])));
        assert_eq!(trailing_ready_status(&mut no_rfq), None);
    }
}
