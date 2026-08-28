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
//! response), so the proxy originates them itself using a configured backend password plus the
//! `user`/`database` it captured from the client's startup message — the standard pooler model.
//! Only `trust` and cleartext `password` backend auth are supported for originated connections in
//! this milestone; md5 and SCRAM origination are a follow-up. Per-user credential mapping (a
//! pgbouncer-style userlist) is also a follow-up: today every replica connection authenticates
//! with the one configured password.
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
use crate::message::{Message, Messages};
use crate::tls::{TlsConnector, TlsConnectorConfig};
use crate::transforms::{
    ChainState, DownChainProtocol, Transform, TransformBuilder, TransformConfig,
    TransformContextBuilder, TransformContextConfig, UpChainProtocol,
};
use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

/// The protocol version literal for protocol 3.0 (major 3 in the high 16 bits).
const PROTOCOL_VERSION_3_0: i32 = 196608;

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PostgresSinkClusterConfig {
    pub name: String,
    /// Candidate backend hosts (`host:port`). Each is probed with `pg_is_in_recovery()` to decide
    /// which is the primary and which are read replicas.
    pub first_contact_points: Vec<String>,
    /// The user used to originate replica connections and to probe topology.
    pub username: String,
    /// The backend password used to originate replica connections and to probe topology.
    pub password: String,
    /// The database used only for topology probing (`pg_is_in_recovery()` works in any database).
    #[serde(default = "default_probe_database")]
    pub probe_database: String,
    pub connect_timeout_ms: u64,
    pub tls: Option<TlsConnectorConfig>,
}

fn default_probe_database() -> String {
    "postgres".to_owned()
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
        _transform_context: TransformContextConfig,
    ) -> Result<Box<dyn TransformBuilder>> {
        if self.first_contact_points.is_empty() {
            bail!("PostgresSinkCluster requires at least one first_contact_point");
        }
        let tls = self.tls.as_ref().map(TlsConnector::new).transpose()?;
        Ok(Box::new(PostgresSinkClusterBuilder {
            name: self.name.clone(),
            contact_points: self.first_contact_points.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            probe_database: self.probe_database.clone(),
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            tls,
            topology: Arc::new(Mutex::new(None)),
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

/// The discovered roles of the backend hosts. Shared across all client connections and refreshed
/// when a connection to the recorded primary fails (basic failover).
#[derive(Clone, Debug)]
struct Topology {
    primary: String,
    replicas: Vec<String>,
}

pub struct PostgresSinkClusterBuilder {
    name: String,
    contact_points: Vec<String>,
    username: String,
    password: String,
    probe_database: String,
    connect_timeout: Duration,
    tls: Option<TlsConnector>,
    topology: Arc<Mutex<Option<Topology>>>,
}

impl TransformBuilder for PostgresSinkClusterBuilder {
    fn build(&self, transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(PostgresSinkCluster {
            contact_points: self.contact_points.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            probe_database: self.probe_database.clone(),
            connect_timeout: self.connect_timeout,
            tls: self.tls.clone(),
            topology: self.topology.clone(),
            force_run_chain: transform_context.force_run_chain,
            primary: None,
            replica: None,
            replica_addr: None,
            startup_complete: false,
            client_user: None,
            client_database: None,
            in_transaction: false,
            session_pinned: false,
            unit_target: None,
            round_robin: 0,
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
    tls: Option<TlsConnector>,
    topology: Arc<Mutex<Option<Topology>>>,
    force_run_chain: Arc<Notify>,

    /// Client-auth passthrough connection to the primary.
    primary: Option<SinkConnection>,
    /// Proxy-originated connection to one replica.
    replica: Option<SinkConnection>,
    replica_addr: Option<String>,

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
    /// Rotates replica selection across new client connections.
    round_robin: usize,
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
        self.ensure_topology().await?;
        self.ensure_primary().await?;

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
        self.route(target, std::mem::take(&mut chain_state.requests))
            .await
    }
}

impl PostgresSinkCluster {
    /// Chooses where an incoming request batch goes. Preserves an in-progress unit's node; only
    /// re-decides at a unit boundary (session idle, no open transaction).
    fn decide_target(&mut self, requests: &mut [Message]) -> Target {
        if let Some(target) = self.unit_target {
            return target;
        }
        if self.session_pinned || self.in_transaction {
            return Target::Primary;
        }

        let mut all_replica_safe = self.replica_available();
        let mut saw_deciding_read = false;
        for request in requests.iter_mut() {
            match classify_request(request) {
                RequestRoute::ReplicaRead => saw_deciding_read = true,
                RequestRoute::Neutral => {}
                RequestRoute::PinPrimary => {
                    // A lasting session-state change: pin the whole session to the primary.
                    self.session_pinned = true;
                    all_replica_safe = false;
                }
                RequestRoute::Primary => all_replica_safe = false,
            }
        }

        if all_replica_safe && saw_deciding_read {
            Target::Replica
        } else {
            Target::Primary
        }
    }

    /// Sends a batch to the chosen backend, collects its responses, and updates unit/transaction
    /// state from the trailing ReadyForQuery.
    async fn route(&mut self, target: Target, requests: Messages) -> Result<Messages> {
        let target = if target == Target::Replica && self.ensure_replica().await.is_err() {
            // No replica reachable: reads fall back to the primary.
            Target::Primary
        } else {
            target
        };
        self.unit_target = Some(target);

        let requests_count = requests.len();
        let connection = match target {
            Target::Primary => self.primary.as_mut().unwrap(),
            Target::Replica => self.replica.as_mut().unwrap(),
        };
        connection.send(requests)?;

        let mut responses = vec![];
        let mut responses_count = 0;
        while responses_count < requests_count {
            let old = responses.len();
            connection.recv_into(&mut responses).await?;
            for response in &mut responses[old..] {
                if response.request_id().is_some() {
                    responses_count += 1;
                }
                if let Some(status) = trailing_ready_status(response) {
                    // A ReadyForQuery ends the current unit and reports transaction state.
                    self.in_transaction = status != b'I';
                    if status == b'I' {
                        self.unit_target = None;
                    }
                }
            }
        }
        Ok(responses)
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
        let requests_count = requests.len();
        let primary = self.primary.as_mut().unwrap();
        primary.send(requests)?;

        let mut responses = vec![];
        let mut responses_count = 0;
        while responses_count < requests_count {
            let old = responses.len();
            primary.recv_into(&mut responses).await?;
            for response in &mut responses[old..] {
                if response.request_id().is_some() {
                    responses_count += 1;
                }
                if let Some(status) = trailing_ready_status(response) {
                    // The first ReadyForQuery means authentication succeeded and the session is live.
                    self.startup_complete = true;
                    self.in_transaction = status != b'I';
                }
            }
        }
        Ok(responses)
    }

    fn replica_available(&self) -> bool {
        self.replica.is_some() || self.replica_addr.is_some()
    }

    /// Probes topology once (shared across all client connections) if it is not already known.
    async fn ensure_topology(&mut self) -> Result<()> {
        let topology = {
            let mut guard = self.topology.lock().await;
            if guard.is_none() {
                let probed = self.probe_topology().await?;
                tracing::info!(
                    "postgres cluster topology: primary={} replicas={:?}",
                    probed.primary,
                    probed.replicas
                );
                *guard = Some(probed);
            }
            guard.as_ref().unwrap().clone()
        };
        self.select_replica_addr(&topology);
        Ok(())
    }

    fn select_replica_addr(&mut self, topology: &Topology) {
        if self.replica_addr.is_none() && !topology.replicas.is_empty() {
            let index = self.round_robin % topology.replicas.len();
            self.round_robin = self.round_robin.wrapping_add(1);
            self.replica_addr = Some(topology.replicas[index].clone());
        }
    }

    /// Connects to each contact point, runs `pg_is_in_recovery()`, and classifies primary vs replica.
    async fn probe_topology(&self) -> Result<Topology> {
        let mut primary = None;
        let mut replicas = vec![];
        for host in &self.contact_points {
            match self.probe_host(host).await {
                Ok(true) => replicas.push(host.clone()),
                Ok(false) => {
                    if primary.is_some() {
                        tracing::warn!(
                            "postgres cluster: more than one primary found, keeping the first"
                        );
                    } else {
                        primary = Some(host.clone());
                    }
                }
                Err(err) => tracing::warn!("postgres cluster: probe of {host} failed: {err}"),
            }
        }
        match primary {
            Some(primary) => Ok(Topology { primary, replicas }),
            None => bail!(
                "postgres cluster: no primary found among {:?}",
                self.contact_points
            ),
        }
    }

    async fn probe_host(&self, host: &str) -> Result<bool> {
        let mut connection = self.new_backend_connection(host).await?;
        let database = self.probe_database.clone();
        authenticate_backend(&mut connection, &self.username, &database, &self.password).await?;
        query_scalar_bool(&mut connection, "SELECT pg_is_in_recovery()").await
    }

    async fn ensure_primary(&mut self) -> Result<()> {
        if self.primary.is_some() {
            return Ok(());
        }
        let primary_addr = {
            let guard = self.topology.lock().await;
            guard
                .as_ref()
                .ok_or_else(|| anyhow!("topology not resolved"))?
                .primary
                .clone()
        };
        // The primary connection carries the client's own auth by passthrough.
        self.primary = Some(self.new_backend_connection(&primary_addr).await?);
        Ok(())
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
        let mut connection = self.new_backend_connection(&addr).await?;
        authenticate_backend(&mut connection, &user, &database, &self.password).await?;
        self.replica = Some(connection);
        Ok(())
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
async fn authenticate_backend(
    connection: &mut SinkConnection,
    user: &str,
    database: &str,
    password: &str,
) -> Result<()> {
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

    loop {
        let mut responses = vec![];
        connection.recv_into(&mut responses).await?;
        for response in &mut responses {
            let Some(Frame::Postgres(PostgresFrame::Response(messages))) = response.frame() else {
                continue;
            };
            for message in messages.iter() {
                match message {
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
                        bail!(
                            "PostgresSinkCluster can only originate replica connections with trust or cleartext password auth; \
                             this backend requested md5/SCRAM (a follow-up). Configure the backend with password auth or use PostgresSinkSingle."
                        );
                    }
                    BackendMessage::ErrorResponse { .. } => {
                        bail!(
                            "PostgresSinkCluster backend authentication failed: {}",
                            message.error_message().unwrap_or("unknown error")
                        );
                    }
                    BackendMessage::ReadyForQuery { .. } => return Ok(()),
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

    let mut responses = vec![];
    loop {
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
