# PostgreSQL deployment: when you need pgbouncer, and when you do not

Audience: operators deploying [`PostgresSinkSingle`](../transforms.md#postgressinksingle) or
[`PostgresSinkCluster`](../transforms.md#postgressinkcluster). The numbers below were measured on a
review rig (postgres:18 primary + streaming standby, pgbouncer 1.25, traefik 3.7.12) and are indicative,
not a benchmark of your hardware.

## The one-line answer

Shotover holds **one backend connection per client connection**. If your problem is *how many* backend
connections exist or *how expensive* each new one is, put pgbouncer between shotover and each PostgreSQL
node. If your problem is routing, redaction, failover, cancellation, rate limiting, or read throughput,
shotover alone is the better tool and pgbouncer would only cost you throughput.

## Decision table

| Your situation | Deploy | Why |
|---|---|---|
| Fewer than ~200 client connections per node, long-lived sessions (app servers with their own client-side pool) | **shotover only** | No connection pressure. pgbouncer would cut write TPS ~45% and read TPS ~2-4x for nothing. |
| Thousands of client connections (serverless functions, per-request connections, many small workers) | **shotover -> pgbouncer per node** | On the rig 60 idle clients collapsed to 1 backend; PostgreSQL forks a process per connection and degrades past a few hundred. |
| Connect-heavy workload (short-lived connections, connect+query per request) | **shotover -> pgbouncer** | connect+query 7.8 ms -> 3.1 ms through shotover with the pooler in front; pgbouncer hands out a warm server connection instead of forking. |
| Read-heavy, throughput-bound | **shotover only**, reads offloaded to replicas | shotover is multithreaded: ~48k read tps vs ~24k through single-threaded pgbouncer on the same box. Point read-heavy chains at bare replicas. |
| Write-heavy, throughput-bound | **shotover only** | ~2,027 TPC-B tps direct vs ~1,183 through pgbouncer; a bigger pool does not help (pgbouncer's per-transaction overhead). |
| Backends are `scram-sha-256` only and you need the read/write split | **shotover -> pgbouncer** | The cluster sink cannot originate SCRAM replica connections today; direct, reads fall back to the primary. pgbouncer facing shotover with `auth_type=plain` does the SCRAM to PostgreSQL. |
| Clients rely on session state across transactions (`SET search_path`, temp tables, SQL `PREPARE`, `LISTEN`, advisory locks, cursors) | **shotover only**, or pgbouncer in `pool_mode=session` | Transaction pooling leaks/loses that state; on the rig a second client saw another client's `search_path`, temp table row and prepared statement. Shotover's session pinning cannot see the pooler swap. Session mode keeps the warm-connection benefit but not multiplexing. |
| Multi-tenant with per-connection `search_path`/`role` | **shotover only**, transaction pooling forbidden | Same leak, but now it is cross-tenant data. |
| You need more than one shotover instance (HA of the proxy layer) | **traefik >= 3.7 (TCP, health-checked) or HAProxy in front of shotover** | Orthogonal to pooling. traefik < 3.7 has no TCP health check and keeps sending connections to a dead instance. |

## Reference topologies

### Shotover only (default)

```text
clients -> shotover PostgresSinkCluster -> primary
                                       -> replica(s)
```

Use `read_timeout_ms`, `preferred_replicas`, `replica_health_cooldown_ms`, `replica_users` as documented
on [PostgresSinkCluster](../transforms.md#postgressinkcluster). Replica auth: trust or cleartext (over
sink TLS) until SCRAM origination ships.

### Shotover with a pooler per node (connection pressure)

```text
clients -> shotover PostgresSinkCluster -> pgbouncer(node A) -> primary
                                       -> pgbouncer(node B) -> replica
```

Rules that make this work (each one was needed on the rig):

- **One pooler per node**, never one pooler in front of the cluster: shotover must still see distinct
  primary/replica endpoints for `pg_is_in_recovery()` probing, fencing (`pg_stat_wal_receiver`), and
  cancel routing. The contact points are the poolers.
- pgbouncer `auth_type = plain` (or `trust`) on the side facing shotover, over TLS or loopback; the
  pooler's `auth_file` holds the SCRAM-capable secrets; PostgreSQL keeps `scram-sha-256`.
- `pool_mode = transaction` only for chains whose clients are stateless across transactions; otherwise
  `session`. Mixed fleets: two shotover chains on two ports, one per pooler mode.
- pgbouncer >= 1.21 with `max_prepared_statements` set, so drivers using protocol-level prepared
  statements (pgjdbc, npgsql, psycopg3, pgx) work; SQL-level `PREPARE` still leaks between clients.
- `ignore_startup_parameters = extra_float_digits,options` or the pooler rejects some drivers' startup
  packets. (Shotover's read cache latches OFF on `options` and keys on the rendering GUCs, so it is safe
  either way.)
- Size `default_pool_size` per node to the write concurrency; expect ~45% lower write TPS than direct.
- Failover: pgbouncer closes clients when its server login keeps failing, which shotover's probe reads as
  unreachable and re-probes; and a class-08 error to shotover's probe query is also treated as
  unreachable, so failover does not depend on the pooler's disconnect behaviour.
- `server_reset_query_always = 1` if you cannot rule out session-state statements and still want
  transaction mode; it costs a `DISCARD ALL` per transaction and does not isolate temp tables inside a
  transaction.

### Mixed: pooler for the write path, bare replicas for reads

```text
clients -> shotover PostgresSinkCluster -> pgbouncer(node A) -> primary
                                       -> replica B (bare)
                                       -> replica C (bare)
```

Contact points may mix poolers and bare nodes. This gets the connect-cost benefit where connections churn
(the primary) and shotover's multithreaded read throughput on the replicas. Replica auth then needs trust
or cleartext on the bare nodes.

### Proxy-layer HA

```text
clients -> traefik 3.7+ (TCP router, healthCheck interval 2s) -> shotover A
                                                              -> shotover B
```

Each shotover instance is independent (its own topology cache and cancel registry). A cancel sent by a
client must reach the instance that holds that session's key; with a TCP balancer this is not guaranteed,
so either use source-IP sticky sessions on the balancer, or accept that cancels from a different instance
only reach the primary by key passthrough (which works, since the client's key is the primary's) and not
the replica.

## Things pgbouncer does NOT fix

- **Whole-train buffering.** Shotover assembles each response in memory (roughly several times its wire
  size, retained by the allocator). Large results cost the same with or without a pooler.
- **Extended-protocol per-message cost.** Un-prepared extended-protocol queries are markedly slower than
  simple queries; prepared mode recovers most of it. A pooler adds its own cost on top.
- **Read-your-writes across the split.** A read after a write may hit a lagging replica; wrap it in a
  transaction to pin to the primary. Unchanged by pooling.
- **Session-state semantics.** Pooling only makes these worse; see the decision table.

## Quick self-check before choosing

1. Count client connections per node at peak. Under ~200 and stable: shotover only.
2. Measure connect rate. Above ~100 connects/s/node: add the pooler.
3. Grep application code for `SET`, `PREPARE`, `CREATE TEMP`, `LISTEN`, `pg_advisory`, `DECLARE`. Any hit:
   session mode, or no pooler for that chain.
4. Check backend auth. SCRAM-only and you need replica reads today: pooler.
5. If you add the pooler, re-run your write benchmark; budget ~45% lower write TPS or a bigger primary.
