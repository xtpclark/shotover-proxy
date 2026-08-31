# Adversarial review — PostgreSQL support for Shotover

**Branch:** `postgres-support` @ `39393e2f` (base `5be0561c`, +~5.6k lines)
**Reviewer scope:** codec pairing, frame model + `analyze_sql`, the four postgres transforms, and shared plumbing.
**Verdict:** the protocol state machine and the fuzz/panic surface are solid, but there are two serious
correctness/safety holes (redaction bypass, cluster mis-route) and a connection-exhaustion DoS that are
each reachable today.

## How this was verified

Built the `shotover-proxy` binary on the pinned Rust 1.98.0 toolchain and ran live rigs under Podman:

- A single `postgres:18` behind `PostgresSource -> PostgresRedactColumn -> PostgresSinkSingle`.
- A **real streaming-replication primary+standby pair** (`pg_basebackup`, `standby.signal`, WAL streaming
  confirmed) behind `PostgresSource -> PostgresSinkCluster`.

Drove both with real `psql` and with hand-written protocol frames over raw sockets to control TCP batching
exactly. Every finding marked **CONFIRMED** was reproduced end-to-end through the running proxy.

Baseline health checks that passed: `cargo nextest`/`cargo test` unit tests (147) green; `cargo clippy
--features postgres,alpha-transforms -- -D warnings` clean; no panic under a hostile-input barrage (TLS
ClientHello, negative/huge/short startup lengths, malformed cancel, tagged-before-startup) — the proxy kept
serving; and no deadlock on the buffered-Parse-then-simple-Query shape (the server flushes and `exchange`
balances).

---

## Findings

| # | Severity | Area | One line |
|---|----------|------|----------|
| 1 | Critical | Redaction | Any output-column alias/expression leaks the protected value |
| 2 | High | Cluster routing | A statement's Parse and Execute split across replica/primary → stranded response + spurious error |
| 3 | High | Source / DoS | A stalled half-startup holds a connection permit forever |
| 4 | Medium | Redaction | Fail-closed desyncs client vs. server transaction state |
| 5 | Medium | Redaction | Per-statement/portal state maps grow unbounded |
| 6 | Low | Source | Repeated `Failed to parse frame` log lines per bad frame |

---

### 1. CRITICAL — `PostgresRedactColumn` leaks the protected value under any alias or expression

**Location:** `shotover/src/transforms/postgres/redact_column.rs:287`
`let resolved = match fields.iter().position(|f| f.name == self.column) { ... }`

Redaction is keyed on the **result column label** carried in `RowDescription`, which is entirely
client-controlled. Rename the column with `AS`, or wrap it in any expression, and its label no longer
equals the configured name, so the shape resolves to `Absent` and the real value passes through. This
contradicts the transform's own contract ("It is a security control, so it fails **closed** … never …
leak an unredacted value").

**Reproduced live** (`column: "ssn"`, `replacement: "[REDACTED]"`, single sink, real `psql`):

```
select id, ssn        from patients -> 1|[REDACTED]   2|[REDACTED]     redacted
select id, ssn AS x   from patients -> 1|111-22-3333  2|444-55-6666    LEAK
select id, ssn||''    from patients -> 1|111-22-3333  2|444-55-6666    LEAK
select *              from patients -> 1|[REDACTED]|alice ...          redacted
```

The alias leak reproduces identically through the extended protocol (Parse/Bind/Describe/Execute/Sync).
A related case: two output columns both labelled `ssn` (`select ssn, other AS ssn from t`) → only the
first is redacted, the second leaks (`position` returns the first match).

This is not only an attacker bypass: ordinary queries wrapping the column (`coalesce(ssn,'')`,
`substring(ssn,1,4)`, a cast, a view that renames it) silently leak. Marked critical because the control's
sole purpose — never emit the value — fails on trivial, common inputs.

**Suggested direction:** matching by client-chosen output label cannot be made safe. Redaction needs an
identity the client can't rename — e.g. resolve by `(table_oid, column_attribute_number)` from
`RowDescription` (redact any output column that originates from the target table column, regardless of
label), and treat a computed/opaque column derived from it as unredactable → fail closed. At minimum,
document loudly that this matches output labels only and is trivially bypassable, and reconsider calling it
a security control.

---

### 2. HIGH — Cluster router splits a statement's Parse (replica) from its Execute (primary)

**Location:** `shotover/src/transforms/postgres/sink_cluster.rs:267` (`decide_target`) together with
`shotover/src/transforms/postgres/mod.rs:46` (`trailing_unanswerable`).

`decide_target` lets a batch open a **replica** unit whenever it contains any self-terminating message
(`is_self_terminating` = "has a Sync or a simple Query"). But `exchange`/`trailing_unanswerable`
deliberately leave every message **after the last flush point** outstanding. So a coalesced read pipeline
whose flush point is not last is sent to the replica *and* strands its trailing Parse/Bind/Execute there;
the continuation, arriving in the next batch with no "deciding read", defaults to the **primary**, where
that statement/portal does not exist.

The comment at `sink_cluster.rs:270-275` — "Only such a batch may open a replica unit: it drains fully
within one exchange() call … so a replica unit never spans batches" — is false for this shape.

**Reproduced live** against the replication pair, one pipelined client, batched by TCP as normal load does:

```
BATCH 1 (single write): Parse(""), Bind, Describe, Execute, Sync, Parse("")   # trailing Parse
   -> served by the REPLICA (row shows pg_is_in_recovery = 't')
   -> the trailing Parse (the unnamed statement for "cycle 2") is stranded on the replica
BATCH 2 (next write):   Bind(""), Execute, Sync                               # continuation
   -> routed to the PRIMARY
   -> ErrorResponse("unnamed prepared statement does not exist")
```

The **identical byte stream against a single Postgres returns the row normally** (verified: BATCH 2 ->
`ParseComplete, BindComplete, DataRow['c2'], CommandComplete, ReadyForQuery`). So this is a cluster-only
regression, triggered purely by where the TCP batch boundary falls — no misbehaving client. It breaks
invariant #1 (the trailing Parse's `ParseComplete` is stranded on the replica and `outstanding_replica` is
left elevated) and invariant #4 (Execute sent to a node lacking the statement). If the primary's unnamed
slot happens to hold a stale statement, the Execute would silently return the wrong rows instead of erroring.

A simpler instance reproduces the same class: `[Parse("",...), Sync]` opens a replica unit, then a later
`[Bind(""), Execute, Sync]` reusing the still-live unnamed statement routes to the primary and errors.

**Suggested direction:** only open a replica unit for a batch that ends *at* its flush point with nothing
trailing (i.e. `trailing_unanswerable == Some(0)`), not merely "contains a flush point". Alternatively, pin
a session to the node where its unnamed/una-`Close`d statement currently lives until that statement is
re-Parsed or Closed.

---

### 3. HIGH — Stalled half-startup holds a connection permit forever (connection-exhaustion DoS)

**Location:** `shotover/src/codec/postgres.rs:44-98` (`source_prologue`), `shotover/src/source_task.rs`
handshake path.

`CLIENT_STARTUP_TIMEOUT` (10s) bounds only the first 8-byte `read_exact` of the startup header. Once those
8 bytes arrive, `source_prologue` returns and the codec blocks reading the rest of the startup body — with
no timeout, unless the optional source `timeout` config is set (it is unset by default).

**Reproduced live:** opened 5 connections that send an 8-byte startup header announcing a 100-byte packet
and then send nothing → **5/5 still held open after 13s** (past the 10s window). At the default
`connection_limit` of 512, 512 such 8-byte connections exhaust the source and lock out every legitimate
client. The comment on `CLIENT_STARTUP_TIMEOUT` ("a client that connects and sends nothing would hold a
connection permit forever" — implying it prevents that) is defeated by sending 8 bytes then nothing.

Corollary: an oversized startup length (`> MAX_STARTUP_PACKET_LENGTH`) that `message_wire_length` would
reject is never even decoded, because the seeded buffer isn't parsed until more bytes arrive — so the
length cap is bypassed for the hang.

**Suggested direction:** apply an overall deadline to the whole startup handshake (header **and** body),
not just the first read — e.g. wrap the seed-then-first-decode in the same `CLIENT_STARTUP_TIMEOUT`, or
give the source a sensible default `timeout`. Also decode the seeded prologue bytes immediately so an
over-cap startup length is rejected without waiting for more input.

---

### 4. MEDIUM — Redaction fail-closed desyncs client vs. server transaction state

**Location:** `shotover/src/transforms/postgres/redact_column.rs:168-206`.

When the redactor fails closed on an extended-protocol `Execute` (e.g. `Bind`/`Execute` of a statement that
was never `Describe`d in this connection — a valid pattern, also hit for statements with **no** sensitive
column), it injects an `ErrorResponse` but the server's transaction is untouched.

**Reproduced live**, inside a transaction:

```
begin                              -> ReadyForQuery(T)
Parse + Bind + Execute + Sync      (no Describe)
   -> BindComplete,
      ErrorResponse("PostgresRedactColumn: ... row shape unknown"),
      ReadyForQuery(T)             # a real PG sends ReadyForQuery(E) after an in-txn error
select 42                          -> succeeds, ReadyForQuery(T)   # PG would say "txn aborted"
commit                             -> COMMIT, ReadyForQuery(I)     # the txn commits anyway
```

The client sees an error, but the trailing `ReadyForQuery` reports `T`, not the `E` Postgres always sends
after an in-transaction error. A driver that trusts the error rolls back work the server would have
committed; a driver that trusts the status commits a transaction with the "failed" statement silently
missing. The two ends disagree about what happened. (Separately, this makes SQL `PREPARE` + extended
`Execute`, and any Bind/Execute-without-Describe, fail even for queries that have no sensitive column.)

**Suggested direction:** when failing closed inside an extended-protocol exchange, drive the connection into
a state consistent with what the client will see — i.e. ensure the client's next `ReadyForQuery` reports the
error (`E`) state, or fail the whole pipeline coherently rather than substituting one message. Also consider
whether "executed without a Describe" should really fail closed for statements whose result cannot contain
the target column.

---

### 5. MEDIUM — Redaction per-statement/portal state grows unbounded

**Location:** `shotover/src/transforms/postgres/redact_column.rs` — inserts at `:220-227` (Bind) and
`:293`/`:301` (shape learned); eviction only at `:217` (re-Parse) and `:248-253` (protocol Close).

`portal_statements` and `statement_shapes` are cleared only on an explicit protocol `Close` or a re-`Parse`
— never at transaction end (where Postgres itself drops non-holdable portals) or on connection idle. A
client that `Bind`s distinct portal names, or `Parse`s distinct named statements, without `Close` grows
these `HashMap`s without bound → per-connection memory growth on a long-lived pooled connection.
(Confirmed by code inspection; the memory-exhaustion endpoint was not run.)

**Suggested direction:** drop non-holdable portals from `portal_statements` on a `ReadyForQuery` that ends a
transaction, mirroring the server's own portal lifecycle; bound or LRU the maps.

---

### 6. LOW — Repeated `Failed to parse frame` log lines per bad frame

A single malformed frame emits `ERROR shotover::message: Failed to parse frame` ~4× per connection
(observed on the cluster sink, connection ids 7–8). Minor log-flood surface, and it suggests the failed
frame is re-parsed several times rather than once.

---

## What held up (verified, no defect)

- **No panic on hostile input (invariant #3).** TLS ClientHello, negative/huge/short startup lengths,
  malformed cancel, tagged-before-startup — all handled without a crash; the proxy answered a query
  immediately after the barrage. A parser fuzz (every tag × truncated/overflow bodies, all three parse
  directions) also produced no panic. Malformed messages degrade to `Raw` and round-trip; bad framing
  errors rather than panics.
- **No deadlock on buffered-Parse-then-simple-Query.** The server flushes the buffered `ParseComplete` when
  it processes the simple `Query`, and `exchange`'s `outstanding` accounting balances — the client received
  both responses.
- **Byte-faithful passthrough of untouched columns** (`select *` redacts `ssn`, leaves other columns intact).
- **Cluster read/write split** routes reads to the replica (`pg_is_in_recovery()='t'`) and writes to the
  primary (`'f'`); topology probing is correct.
- **Headline claims** ("147/147 tests, clippy clean") reproduced on a clean toolchain for
  `-p shotover --features postgres,alpha-transforms`.

## Not covered

- Full feature-powerset clippy and the `postgres_int_tests` integration harness.
- Finding 5's actual memory-exhaustion endpoint (code-confirmed only).
- Whether Finding 2 can be steered into *silent wrong rows* rather than the error reproduced here — that
  depends on the primary's unnamed-statement slot at that instant; the error path is confirmed, the
  wrong-row path is reasoned.
