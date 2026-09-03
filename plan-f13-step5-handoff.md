# F13 — handoff into step 5 (streaming redaction)

Branch `f13-step4b-backpressure` @ `9b809b00` on the **fork**
(`github.com/xtpclark/shotover-proxy`). Steps 4a and 4b are DONE and cold-re-verified.

## Where the numbers stand

| scenario | before F13 | after 4a | after 4b |
|---|---|---|---|
| fast client, 442 MB result, 1 MiB threshold | 740–836 MB | 63–84 MB | 74 MB |
| **slow client (~4 MB/s)**, same result | 458 MB | 458 MB | **95 MB** |
| two concurrent 442 MB results | — | — | 175 MB |
| threshold 0 (streaming off) | 2746 MB | 2746 MB | 2746 MB |

The 4b acceptance evidence that matters most: the backend session sat in `ClientWrite` for 19
consecutive `pg_stat_activity` samples and returned to `ClientRead` only once the result drained.
The backpressure reaches PostgreSQL; it does not merely relocate between shotover's buffers.
pgbench prepared/8 clients is 1023 tps with the bound and 1023 tps without.

## Review findings

**1. `try_send` in the client reader task — FIXED in `9b809b00`.** Both
`CodecReadError::RespondAndThenCloseConnection` arms now use `send_terminal`, a bounded wait
(`TERMINAL_MESSAGE_TIMEOUT`, 5 s). It needs neither a `Shutdown` nor the source `timeout`, so
`spawn_read_write_tasks` keeps its signature and all five sources are untouched. The client gets its
error response whenever the writer is draining at all, and the reader task still cannot be stranded
when the writer is itself wedged on a non-reading client.

**2. `timeout` now means two things.** "Client sent nothing for N s" and "client did not read one
batch for N s". A batch is up to `8 * stream_threshold_bytes`, so `timeout: 30` at a 1 MiB threshold
demands ~280 KB/s of a client mid-result. Documented with the arithmetic in `sources.md` and on the
config field. A separate `client_write_timeout`, or a byte-derived/semaphore budget, is the right
follow-up and stays parked.

**3. Untested protocols — down to one.** Measured through the proxy at the default config and
identical to direct: valkey (PING/SET/GET, 50-deep pipeline), cassandra 4.1.12 (system.local, DDL, a
three-INSERT BATCH, COUNT, a 297-row system_schema.columns result), and opensearch 2.19.6 (GET /,
50 x 2 KB documents indexed, a 50-hit 104,550-byte search, /_cluster/state). Zero ERROR/WARN in the
proxy log for any of them.

**Kafka remains argument-only** — no rig, and the source config needs a broker plus `shotover_nodes`
wiring nobody wanted to guess at. The argument is that the default 10,000-batch bound equals its
previous effective behaviour and the diff touches nothing on its path beyond the channel type. That
held for the three above when measured, but it is still not a measurement.

## Still parked from 4a

Moving the sink's idle timeout into `reader_task`'s watchdog, and deleting `outstanding` in favour of
`SinkConnection::pending_requests_count()`. Both are refactors of pre-existing shared connection
machinery.

## Step 5

Streaming redaction. The reviewer is bringing the redaction recipes (label-match, fail-close on
unknown shape, the extended-protocol Describe path) plus the chunk-boundary cases from steps 2–4.

The invariant that has broken every step so far and will break this one: **partial chunks carry no
request id**, and all four accounting sites filter on `request_id().is_some()`. A redaction transform
that runs per chunk has no request to attribute a chunk to, so anything it needs to know about the
statement must come from state stamped when the request went out, not from the chunk in hand.
