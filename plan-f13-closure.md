# F13 streaming response trains — closed

Steps 2 through 6 are done and cold-re-verified on an independent rig. Branch
`f13-step6-stream-by-default` @ `6601aa34` on the **fork**
(`github.com/xtpclark/shotover-proxy`); each step sits on the one before it.

| step | branch | what it did |
|---|---|---|
| 2 | `f13-step2-chunked-trains` | the codec emits an in-progress train as partial chunks |
| 3 | `f13-step3-transform-contract` | `accepts_partial_responses`, chain validation, per-transform audit |
| 4a | `f13-step4a-incremental-forwarding` | chunks reach the client as they arrive, not at the end |
| 4b | `f13-step4b-backpressure` | both response queues bounded, so a slow client stalls the backend |
| 5 | `f13-step5-streaming-redaction` | redaction works across chunk boundaries |
| 6 | `f13-step6-stream-by-default` | `stream_threshold_bytes` defaults to 1 MiB |

## Where the numbers stand

All on a 442 MB result unless stated. **The authoritative copy of this table is the doc comment on
`PostgresDecoder::stream_threshold_bytes`** — it is quoted here for convenience and should not be
edited independently.

| configuration | peak |
|---|---|
| `stream_threshold_bytes: 0` (whole trains) | 2748 MB |
| the shipped default, fast client | 74–84 MB (53 MB on the reviewer's step 6 run) |
| the shipped default, cluster sink | 64 MB |
| slow client (~4 MB/s), no source bound | 458 MB |
| slow client, `response_buffer_batches: 4` | 95 MB |
| redaction chain (313 MB result, 10M rows) | 156 MB, against 1949 MB unstreamed |
| two concurrent 442 MB results | 175 MB |

**Beware 740–836 MB.** It is the step-2 intermediate — codec chunking before responses were
forwarded incrementally — and an earlier version of this document listed it as the "before F13"
figure directly above a row saying threshold 0 was 2746 MB. That contradiction propagated the wrong
baseline into eleven sites, understating the win by 3.5x and under-sizing anyone who opts out. It is
not the cost of buffering.

Latency: no percentile regressed at either threshold, with or without redaction (pgbench, 16 clients,
20 s, prepared, release + jemalloc; TPC-B p99 34.06 ms at `0` against 32.82 ms at 1 MiB, SELECT-only
0.67 against 0.55 ms). A result under the threshold never chunks, so the hot path is byte-identical.

Behavioural evidence, not just numbers: a backend killed mid-result now delivers ~3.1M rows where
whole-train buffering delivered none, and under a slow client the backend session sits in
`ClientWrite` — the backpressure reaches PostgreSQL rather than relocating between shotover's own
buffers.

## Carried forward

**1. The read cache's pending-miss map is per chain run.** `cache_on_response` is a local, and since
4a a streamed result's tail arrives in a LATER run, so the tail is never matched: the read is a miss
and the decision not to store it is never reached. This also stops a NON-chunked response that lands
in a later run (a pipelined `[large; small]`) from being cached at all. Making the map
per-connection, keyed by request id and removed on the id-carrying response, fixes both. It changes
what gets cached, so it needs its own verification and its own step. The analysis is in the
`read_cache` module doc so it does not have to be rediscovered.

**2. Kafka rests on argument, not measurement.** Valkey, cassandra 4.1.12 and opensearch 2.19.6 were
all measured through the proxy and identical to direct. Kafka was not — no rig, and the source config
needs a broker plus `shotover_nodes` wiring nobody wanted to guess at. The argument is that the
default 10,000-batch bound equals its previous effective behaviour and the diff touches nothing on
its path beyond the channel type. That held for the three that were measured; it is still not a
measurement.

**3. `cargo clippy --workspace --all-features --all-targets` has been run by nobody.** It needs
`cmake` AND `libcurl-devel` (librdkafka 2.12 includes `curl/curl.h` unconditionally in
`rdkafka_conf.c` despite `-DWITH_CURL=0`). What IS clean on both machines, exit statuses captured:
`-p shotover --all-features --all-targets`, and `--workspace --all-targets` both at default features
and with `shotover-proxy/alpha-transforms,jemalloc`. On a host with openssl-devel,
`OPENSSL_NO_VENDOR=1` is the zero-install way to run the workspace variants. What remains unlinted is
only the two `*-cpp-driver-tests` cfgs in `test-helpers` — nothing in a shipping path.

**4. Deliberately not done, from 4a:** moving the sink's idle timeout into `reader_task`'s watchdog,
and deleting `outstanding` in favour of `SinkConnection::pending_requests_count()`. Both are
refactors of pre-existing shared connection machinery.

**5. Parked from 4b:** a separate `client_write_timeout`, or a byte-derived/semaphore budget, instead
of reusing the source idle `timeout` for both "client sent nothing" and "client did not read one
batch". The second meaning implies a minimum read rate — at a 1 MiB threshold and `timeout: 30`, a
client must sustain ~280 KB/s mid-result — which is documented but is a real operational surprise.

## What flipping the default breaks

`accepts_partial_responses` defaults to `false`, so a postgres chain containing `Tee`,
`DebugPrinter`, `DebugForceParse`, `DebugReturner`, a sink inside a `ConnectionBalanceAndPool`
sub-chain, **or any custom transform** refuses to start until the sink sets
`stream_threshold_bytes: 0`. Custom transforms are the wide one: the method did not exist before this
release, so nothing written against 0.7 can have overridden it. This is in the changelog.

Shotover now validates the topology before requesting a hot reload handoff, so a binary that refuses
its topology fails while the running instance is still serving rather than after it has given up its
listeners. Chain-shape errors (terminating/non-terminating, protocol mismatch) still come from
`source.build`, which creates listeners, so they are NOT covered — splitting those out is a larger
refactor.
