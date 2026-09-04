# Sources

## Listener retry behavior

At startup, if a source fails to bind its `listen_addr`, Shotover startup fails.
At runtime, once a source is already running, transient listener and accept failures are retried 
forever with capped exponential backoff (1s, 2s, 4s, ... up to 64s) instead of shutting down Shotover.

Use `shotover_connections_accept_failures_count` to detect accept retry failures and `shotover_listener_create_failures_count` to detect runtime listener creation retry failures.

| Source                              | Implementation Status |
|-------------------------------------|-----------------------|
|[Cassandra](#cassandra)              |Beta                   |
|[Postgres](#postgres)                |Alpha                  |
|[Valkey](#valkey)                    |Beta                   |

## Cassandra

```yaml
Cassandra:
  # The address to listen from.
  listen_addr: "127.0.0.1:6379"

  # The number of concurrent connections the source will accept.
  # If not provided defaults to 512
  connection_limit: 512

  # Defines the behaviour that occurs when Once the configured connection limit is reached:
  # * when true: the connection is dropped.
  # * when false: the connection will wait until a connection can be made within the limit.
  # If not provided defaults to false
  hard_connection_limit: false

  # When this field is provided TLS is used when the client connects to Shotover.
  # Removing this field will disable TLS.
  #tls:
  #  # Path to the certificate file, typically named with a .crt extension.
  #  certificate_path: "tls/localhost.crt"
  #  # Path to the private key file, typically named with a .key extension.
  #  private_key_path: "tls/localhost.key"
  #  # Path to the certificate authority file, typically named with a .crt extension.
  #  # When this field is provided client authentication will be enabled.
  #  #certificate_authority_path: "tls/localhost_CA.crt"
 
  # Timeout in seconds after which to terminate an idle connection. This field is optional, if not provided, idle connections will never be terminated.
  # timeout: 60

  # The transport that cassandra communication will occur over.
  # TCP is the only Cassandra protocol conforming transport.
  transport: Tcp

  chain:
    Transform1
    Transform2
    ...
```

## Postgres

```yaml
Postgres:
  # The address to listen from.
  listen_addr: "127.0.0.1:15432"

  # The number of concurrent connections the source will accept.
  # If not provided defaults to 512
  connection_limit: 512

  # Defines the behaviour that occurs when Once the configured connection limit is reached:
  # * when true: the connection is dropped.
  # * when false: the connection will wait until a connection can be made within the limit.
  # If not provided defaults to false
  hard_connection_limit: false

  # How many batches of responses may queue for the client before the transform chain waits for it
  # to catch up. If not provided the limit is one no source could reach before streaming existed,
  # which is how every source behaves by default.
  #
  # Only worth setting alongside `stream_threshold_bytes` on a postgres sink. With streaming on, a
  # client that reads slowly otherwise accumulates the whole result in this queue, because the chain
  # hands responses to the writer and returns rather than waiting for the socket. Bounding it makes
  # the chain wait, which stops it draining the backend, which lets TCP stall the backend — so a
  # slow client costs a bounded amount of memory instead of the whole result.
  #
  # Sizing: a queued batch can hold a whole sink queue's worth of chunks (8), and two more are in
  # flight in the writer task and the chain, so the buffers come to about
  # (response_buffer_batches + 2) * 8 * stream_threshold_bytes. Add the client socket buffer and
  # allocator slack and budget roughly double: measured peak RSS with 4 and a 1 MiB threshold is
  # 95 MB for a 442 MB result, against 458 MB unbounded.
  #
  # That figure is for a chain that forwards chunks without reading them. A transform that inspects
  # every chunk — PostgresRedactColumn is the only one — parses and re-encodes it, which holds the
  # decoded frame and the re-encoded output alongside the original bytes. That cost applies only to
  # the chunks in flight, and they are freed as they are written, so it roughly DOUBLES the peak
  # rather than scaling with the result.
  #
  # Measured, release build with jemalloc, 10,000,000 rows of (id, ssn) = 313 MB on the wire:
  # redaction at a 1 MiB threshold peaked at 156 MB; the same chain with streaming off peaked at
  # 1949 MB.
  #
  # Cost: a client that stops reading entirely stalls its own requests, exactly as it would talking
  # to postgres directly. Such a connection parks the chain outside the loop that re-arms the idle
  # timeout, so `timeout` is what reclaims it — setting this without `timeout` is refused at startup.
  #response_buffer_batches: 4

  # When this field is provided TLS is used when the client connects to Shotover.
  # Clients negotiate TLS through the standard postgres SSLRequest handshake.
  # When TLS is configured a client attempting a plaintext startup is refused,
  # matching a postgres server whose pg_hba requires hostssl.
  # Removing this field will disable TLS.
  #tls:
  #  # Path to the certificate file, typically named with a .crt extension.
  #  certificate_path: "tls/localhost.crt"
  #  # Path to the private key file, typically named with a .key extension.
  #  private_key_path: "tls/localhost.key"
  #  # Path to the certificate authority file, typically named with a .crt extension.
  #  # When this field is provided client authentication will be enabled.
  #  #certificate_authority_path: "tls/localhost_CA.crt"

  # Timeout in seconds after which to terminate an idle connection. This field is optional, if not provided, idle connections will never be terminated.
  # With response_buffer_batches set it also bounds how long the chain waits for a slow client, and
  # is required, because a connection parked on the full response queue cannot re-arm this timeout.
  # That implies a minimum read rate, because it bounds the wait for ONE batch of up to
  # 8 * stream_threshold_bytes: at a 1 MiB threshold and timeout 30 a client must sustain roughly
  # 280 KB/s or be disconnected mid-result. Raise it for slower consumers.
  # timeout: 60

  chain:
    Transform1
    Transform2
    ...
```

Note on responses: shotover groups the complete train of backend messages answering
one frontend message (e.g. `RowDescription, DataRow..., CommandComplete, ReadyForQuery`)
into a single shotover response message. This is what upholds shotover's
one-response-per-request invariant on the postgres protocol, and it means large result
sets are buffered in full while passing through shotover.

Authentication is passed through to the sink database: shotover holds no credentials.
cleartext, md5 and SCRAM-SHA-256 all work unmodified.

SCRAM channel binding (`SCRAM-SHA-256-PLUS`) cannot pass through when shotover terminates
TLS, because the client would bind its proof to shotover's certificate while the server
verifies against its own. This is a property of SCRAM's downgrade protection, not something
a credential-less proxy can work around. When shotover terminates TLS in front of a
channel-binding-capable server, clients must not use channel binding (libpq
`channel_binding=disable`), or the deployment must use a non-SCRAM auth method.

Note on `QueryTypeFilter` with postgres: the generic error response used when a request is
filtered ends with a `ReadyForQuery`, which is correct for the simple query protocol but desyncs
an extended-protocol client (it delivers two `ReadyForQuery` for one `Sync`). `AllowList` mode is
also unusable with postgres because non-query messages (including the startup message) classify as
`ReadWrite` and would be filtered. Use `QueryTypeFilter` on postgres only with simple-query
workloads and `DenyList` mode; protocol-state-aware error responses are a follow-up.

## Valkey

```yaml
Valkey:
  # The address to listen from
  listen_addr: "127.0.0.1:6379"

  # The number of concurrent connections the source will accept.
  # If not provided defaults to 512
  connection_limit: 512

  # Defines the behaviour that occurs when Once the configured connection limit is reached:
  # * when true: the connection is dropped.
  # * when false: the connection will wait until a connection can be made within the limit.
  # If not provided defaults to false
  hard_connection_limit: false

  # When this field is provided TLS is used when the client connects to Shotover.
  # Removing this field will disable TLS.
  #tls:
  #  # Path to the certificate file, typically named with a .crt extension.
  #  certificate_path: "tls/valkey.crt"
  #  # Path to the private key file, typically named with a .key extension.
  #  private_key_path: "tls/valkey.key"
  #  # Path to the certificate authority file typically named ca.crt.
  #  # When this field is provided client authentication will be enabled.
  #  #certificate_authority_path: "tls/ca.crt"
    
  # Timeout in seconds after which to terminate an idle connection. This field is optional, if not provided, idle connections will never be terminated.
  # timeout: 60

  chain:
    Transform1
    Transform2
    ...
```

## Kafka

```yaml
Kafka:
  # The address to listen from
  listen_addr: "127.0.0.1:6379"

  # The number of concurrent connections the source will accept.
  # If not provided defaults to 512
  connection_limit: 512

  # Defines the behaviour that occurs when Once the configured connection limit is reached:
  # * when true: the connection is dropped.
  # * when false: the connection will wait until a connection can be made within the limit.
  # If not provided defaults to false
  hard_connection_limit: false

  # When this field is provided TLS is used when the client connects to Shotover.
  # Removing this field will disable TLS.
  #tls:
  #  # Path to the certificate file, typically named with a .crt extension.
  #  certificate_path: "tls/localhost.crt"
  #  # Path to the private key file, typically named with a .key extension.
  #  private_key_path: "tls/localhost.key"
  #  # Path to the certificate authority file, typically named with a .crt extension.
  #  # When this field is provided client authentication will be enabled.
  #  #certificate_authority_path: "tls/localhost_CA.crt"

  # Timeout in seconds after which to terminate an idle connection. This field is optional, if not provided, idle connections will never be terminated.
  # timeout: 60

  chain:
    Transform1
    Transform2
    ...
```
