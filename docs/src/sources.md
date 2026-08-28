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
