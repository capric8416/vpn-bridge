# QUIC proxy

`proxy-client` and `proxy-server` are a separate cross-platform proxy pair. They do not replace
`vpnbridge-host` or `vpnbridge-vm`.

## Transport model

- The client prefers UDP/QUIC and automatically falls back to encrypted gRPC over TCP when QUIC
  cannot connect or open a stream.
- By default QUIC and gRPC use the same configured IP and port number: UDP for QUIC and TCP for
  gRPC. Optional per-transport addresses can assign different ports.
- Every TCP or UDP flow uses one bidirectional QUIC stream or one bidirectional gRPC call.
- TCP bytes are copied directly over the stream.
- UDP datagrams use the existing two-byte length framing inside the reliable transport stream.
- After falling back, new flows use gRPC immediately until `reconnect_interval_ms` expires; the
  next flow probes QUIC again. If gRPC fails first, the client retries QUIC immediately.
- There is no unencrypted TCP fallback and no use of unreliable QUIC datagrams.
- TLS uses a server-generated self-signed certificate. The client trusts only the configured
  certificate for both QUIC and gRPC, and every stream also carries and validates the configured
  token.

## Build

```bash
cargo build --release -p proxy-server -p proxy-client
```

The independent `proxy release` workflow publishes Linux, Windows, and macOS archives only when
`crates/proxy-client` or `crates/proxy-server` changed since the previous tag. Every platform
archive contains both client and server binaries, with `proxy-client.toml` and `proxy-server.toml`
beside them.

On Windows, put the architecture-matched `wintun.dll` next to `proxy-client.exe`. Creating a TUN
and changing routes requires Administrator privileges. Linux requires root or `CAP_NET_ADMIN`;
macOS requires root.

## Configure and run

1. Copy `config/proxy-server.toml` to the server and replace the token.
2. Start the server once. If both configured PEM files are absent, it creates a self-signed
   certificate and a private key. On Unix, the private key is created with mode `0600`.
3. Copy only `proxy-server-cert.pem` to the client, alongside `config/proxy-client.toml`.
4. Put the same token in the client configuration and set the server IP and proxy routes.
5. Allow both UDP and TCP on the server's configured listen port through its firewall. UDP carries
   QUIC and TCP carries the gRPC fallback.

For transport-specific testing, both programs support independent switches and addresses:

```toml
# proxy-client.toml
quic_enabled = true
grpc_enabled = true
quic_server = "192.168.122.57:17443"
grpc_server = "192.168.122.57:17444"
```

```toml
# proxy-server.toml
quic_enabled = true
grpc_enabled = true
quic_listen = "0.0.0.0:17443"
grpc_listen = "0.0.0.0:17444"
```

Set `quic_enabled = false` to force gRPC/TCP, or `grpc_enabled = false` to test QUIC only. At least
one transport must remain enabled. If an override is omitted, that transport uses the legacy
`server` or `listen` value, so existing configuration files remain valid.

```bash
proxy-server --config proxy-server.toml --check
proxy-server --config proxy-server.toml

proxy-client --config proxy-client.toml --check
sudo proxy-client --config proxy-client.toml
```

`--config`/`-c` is optional. Without it, each program first looks for `proxy-server.toml` or
`proxy-client.toml` in the current directory, then next to its executable.

The `server_name` values must match. The proxy server IP must not be inside any client proxy route,
otherwise the tunnel would capture itself; configuration validation rejects this case. Routes are
installed with `ip` on Linux, `route` on macOS, and `netsh` on Windows, then removed on graceful
shutdown.

The current client configures only IPv4 on its TUN, so configured proxy routes are intentionally
limited to IPv4. ICMP and other non-TCP/UDP traffic is dropped.
