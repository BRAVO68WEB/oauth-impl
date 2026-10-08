# Deploy

This page is how you run oauth-impl. Keys and defaults are in
[Configuration](CONFIG.md). The data layout is in
[Infrastructure](INFRA.md).

## Start the process

From the repository root:

```bash
just run
```

`just run` executes `go run cmd/oauth-server/main.go`. With no
`config.yaml` in the working directory, the server listens on
`http://localhost:8080`. When `config.yaml` is present, that file sets
the host, port, and TLS.

```bash
just dev                 # reload on save, requires air
just build               # bin/oauth-server, bin/oauth-cli, bin/oauth-mobile
./bin/oauth-server
go run cmd/oauth-server/main.go --port 9090
go run cmd/oauth-server/main.go --config /etc/oauth/config.yaml
go run cmd/oauth-server/main.go --db /var/lib/oauth/oauth.db
```

`--port` overrides `server.port`. `--db` overrides `database.path`. A
missing file passed to `--config` exits. An empty `--config` still loads
`./config.yaml` when that file exists.

Run the server from the project root. Startup reads
`internal/hashalgo/algo.go` and refuses to serve when that file differs
from the binary.

`GET /health` returns `{"status":"ok"}`.

## TLS

Set `server.tls.enabled` and point `cert_file` and `key_file` at the
certificate and key. Client certificates use `client_ca`, `client_auth`
(`require_and_verify`, `require`, `request`, or `none`), and `crl_file`.
A missing client CA is fatal when TLS client auth is configured. A
missing CRL is a warning.

`scripts/cert.sh` writes a local CA and server certificate under
`certs/` and replaces `config.yaml` with a TLS example on port 8443.
Use it on a fresh checkout. When you already have a config, set the TLS
paths yourself. `scripts/cert.sh --force` regenerates the certificates.
`certs/` is gitignored.

## Reverse proxy

Set `security.issuer` and `oidc.issuer` to the public `https` URL. The
browser and discovery documents use that issuer.

The client IP recorded for login analytics is the TCP peer. List the
proxy in `security.trusted_proxies` as CIDR blocks, for example
`10.0.0.0/8`, when the server sits behind a proxy. Only then are
`X-Forwarded-For` and `X-Real-IP` read. A forwarded address that is
itself inside that list is skipped.

## Postgres

SQLite is the default. For Postgres:

```yaml
database:
  driver: postgres
  dsn: postgres://oauth:oauth@localhost:5432/oauth?sslmode=disable
  migrations: true
```

`database.path` is unused when the driver is `postgres`. Integer flags
are stored as `0` and `1`.

## Redis

Leave `redis.addr` empty to keep the approval queue, CIMD documents, and
DPoP replay in the process. Set the address and switch the consumers you
want to share:

```yaml
redis:
  addr: localhost:6379
  prefix: oauth
queue:
  type: redis
cache:
  provider: redis
```

`addr` is `host:port` or a `redis://` URL. Users, sessions, tokens,
consents, and audit stay in SQL. More than one server process shares
queue and cache state only when those settings are `redis`.

## SMTP

Password reset, email confirmation, and login mail send when
`smtp.enabled` is true. With SMTP off, forgot-password returns
`503` and `mailer_disabled`. An operator can still set a password with
`oauth-cli user password` or `POST /api/users/{id}/password`. Login
still succeeds when a send fails.

Message text is in [Configuration](CONFIG.md).

## Traces

Traces stay off unless `telemetry.enabled` is true. The server then
exports OTLP over HTTP to `telemetry.otlp_endpoint`. Enabling traces
with an empty endpoint is a startup error. Spans omit tokens, codes,
secrets, and `Authorization`.

## Related

[Configuration](CONFIG.md) lists every key.
[CLI](CLI.md) is how you manage the running server.
