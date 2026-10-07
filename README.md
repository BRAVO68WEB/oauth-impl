# OAuth Implementation Server

A comprehensive OAuth 2.0 / OpenID Connect testing server implementing all major flows and standards.

## Features

- **All OAuth 2.0 Flows**: Authorization Code + PKCE, Client Credentials, Device Code, Implicit, Hybrid
- **CIBA**: Client-Initiated Backchannel Authentication (Poll/Ping/Push modes)
- **PAR**: Pushed Authorization Requests (RFC 9126)
- **DPoP**: Demonstrating Proof-of-Possession (RFC 9449)
- **OpenID Connect**: Discovery, JWKS, UserInfo, ID Tokens
- **TOTP MFA**: Two-factor authentication with QR code enrollment
- **Session-based Auth**: Login, registration, consent, device approval, and logout pages
- **CIAM APIs**: Self-service profile, password, sessions, and login activity at `/api/me`
- **Management APIs**: Client-credentials tokens with the `management` scope
- **Back-Channel Logout**: RP-initiated logout and logout-token delivery
- **SMTP mail**: Password reset, email confirmation, and login activity
- **API Documentation**: Scalar OpenAPI UI at `/docs`
- **CLI Tools**: Management CLI and mobile polling CLI

## Quick Start

```bash
# Clone and build
git clone https://github.com/bravo68web/oauth-impl.git
cd oauth-impl

# Run the server
just run

# Or with Go directly
go run cmd/oauth-server/main.go
```

The server starts at `http://localhost:8080` when `config.yaml` is absent.
If `config.yaml` is present, `just run` uses that file, including its port
and TLS settings. Generate one with `./bin/oauth-cli init`.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      HTTP Request                           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Route Layer (internal/route/)                              │
│  - URL → Controller mapping                                 │
│  - Middleware (CORS, logging, recovery)                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Controller Layer (internal/controller/)                    │
│  - HTTP request parsing                                     │
│  - Response formatting                                      │
│  - Calls Service layer                                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Service Layer (internal/service/)                          │
│  - Business logic                                           │
│  - Token generation                                         │
│  - Validation                                               │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Repository Layer (internal/repository/)                    │
│  - SQL queries only                                         │
│  - No business logic                                        │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  SQLite Database                                            │
└─────────────────────────────────────────────────────────────┘
```

## Supported OAuth/OIDC Flows

| Flow | Endpoint | RFC |
|------|----------|-----|
| Authorization Code + PKCE | `/oauth/authorize` + `/oauth/token` | RFC 6749, RFC 7636 |
| Client Credentials | `/oauth/token` | RFC 6749 |
| Device Code | `/oauth/device` + `/oauth/token` | RFC 8628 |
| CIBA (Poll mode) | `/oauth/bc-authorize` + `/oauth/token` | OIDC CIBA |
| PAR | `/oauth/par` | RFC 9126 |
| DPoP | Token binding | RFC 9449 |
| Token Introspection | `/oauth/introspect` | RFC 7662 |
| Token Revocation | `/oauth/revoke` | RFC 7009 |
| Dynamic Registration | `/oauth/register` | RFC 7591 |
| OIDC Discovery | `/.well-known/openid-configuration` | OIDC Core |
| JWKS | `/oidc/jwks` | OIDC Core |
| UserInfo | `/oidc/userinfo` | OIDC Core |
| RP-Initiated Logout | `/oauth/logout` | OIDC RP-Initiated Logout |
| Back-Channel Logout | Client `backchannel_logout_uri` | OIDC Back-Channel Logout |

### Response Types

| Response Type | Returns | Location |
|---------------|---------|----------|
| `code` | Authorization code | Query parameter |
| `token` | Access token | Fragment |
| `id_token` | ID token | Fragment |
| `code id_token` | Code + ID token | Fragment |
| `code token` | Code + access token | Fragment |
| `code id_token token` | All three | Fragment |
| `none` | Nothing | Query (state only) |

## CLI Tools

### Management CLI (`oauth-cli`)

```bash
# Build
just build-cli

# Initialize config and the password hasher.
# init writes a management client id and secret into the config file.
./bin/oauth-cli init
./bin/oauth-cli init --mfa
./bin/oauth-cli init --hash argon2id

# Client management
./bin/oauth-cli client list
./bin/oauth-cli client create --name "My App" --redirect-uri "https://example.com/cb"
./bin/oauth-cli client get <client-id>
./bin/oauth-cli client delete <client-id>

# User management. These calls use the management client from config.yaml,
# or --client-id and --client-secret.
./bin/oauth-cli user list
./bin/oauth-cli user create --username "user" --password "pass" --email "user@example.com"
./bin/oauth-cli user password <user-id> --password "new-pass"
./bin/oauth-cli user disable <user-id>

# Webhooks. Repeat --event for each trigger, or pass --event '*'
./bin/oauth-cli webhook create --url "https://example.com/hooks" --event login --event logout
./bin/oauth-cli webhook list

# Token management
./bin/oauth-cli token list
./bin/oauth-cli token refresh list
./bin/oauth-cli token refresh revoke <id>
./bin/oauth-cli token introspect <token>
./bin/oauth-cli token revoke <token>

# MFA management
./bin/oauth-cli mfa enable --user-id <id>
./bin/oauth-cli mfa enable --user-id <id> --show-secret
./bin/oauth-cli mfa verify --user-id <id> --code 123456

# CIBA management
./bin/oauth-cli ciba pending
./bin/oauth-cli ciba approve <auth-req-id>
./bin/oauth-cli ciba deny <auth-req-id> --reason "Denied"

# Flow testing
./bin/oauth-cli flow client-credentials --client-id <id> --client-secret <secret>
./bin/oauth-cli flow device --client-id <id> --client-secret <secret>
```

### Mobile Polling CLI (`oauth-mobile`)

```bash
# Build
just build-mobile

# Poll for CIBA requests
./bin/oauth-mobile poll --server http://localhost:8080

# List pending requests
./bin/oauth-mobile list

# Approve/deny requests
./bin/oauth-mobile approve <auth-req-id> --user-id <user-id>
./bin/oauth-mobile deny <auth-req-id> --reason "Denied"
```

## Configuration

Generate a config file and the password hasher. `init` will not
replace an existing config file unless you pass `--force`. It also
leaves an edited hasher file in place unless you pass `--force`.

```bash
./bin/oauth-cli init
./bin/oauth-cli init --mfa --output config.yaml
./bin/oauth-cli init --hash argon2id
HASH_ALGO=./myhash.go ./bin/oauth-cli init
```

`just run` loads `config.yaml` from the working directory when that
file exists. If you pass `-config` and that file is missing, the
server exits. With no flag and no `config.yaml`, the server uses
built-in defaults.

### Config Structure

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""

database:
  path: "./oauth.db"
  migrations: true

security:
  access_token_lifetime: 3600s
  refresh_token_lifetime: 86400s
  authorization_code_lifetime: 600s
  device_code_lifetime: 1800s
  ciba_request_lifetime: 120s
  request_uri_lifetime: 60s
  require_pkce: true
  allow_plain_pkce: false
  issuer: "http://localhost:8080"
  hash_algo: "internal/hashalgo/algo.go"
  session_lifetime: 8h
  reset_token_lifetime: 30m
  trusted_proxies: []
  disable_registration: false
  disable_social_registration: false
  allow_insecure_fetch: false
  fetch_allow_ips: []
  password:
    min_length: 8
    max_length: 128
    require_uppercase: false
    require_lowercase: false
    require_number: false
    require_symbol: false
    block_username: true
  bot_protection:
    provider: ""
    site_key: ""
    secret_key: ""
  mfa:
    enabled: false
    required: false
    issuer: "OAuthImplServer"
    digits: 6
    period: 30

management:
  client_id: ""
  client_secret: ""

smtp:
  enabled: false
  host: ""
  port: 587
  username: ""
  password: ""
  from: ""
  starttls: true
  implicit_tls: false

branding:
  product_name: "OAuth Server"
  login_title: "Sign In"
  username_label: "Username"
  password_label: "Password"
  submit_label: "Sign In"
  assets_dir: ""
  logo_file: ""
  favicon_file: ""
  primary_color: "#0066ff"
  background_color: ""
  text_color: ""
  footer_text: ""
  support_url: ""
  privacy_url: ""
  terms_url: ""
  show_register: true
  show_forgot_password: true
  templates: ""

registration:
  dcr_enabled: true
  cimd_enabled: false

queue:
  type: "memory"
  poll_interval: 5s
  max_pending: 100

oidc:
  issuer: "http://localhost:8080"
  key_rotation_interval: 0s
  key_retain: 48h
  claim_mappings: []
  supported_scopes:
    - openid
    - profile
    - email
    - address
    - phone
    - offline_access
  supported_grant_types:
    - authorization_code
    - client_credentials
    - refresh_token
    - urn:ietf:params:oauth:grant-type:device_code
    - urn:openid:params:grant-type:ciba
```

## Login page

Auth pages read `branding` from the config. Restart the server after a change.
`branding.assets_dir` is a directory of `logo_file`, `favicon_file`, and an
optional `custom.css`. The server serves those files at `/branding/assets/`.
An image hosted on another site does not load.

`branding.templates` is a directory of HTML files, read when the process
starts. `login.html` replaces the stock login page. Every other file name
you omit stays on the built-in page. A replacement login form must POST to
`/login` and keep the field names `username`, `password`, `client_id`,
`redirect_uri`, `response_type`, `scope`, `state`, `nonce`,
`code_challenge`, `code_challenge_method`, `request_uri`, `prompt`,
`login_hint`, `resource`, and `next`. Replace `chrome.html` when you want
a different shared header on every auth page. `show_register: false` hides
the register link and leaves signup available. `security.disable_registration`
closes self-service signup: `GET` and `POST /register` and
`POST /api/account/register` return 403. Management `POST /api/users` still
creates accounts. Dynamic client registration at `POST /oauth/register` is
unchanged.

Colors are `#rgb` or `#rrggbb`.

## Social login

`social.providers` lists upstream OAuth apps. Each `id` is lowercase. `type`
is `google`, `github`, `facebook`, `oidc`, or `oauth2`. An enabled provider
needs `client_id` and `client_secret`. Presets fill the endpoints. `oidc`
needs `issuer`. `oauth2` needs the authorization, token, and userinfo URLs.

Register this redirect URI on the upstream app:

`{security.issuer}/login/social/{id}/callback`

The login page links to each enabled provider. The first sign-in creates a
local user with a random password. The next sign-in from the same provider
account uses that user. An email that already belongs to a password user is
not attached. `security.disable_social_registration` and
`security.disable_registration` both refuse that first sign-in. A provider
account that is already linked can still sign in.

```yaml
social:
  providers:
    - id: google
      type: google
      name: Google
      enabled: true
      client_id: ""
      client_secret: ""
```

## Accounts, sessions, and mail

`oauth-cli init` writes `management.client_id` and `management.client_secret`.
On startup the server creates that client when it is missing, with the
`client_credentials` grant and the `management` scope. `/api` and `/ciba`
require an access token from that grant. A user access token calls `/api/me`
and cannot call `/api`.

Dynamic registration drops the `management` scope. A client-credentials
request can only receive scopes already stored on the client.

Device approval at `/device` uses the signed-in browser session. The form
does not accept a user id.

Browser sessions are stored in SQLite. The cookie lasts for
`security.session_lifetime` (8 hours by default) and is shared by every
client on this issuer. `prompt=none` uses that session. `/oauth/logout`
ends it and posts a logout token to each client that has a
`backchannel_logout_uri` and was used in the session.

Refresh tokens rotate on use. Reuse of a revoked refresh token revokes
that token family. Other families for the same user stay valid.
`GET /api/refresh-tokens` and `GET /api/me/refresh-tokens` list them by
public id and omit the secret.

SMTP is off unless `smtp.enabled` is true. Password reset then returns
503 `mailer_disabled`. An operator sets a password with
`POST /api/users/{id}/password` or `oauth-cli user password`. When SMTP
is on, the server sends password reset, email confirmation, password
changed, and login activity mail. Login still succeeds when a send fails.
`email_verified` in ID tokens and UserInfo follows the stored flag.
Existing rows with an email are marked verified once, on the first
migration after this change. New self-service accounts start unverified.
Login is allowed either way.

## Login analytics

Every sign-in attempt stores the client IP and user agent. The IP is the
TCP peer. Set `security.trusted_proxies` to CIDR blocks, such as
`10.0.0.0/8`, when the server sits behind a reverse proxy. Only then are
`X-Forwarded-For` and `X-Real-IP` used, and a forwarded address that is
itself inside that list is skipped.

`GET /api/me/login-analytics?window=168h` summarizes the signed-in user.
Management calls are `GET /api/users/{id}/login-analytics` and
`GET /api/analytics/logins`. The report includes attempts, the failure
rate, unique addresses, addresses first seen in the window, a per-address
breakdown, and a per-day breakdown. `window` defaults to 30 days (`720h`).

```bash
./bin/oauth-cli analytics logins
./bin/oauth-cli analytics logins --user-id <id> --window 24h
```

A successful sign-in from an address that user has not used before sets
`new_ip` on the `login` webhook. The browser session stores the same IP.

## Webhooks

Create a webhook with the management API or `oauth-cli webhook create`.
Each subscription lists the events it receives. Use `*` to receive every
event. The request is `POST` JSON. `X-Webhook-Signature` is
`sha256=` plus the hex HMAC-SHA256 of `timestamp.body`, using the
webhook secret. `X-Webhook-Timestamp` is the unix time, and
`X-Webhook-Event` is the event name.

Events: `login`, `login_failed`, `logout`, `sso_session_triggered`,
`bruteforce_detected`, `forgot_password`, `change_password`,
`password_reset`, `user_registered`, `email_verified`, `user_disabled`.

`sso_session_triggered` fires when an existing browser session authorizes
a second client, and when `prompt=none` succeeds. `bruteforce_detected`
fires once per user per 15 minutes after five failed sign-ins.
A delivery error is logged and does not fail the user action.
`POST /api/webhooks/{id}/test` sends a `webhook.test` event.

## Password hashing

User passwords are hashed by the single function in
`internal/hashalgo/algo.go`. `init` writes that file with bcrypt, which
matches passwords already stored in the database.

The file must use package `hashalgo` and must export only `Hash`:

```go
package hashalgo

import "github.com/bravo68web/oauth-impl/pkg/passhash"

func Hash() passhash.Hasher {
    return passhash.Bcrypt(passhash.DefaultBcryptCost)
}
```

Edit the body and keep the signature. Start the server again with
`just run` so the process recompiles. A binary in `bin/` keeps the
function it was built with, so run `just build` after an edit before
you start `bin/oauth-server`.

Set `HASH_ALGO` to another Go file during `init` to copy it onto
`internal/hashalgo/algo.go`. The server does not load a different path
at startup. `HASH_ALGO` and `security.hash_algo` must name
`internal/hashalgo/algo.go`.

`./bin/oauth-cli init --hash argon2id` writes an argon2id function that
still accepts existing bcrypt passwords. The next successful login
stores a new argon2id hash. Those settings use 64 MiB of memory. Lower
`Memory` in the file if login stalls.

The server refuses to start when `algo.go` on disk does not match the
function compiled into the process. Run the server from the project
root so it can read that file.

## API Documentation

- **Scalar UI**: http://localhost:8080/docs
- **OpenAPI JSON**: http://localhost:8080/openapi
- **OpenAPI YAML**: http://localhost:8080/docs/openapi.yaml
- **Static spec**: `openapi/spec.yaml`

## Development

### Prerequisites

- Go 1.21+
- `just` (command runner)
- `golangci-lint` (for linting)
- `air` (for hot reload)

### Install Tools

```bash
just install-tools
```

### Common Commands

```bash
just build          # Build all binaries
just run            # Start server (loads config.yaml when present)
just dev            # Hot reload with air
just test           # Run all tests
just lint           # Run linter
just vet            # Run go vet
just fmt            # Format code
just check          # Full check (fmt + vet + lint + test)
just clean          # Clean build artifacts
```

### Project Structure

```
oauth-impl/
├── cmd/
│   ├── oauth-server/    # Main HTTP server
│   ├── oauth-cli/       # Management CLI
│   └── oauth-mobile/    # Mobile polling CLI
├── internal/
│   ├── config/          # YAML configuration
│   ├── controller/      # HTTP request handlers
│   ├── database/        # SQLite connection + migrations
│   ├── handlers/        # OAuth/OIDC handlers
│   ├── hashalgo/        # Password hasher (edit algo.go)
│   ├── models/          # Data models
│   ├── oidc/            # OIDC handler
│   ├── queue/           # In-memory queue for CIBA
│   ├── repository/      # Database access layer
│   ├── route/           # Route definitions
│   ├── security/        # DPoP validation
│   ├── service/         # Business logic
│   └── templates/       # HTML templates
├── openapi/             # OpenAPI 3.1 spec
├── migrations/          # SQL migration files
├── pkg/
│   ├── crypto/          # PKCE, token generation
│   ├── errors/          # Custom error types
│   ├── jwt/             # JWT utilities
│   └── passhash/        # bcrypt, argon2id, fallback
└── tests/
    └── integration/     # Integration tests
```

## Testing

```bash
# Run all tests
just test

# Run specific package tests
go test ./pkg/crypto/... -v
go test ./internal/queue/... -v
go test ./internal/database/... -v
go test ./tests/integration/... -v

# Run with coverage
just test-cover

# Browser and protocol flows (Playwright + Mocha)
cd e2e && npm install
npx playwright install chromium
npm test
```

`e2e/` starts Postgres with testcontainers (`e2e/pgserve`) and then starts `oauth-server` in separate modes: standard grants, CIBA, refresh and signing-key rotation, webhooks, brute-force detection, password complexity, required PKCE, closed registration, MFA enrollment, forced DPoP, CIMD, and JWT access tokens (`security.access_token_format: jwt`). The default access token format stays `opaque`.

## Database and Redis

`database.driver` is `sqlite` or `postgres`. SQLite is the default and uses `database.path` (default `./oauth.db`). Postgres uses `database.dsn`, for example `postgres://oauth:oauth@localhost:5432/oauth?sslmode=disable`.

`queue.type` and `cache.provider` are `memory` or `redis`. Leave `redis.addr` empty to keep the CIBA and device queue, the CIMD document cache, and the DPoP replay cache in the server process. Set `redis.addr` and switch either setting to `redis` when more than one server process must share that state. Tokens, users, and sessions stay in the SQL database.

## License

This project is licensed under the [MIT License](LICENSE).
