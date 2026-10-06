# AGENTS.md - OAuth Implementation Server

## Quick Reference

```bash
just run              # Start server (loads config.yaml if present)
just dev              # Hot reload with air
just test             # Run all tests
just build            # Build all binaries to bin/
just test-flow        # Quick integration test
just e2e              # Playwright + Mocha flows (cd e2e && npm install first)

# CLI commands
./bin/oauth-cli init                    # Generate config.yaml and algo.go
./bin/oauth-cli init --mfa              # Generate config with MFA enabled
./bin/oauth-cli init --hash argon2id    # argon2id hasher, bcrypt still verifies
./bin/oauth-cli server status           # Check server status
./bin/oauth-cli client list             # List clients
./bin/oauth-cli mfa enable --user-id X  # Enable MFA for user
```

## Architecture

Three binaries in `cmd/`:
- **oauth-server** - Main HTTP server (chi router, SQLite, port 8080)
- **oauth-cli** - Management CLI (client/user/token management + config init)
- **oauth-mobile** - Mobile polling CLI (CIBA request approval)

### Layered Architecture (Route → Controller → Service → Repository)

Key package boundaries:
- `internal/route/` - Route definitions (maps URLs to controllers)
- `internal/controller/` - HTTP request/response handling (thin layer)
- `internal/service/` - Business logic (no HTTP, no SQL)
- `internal/repository/` - Database access (SQL only, no business logic)
- `internal/templates/` - Go HTML templates (login, register, consent, MFA, device, reset, logout)
- `internal/mailer/` - SMTP and the disabled mailer
- `internal/auth/` - Bearer checks for `/api` and `/api/me`
- `internal/handlers/oauth/` - Legacy OAuth handlers (being migrated)
- `internal/handlers/oidc/` - OIDC handler (discovery, JWKS, UserInfo)
- `internal/database/` - SQLite connection + migrations
- `internal/queue/` - In-memory queue for CIBA/PAR
- `internal/config/` - YAML config with MFA settings
- `internal/hashalgo/` - Operator password hasher (`algo.go` exports `Hash`)
- `internal/models/` - Data models
- `pkg/crypto/` - PKCE, token generation
- `pkg/passhash/` - bcrypt, argon2id, and fallback hashers
- `pkg/errors/` - Custom OAuth error types
- `pkg/jwt/` - JWT utilities
- `openapi/` - OpenAPI 3.1 spec

### New Features

**MFA (TOTP):**
- Config: `security.mfa.enabled`, `security.mfa.required`
- Web enrollment: `/mfa/enroll` (QR code + secret text)
- CLI enrollment: `oauth-cli mfa enable --user-id X`
- QR rendering: `skip2/go-qrcode` (PNG + ASCII art)
- TOTP: `pquerna/otp` library

**Web Pages:**
- `/login` - Login form
- `/register` - Registration form. `security.disable_registration` returns 403 for this page, `POST /register`, and `POST /api/account/register`. Management `POST /api/users` still creates users.
- `/login/social/{id}` - Social login. Providers live in `social.providers`. `security.disable_social_registration` blocks creating an account from that callback.
- `/consent` - OIDC consent screen
- `/mfa/enroll` - TOTP enrollment with QR code
- `/forgot`, `/reset`, `/verify-email`, `/device`, `/oauth/logout` - account pages
- Branding: `branding` in config, assets at `/branding/assets/`, optional HTML overlay in `branding.templates` (read at startup)

**API Documentation:**
- `/docs` - Scalar OpenAPI UI
- `/openapi` - OpenAPI spec (JSON)
- `/docs/openapi.yaml` - OpenAPI spec (YAML)

## Testing

```bash
go test ./pkg/crypto/... -v        # Crypto tests
go test ./internal/queue/... -v    # Queue tests
go test ./internal/database/... -v # Database tests
go test ./tests/integration/... -v # Integration tests
go test ./... -v                   # All tests
```

## Key Quirks

- **SQLite single-connection**: `database.go` sets `MaxOpenConns=1`
- **Password hashing**: `internal/hashalgo/algo.go` exports one function, `Hash() passhash.Hasher`. Default is bcrypt (`passhash.DefaultBcryptCost`). Login, register, `POST /api/users`, and the password grant all use `UserService`. `HASH_ALGO` and `security.hash_algo` must be `internal/hashalgo/algo.go`. Edit the file, then `just run` or `just build`. Startup refuses to serve when the file differs from the binary.
- **Config load**: empty `-config` loads `./config.yaml` when it exists, otherwise built-in defaults. A `-config` path that is missing is fatal.
- **CIBA queue polling**: Uses `MemoryQueue.Poll()` with channels
- **OIDC key generation**: RSA + EC keys generated on startup
- **Config defaults**: Server binds `0.0.0.0:8080`, SQLite at `./oauth.db`
- **MFA**: TOTP with QR code rendering (PNG for web, ASCII for CLI)
- **Management API**: `/api` and `/ciba` require a client-credentials access token with scope `management`. `oauth-cli init` writes `management.client_id` and `management.client_secret`. Startup inserts that client when it is missing. The CLI and `oauth-mobile` send the bearer token (`--client-id`, `--client-secret`, or `management.*` in `--config`).
- **CIAM**: `/api/me` uses the user access token. Public reset and registration live under `/api/account`. SMTP is `smtp` in config and stays off until `enabled` is true.
- **Sessions**: Browser sessions are SQLite rows. Cookie lifetime is `security.session_lifetime` (default 8h). `/device` approval uses that session. `/oauth/logout` sends OIDC back-channel logout tokens.
- **Refresh tokens**: Rotation keeps `family_id`. Reuse revokes that family. List APIs return a public id and omit the secret.
- **Login analytics**: `login_events` stores IP and user agent. `GET /api/me/login-analytics` and `GET /api/analytics/logins` summarize attempts, failure rate, new addresses, per-IP totals, and per-day totals. `security.trusted_proxies` is the only case where `X-Forwarded-For` is read. A first-seen address sets `new_ip` on the login webhook.
- **Webhooks**: `webhooks` table. Management CRUD at `/api/webhooks`. Each row lists events (`login`, `logout`, `sso_session_triggered`, `bruteforce_detected`, `forgot_password`, `change_password`, and others). Delivery is HMAC-SHA256 in `X-Webhook-Signature` and does not fail the user action.
- **Templates**: Go `html/template` in `internal/templates/`. `branding.templates` replaces a page by file name at startup. `docs.html` is not part of the auth chrome. Editing the embedded HTML does not change a built `bin/oauth-server` until the next build; the overlay directory does, after a restart.
- **OpenAPI**: Spec in `openapi/spec.yaml`, Scalar UI at `/docs`

## OAuth Flows Implemented

| Flow | Endpoint | Status |
|------|----------|--------|
| Authorization Code + PKCE | `/oauth/authorize` + `/oauth/token` | Working |
| Client Credentials | `/oauth/token` | Working |
| Device Code | `/oauth/device` + `/oauth/token` | Working |
| CIBA (Poll mode) | `/oauth/bc-authorize` + `/oauth/token` | Working |
| PAR | `/oauth/par` | Working |
| Token Introspection | `/oauth/introspect` | Working |
| Token Revocation | `/oauth/revoke` | Working |
| Dynamic Registration | `/oauth/register` | Working |
| OIDC Discovery | `/.well-known/openid-configuration` | Working |
| JWKS | `/oidc/jwks` | Working |
| UserInfo | `/oidc/userinfo` | Working |
| RP-Initiated Logout | `/oauth/logout` | Working |
| Back-Channel Logout | client `backchannel_logout_uri` | Working |

## CLI Tools

```bash
# Initialize config and internal/hashalgo/algo.go
./bin/oauth-cli init
./bin/oauth-cli init --mfa
./bin/oauth-cli init --hash argon2id
./bin/oauth-cli init --output myconfig.yaml
./bin/oauth-cli init --force
HASH_ALGO=./myhash.go ./bin/oauth-cli init

# Management
./bin/oauth-cli client list
./bin/oauth-cli client create --name "App" --redirect-uri "https://example.com/cb"
./bin/oauth-cli user create --username "user" --password "pass"
./bin/oauth-cli ciba pending

# MFA
./bin/oauth-cli mfa enable --user-id <id>
./bin/oauth-cli mfa enable --user-id <id> --show-secret
./bin/oauth-cli mfa verify --user-id <id> --code 123456

# Mobile
./bin/oauth-mobile list
./bin/oauth-mobile approve <auth-req-id> --user-id <user-id>
./bin/oauth-mobile deny <auth-req-id> --reason "Denied"
```

## Development

- Hot reload: `just dev` (requires `air` - install via `just install-tools`)
- Linting: `just lint` (requires `golangci-lint`)
- Formatting: `just fmt` (requires `goimports`)
- Full check: `just check` (fmt → vet → lint → test)

## Dependencies

Key external packages:
- `github.com/go-chi/chi/v5` - HTTP router
- `github.com/pquerna/otp` - TOTP generation/validation
- `github.com/skip2/go-qrcode` - QR code rendering
- `github.com/golang-jwt/jwt/v5` - JWT handling
- `github.com/spf13/cobra` - CLI framework
- `modernc.org/sqlite` - SQLite driver
- `golang.org/x/crypto` - bcrypt and argon2id password hashing
