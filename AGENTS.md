# AGENTS.md - OAuth Implementation Server

## Quick Reference

```bash
just run              # Start server (port 8080)
just dev              # Hot reload with air
just test             # Run all tests
just build            # Build all binaries to bin/
just test-flow        # Quick integration test

# CLI commands
./bin/oauth-cli init                    # Generate config.yaml
./bin/oauth-cli init --mfa              # Generate config with MFA enabled
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
- `internal/templates/` - Go HTML templates (login, register, consent, MFA)
- `internal/handlers/oauth/` - Legacy OAuth handlers (being migrated)
- `internal/handlers/oidc/` - OIDC handler (discovery, JWKS, UserInfo)
- `internal/database/` - SQLite connection + migrations
- `internal/queue/` - In-memory queue for CIBA/PAR
- `internal/config/` - YAML config with MFA settings
- `internal/models/` - Data models
- `pkg/crypto/` - PKCE, token generation
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
- `/register` - Registration form
- `/consent` - OIDC consent screen
- `/mfa/enroll` - TOTP enrollment with QR code

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
- **Password hashing**: Uses bcrypt in `service/user.go`
- **CIBA queue polling**: Uses `MemoryQueue.Poll()` with channels
- **OIDC key generation**: RSA + EC keys generated on startup
- **Config defaults**: Server binds `0.0.0.0:8080`, SQLite at `./oauth.db`
- **MFA**: TOTP with QR code rendering (PNG for web, ASCII for CLI)
- **Templates**: Go `html/template` in `internal/templates/`
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

## CLI Tools

```bash
# Initialize config
./bin/oauth-cli init
./bin/oauth-cli init --mfa
./bin/oauth-cli init --output myconfig.yaml

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
- `golang.org/x/crypto` - bcrypt password hashing
