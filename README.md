# OAuth Implementation Server

A comprehensive OAuth 2.0 / OpenID Connect testing server implementing all major flows and standards.

## Features

- **All OAuth 2.0 Flows**: Authorization Code + PKCE, Client Credentials, Device Code, Implicit, Hybrid
- **CIBA**: Client-Initiated Backchannel Authentication (Poll/Ping/Push modes)
- **PAR**: Pushed Authorization Requests (RFC 9126)
- **DPoP**: Demonstrating Proof-of-Possession (RFC 9449)
- **OpenID Connect**: Discovery, JWKS, UserInfo, ID Tokens
- **TOTP MFA**: Two-factor authentication with QR code enrollment
- **Session-based Auth**: Login, registration, and consent pages
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

The server starts at `http://localhost:8080`.

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

# Initialize config
./bin/oauth-cli init
./bin/oauth-cli init --mfa

# Client management
./bin/oauth-cli client list
./bin/oauth-cli client create --name "My App" --redirect-uri "https://example.com/cb"
./bin/oauth-cli client get <client-id>
./bin/oauth-cli client delete <client-id>

# User management
./bin/oauth-cli user list
./bin/oauth-cli user create --username "user" --password "pass" --email "user@example.com"

# Token management
./bin/oauth-cli token list
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

Generate a config file:

```bash
./bin/oauth-cli init
./bin/oauth-cli init --mfa --output config.yaml
```

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
  mfa:
    enabled: false
    required: false
    issuer: "OAuthImplServer"
    digits: 6
    period: 30

queue:
  type: "memory"
  poll_interval: 5s
  max_pending: 100

oidc:
  issuer: "http://localhost:8080"
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
just run            # Start server
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
│   └── jwt/             # JWT utilities
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
```

## License

MIT
