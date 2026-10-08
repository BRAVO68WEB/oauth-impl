# OAuth Implementation Server - API Documentation

## Overview

This OAuth 2.0 / OpenID Connect implementation server supports all major OAuth flows and extensions for testing and development purposes.

## Base URL

```
http://localhost:8080
```

## OAuth 2.0 Endpoints

### Authorization Endpoint

```
GET/POST /oauth/authorize
```

Initiates the authorization code flow.

**Parameters:**
- `client_id` (required) - Client identifier
- `response_type` (required) - Must be `code`
- `redirect_uri` (required) - Callback URL
- `scope` (optional) - Space-separated scopes
- `state` (recommended) - CSRF protection
- `code_challenge` (optional) - PKCE challenge
- `code_challenge_method` (optional) - `S256` or `plain`
- `nonce` (optional) - For OpenID Connect

**Response:** Redirects to `redirect_uri` with an authorization code.

A client may register `urn:ietf:wg:oauth:2.0:oob` or `urn:ietf:wg:oauth:2.0:oob:auto` instead of an HTTP callback. The request must use `response_type=code` and PKCE `S256`. After sign-in the server returns an HTML page with the code. The token request sends that same `redirect_uri` back with the pasted code and `code_verifier`. `oauth-cli flow paste` prints the URL and reads the code.

When `security.oob_helper` is true, `GET /oauth/oob` is the helper page from draft-richer-oauth-oob-authcode. Register that URL as a normal redirect URI. The authorization response is still a redirect, with `code` and `state` on the query string. The page shows one combined value. The draft names an HKDF info parameter and does not assign its bytes. This server uses the ASCII string `draft-richer-oauth-oob-authcode`. With the flag off, the path returns 404.

---

### Token Endpoint

```
POST /oauth/token
```

Exchanges authorization grants for tokens.

**Grant Types:**

#### Authorization Code Grant
```
grant_type=authorization_code
code=<authorization_code>
redirect_uri=<redirect_uri>
code_verifier=<code_verifier>
```

#### Client Credentials Grant
```
grant_type=client_credentials
scope=<scopes>
```

#### Refresh Token Grant
```
grant_type=refresh_token
refresh_token=<refresh_token>
```

#### Device Code Grant
```
grant_type=urn:ietf:params:oauth:grant-type:device_code
device_code=<device_code>
```

#### CIBA Grant
```
grant_type=urn:openid:params:grant-type:ciba
auth_req_id=<auth_req_id>
```

**Response:**
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "scope": "openid profile",
  "id_token": "..."  // If openid scope present
}
```

---

### Token Revocation (RFC 7009)

```
POST /oauth/revoke
```

Revokes access or refresh tokens.

**Parameters:**
- `token` (required) - Token to revoke
- `token_type_hint` (optional) - `access_token` or `refresh_token`

---

### Token Introspection (RFC 7662)

```
POST /oauth/introspect
```

Validates and returns token metadata.

**Parameters:**
- `token` (required) - Token to introspect

**Response:**
```json
{
  "active": true,
  "scope": "openid profile",
  "client_id": "...",
  "username": "...",
  "token_type": "Bearer",
  "exp": 1234567890,
  "iat": 1234567890,
  "sub": "..."
}
```

---

### Dynamic Client Registration (RFC 7591)

```
POST /oauth/register
```

Registers a new OAuth client.

**Request Body:**
```json
{
  "client_name": "My App",
  "redirect_uris": ["https://example.com/callback"],
  "grant_types": ["authorization_code"],
  "scope": "openid profile"
}
```

**Response:**
```json
{
  "client_id": "...",
  "client_secret": "...",
  "client_name": "My App",
  "redirect_uris": ["https://example.com/callback"],
  "grant_types": ["authorization_code"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

---

### Device Authorization (RFC 8628)

```
POST /oauth/device
```

Initiates device authorization flow.

**Response:**
```json
{
  "device_code": "...",
  "user_code": "ABCD-EFGH",
  "verification_uri": "http://localhost:8080/device",
  "verification_uri_complete": "http://localhost:8080/device?user_code=ABCD-EFGH",
  "expires_in": 1800,
  "interval": 5
}
```

---

### Pushed Authorization Requests (RFC 9126)

```
POST /oauth/par
```

Pushes authorization request parameters to the server.

**Request Body:** Same as authorization endpoint parameters

**Response:**
```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:...",
  "expires_in": 60
}
```

---

### CIBA Backchannel Authentication

```
POST /oauth/bc-authorize
```

Initiates Client-Initiated Backchannel Authentication.

**Parameters:**
- `scope` (required) - Must include `openid`
- `login_hint` (required*) - User identifier
- `binding_message` (optional) - Display message
- `client_notification_token` (required for ping/push)

**Response:**
```json
{
  "auth_req_id": "...",
  "expires_in": 120,
  "interval": 5
}
```

---

## OIDC Endpoints

### Discovery

```
GET /.well-known/openid-configuration
```

Returns OpenID Connect discovery metadata.

### JWKS

```
GET /oidc/jwks
```

Returns JSON Web Key Set for token verification.

### UserInfo

```
GET /oidc/userinfo
Authorization: Bearer <access_token>
```

Returns user profile information based on scopes.

---

## Management API

`/api` and `/ciba` require `Authorization: Bearer` with a client-credentials
access token whose scope contains `management`. Obtain it from `POST /oauth/token`
with `grant_type=client_credentials&scope=management`.

`oauth-cli init` writes that client into `management.client_id` and
`management.client_secret`. The server inserts the client on startup when
the id is missing.

### Clients

```
GET    /api/clients          - List all clients
POST   /api/clients          - Create client
GET    /api/clients/:id      - Get client
PUT    /api/clients/:id      - Update client
DELETE /api/clients/:id      - Delete client
```

### Users

```
GET  /api/users              - List all users
POST /api/users              - Create user
GET  /api/users/:id          - Get user
PATCH /api/users/:id         - Update profile, disabled, email_verified
POST /api/users/:id/password - Set password
GET  /api/users/:id/sessions - List browser sessions
DELETE /api/users/:id/sessions/:sid
GET  /api/users/:id/activity - Login activity
GET  /api/users/:id/login-analytics?window=720h
GET  /api/analytics/logins?window=720h - All users, grouped by IP and day
```

### Tokens

```
GET  /api/tokens             - List access tokens (filter by client_id, user_id)
POST /api/tokens/:token/revoke - Revoke access token
GET  /api/refresh-tokens     - List refresh tokens by public id
POST /api/refresh-tokens/:id/revoke
```

## CIAM API

Public routes:

```
POST /api/account/register   - 403 registration_disabled when security.disable_registration is true
POST /api/account/password/forgot
POST /api/account/password/reset
POST /api/account/email/verify
```

User access token routes:

```
GET    /api/me
PATCH  /api/me
POST   /api/me/password
POST   /api/me/email/send
GET    /api/me/sessions
DELETE /api/me/sessions/{sid}
GET    /api/me/refresh-tokens
DELETE /api/me/refresh-tokens/{id}
GET    /api/me/activity
GET    /api/me/login-analytics?window=720h
```

`window` is a Go duration. The default is 30 days (`720h`).

## Management API

Clients, users, and tokens:

```
GET    /api/clients
POST   /api/clients
GET    /api/clients/{id}
PUT    /api/clients/{id}
DELETE /api/clients/{id}

GET    /api/users
POST   /api/users
GET    /api/users/{id}
PATCH  /api/users/{id}
POST   /api/users/{id}/password
POST   /api/users/{id}/mfa/enable
POST   /api/users/{id}/mfa/verify
GET    /api/users/{id}/mfa/status
POST   /api/users/{id}/mfa/disable
GET    /api/users/{id}/sessions
DELETE /api/users/{id}/sessions/{sid}
GET    /api/users/{id}/activity
GET    /api/users/{id}/login-analytics

GET    /api/tokens
POST   /api/tokens/{token}/revoke
GET    /api/refresh-tokens
POST   /api/refresh-tokens/{id}/revoke
```

Refresh-token lists use the public id and omit the secret.

Scopes, resources, and consents:

```
GET    /api/scopes
POST   /api/scopes
GET    /api/scopes/{name}
DELETE /api/scopes/{name}

GET    /api/resources
POST   /api/resources
GET    /api/resources/{uri}
PUT    /api/resources/{uri}
DELETE /api/resources/{uri}
GET    /api/resources/{uri}/scopes

GET    /api/consents
DELETE /api/consents
```

Organizations, webhooks, audit, analytics, CIBA, and keys:

```
GET    /api/orgs
POST   /api/orgs
GET    /api/orgs/{orgID}
POST   /api/orgs/{orgID}/domains
POST   /api/orgs/{orgID}/members

GET    /api/webhooks
POST   /api/webhooks
GET    /api/webhooks/{id}
PATCH  /api/webhooks/{id}
DELETE /api/webhooks/{id}
POST   /api/webhooks/{id}/test

GET    /api/audit
GET    /api/analytics/logins
POST   /api/keys/rotate

GET    /api/ciba/pending
POST   /api/ciba/{id}/approve
POST   /api/ciba/{id}/deny
```

`oauth-mobile` calls `GET /ciba/pending`, `POST /ciba/approve`, and
`POST /ciba/deny`. Its `status` command calls `GET /health`.

Webhook deliveries are `POST` JSON. `X-Webhook-Signature` is `sha256=`
plus the hex HMAC-SHA256 of the timestamp, a dot, and the raw body, using
the webhook secret.
`X-Webhook-Timestamp` is the unix time. `X-Webhook-Event` is the event
name. `*` subscribes to every event. Events include `login`,
`login_failed`, `logout`, `sso_session_triggered`,
`bruteforce_detected`, `forgot_password`, `change_password`,
`password_reset`, `user_registered`, `email_verified`, and
`user_disabled`. A delivery error is logged and does not fail the user
action. `POST /api/webhooks/{id}/test` sends `webhook.test`.

`POST /api/keys/rotate` returns the new key ids. Private keys stay in
SQL. See [Infrastructure](INFRA.md).

## Errors

Protocol errors use the OAuth shape:

```json
{
  "error": "invalid_request",
  "error_description": "what went wrong"
}
```

The OpenAPI document lists status codes per route.

## Related

[CLI](CLI.md) calls these routes.
[Configuration](CONFIG.md) is the issuer and client policy behind them.
