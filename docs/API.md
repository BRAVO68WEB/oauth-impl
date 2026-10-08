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
DELETE /api/me/sessions/:sid
GET    /api/me/refresh-tokens
DELETE /api/me/refresh-tokens/:id
GET    /api/me/activity
GET    /api/me/login-analytics?window=720h
```

Browser pages: `/login`, `/register`, `/consent`, `/mfa/enroll`, `/forgot`, `/reset`, `/verify-email`, `/device`, `/oauth/logout`.

`GET /login/social/{id}` redirects to an enabled provider from `social.providers`. `GET /login/social/{id}/callback` finishes sign-in. `security.disable_social_registration` returns 403 when that provider account is not already linked.

`GET /branding/assets/{name}` serves one file from `branding.assets_dir` (png, jpg, jpeg, gif, webp, svg, ico, or css, up to 1 MiB). The page copy, colors, and optional HTML overlay come from the `branding` config block and apply on restart.

## Webhooks

Management token required. Each webhook chooses its events.

```
GET    /api/webhooks
POST   /api/webhooks
GET    /api/webhooks/:id
PATCH  /api/webhooks/:id
DELETE /api/webhooks/:id
POST   /api/webhooks/:id/test
```

`POST` body: `url`, `events` (or `["*"]`), optional `secret`, `description`, `enabled`.
Deliveries are JSON with `X-Webhook-Event`, `X-Webhook-Timestamp`, and
`X-Webhook-Signature: sha256=<hmac of timestamp + "." + body>`.

### CIBA

```
GET  /api/ciba/pending       - List pending CIBA requests
POST /api/ciba/:id/approve   - Approve CIBA request
POST /api/ciba/:id/deny      - Deny CIBA request
```

---

## Supported Scopes

- `openid` - OpenID Connect
- `profile` - User profile information
- `email` - User email address
- `address` - User address
- `phone` - User phone number
- `offline_access` - Refresh tokens

---

## Security Features

### PKCE (RFC 7636)
Supports `S256` and `plain` code challenge methods.

### DPoP (RFC 9449)
Sender-constrained tokens using proof-of-possession.

### Token Types
- `Bearer` - Standard bearer tokens
- `DPoP` - Proof-of-possession tokens

---

## Error Responses

All errors follow RFC 6749 format:

```json
{
  "error": "invalid_request",
  "error_description": "Description of the error"
}
```

`/api` routes other than self-service registration, forgot-password, reset, and email verify require a bearer token. Management routes require a client-credentials token whose scope includes `management`. A user token receives 403.

```
GET   /api/audit?window=720h&action=&actor_id=
POST  /api/keys/rotate
```

`POST /api/keys/rotate` publishes new RSA and EC signing keys and keeps the previous public keys until `key_retain` elapses. The response lists key ids. Private keys stay in SQLite.

`dpop_bound_access_tokens` on an OAuth app forces a DPoP proof on every token grant, on UserInfo, and on revocation of a bound token. `security.dpop.enabled` only controls whether other apps may send an unsolicited proof.

Dynamic client registration (`POST /oauth/register`) is open when `registration.dcr_enabled` is true. The new row is stored with `registration_source=dcr` and `dcr_enabled=true`. Authorize and token reject that client with `unauthorized_client` unless both the tenant flag and the row flag stay true. An HTTPS `client_id` is a Client ID Metadata Document when `registration.cimd_enabled` is true and the row is not disabled.

Browser POSTs to `/login`, `/register`, `/consent`, `/forgot`, `/reset`, `/mfa/enroll/verify`, `/device`, and `/oauth/logout` require the `csrf_token` field copied from the form. A mismatch is 403 `csrf_failed`.

`POST /login`, `POST /register`, and `POST /forgot` check `bot_token` when `security.bot_protection.provider` is `recaptcha` or `turnstile`. A missing or rejected token is 400 `bot_failed`.

Password creates, resets, and changes use `security.password`. A failure is 400 `invalid_password`. Login does not recheck complexity.

ID tokens and UserInfo use `oidc.claim_mappings` when that list is non-empty. An empty list keeps the scope claims from `profile`, `email`, and `phone`.

Common error codes:
- `invalid_request` - Malformed request
- `invalid_client` - Client authentication failed
- `invalid_password` - Password does not meet the configured complexity rules
- `bot_failed` - Bot token missing or rejected
- `csrf_failed` - Browser form token missing or mismatched
- `registration_disabled` - Self-service signup or dynamic client registration is turned off
- `invalid_grant` - Invalid authorization grant
- `unauthorized_client` - Client not authorized for grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Invalid scope requested
