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

**Response:** Redirects to `redirect_uri` with authorization code

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
```

### Tokens

```
GET  /api/tokens             - List tokens (filter by client_id, user_id)
POST /api/tokens/:token/revoke - Revoke token
```

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

Common error codes:
- `invalid_request` - Malformed request
- `invalid_client` - Client authentication failed
- `invalid_grant` - Invalid authorization grant
- `unauthorized_client` - Client not authorized for grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Invalid scope requested
