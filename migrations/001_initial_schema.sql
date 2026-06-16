-- 001_initial_schema.sql
-- Initial database schema for OAuth implementation

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    secret TEXT,
    name TEXT NOT NULL,
    redirect_uris TEXT,
    grant_types TEXT,
    scopes TEXT,
    token_endpoint_auth_method TEXT DEFAULT 'client_secret_basic',
    dpop_bound_access_tokens INTEGER DEFAULT 0,
    require_pushed_authorization_requests INTEGER DEFAULT 0,
    backchannel_token_delivery_mode TEXT,
    backchannel_client_notification_endpoint TEXT,
    backchannel_authentication_request_signing_alg TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    phone_number TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS access_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT,
    scopes TEXT,
    token_type TEXT DEFAULT 'Bearer',
    dpop_jkt TEXT,
    expires_at DATETIME NOT NULL,
    revoked INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    access_token TEXT,
    client_id TEXT NOT NULL,
    user_id TEXT,
    scopes TEXT,
    expires_at DATETIME,
    revoked INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS device_codes (
    device_code TEXT PRIMARY KEY,
    user_code TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT,
    status TEXT DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    interval INTEGER DEFAULT 5,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS pushed_auth_requests (
    request_uri TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    request_params TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS ciba_requests (
    auth_req_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT,
    binding_message TEXT,
    user_code TEXT,
    status TEXT DEFAULT 'pending',
    delivery_mode TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    interval INTEGER DEFAULT 5,
    client_notification_token TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS oidc_nonces (
    nonce TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS dpop_proofs (
    jti TEXT PRIMARY KEY,
    htm TEXT NOT NULL,
    htu TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_client ON authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_device_codes_status ON device_codes(status);
CREATE INDEX IF NOT EXISTS idx_ciba_requests_status ON ciba_requests(status);
