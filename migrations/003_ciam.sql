-- Record of the CIAM, session, logout, and mail columns.
-- The server applies these from internal/database/database.go Migrate.
-- This file is not executed on startup.

ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN given_name TEXT;
ALTER TABLE users ADD COLUMN family_name TEXT;
ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT;
ALTER TABLE clients ADD COLUMN backchannel_logout_session_required INTEGER NOT NULL DEFAULT 1;
ALTER TABLE clients ADD COLUMN post_logout_redirect_uris TEXT;
ALTER TABLE device_codes ADD COLUMN user_id TEXT;
ALTER TABLE device_codes ADD COLUMN session_id TEXT;
ALTER TABLE device_codes ADD COLUMN auth_time DATETIME;
ALTER TABLE refresh_tokens ADD COLUMN id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT;
ALTER TABLE authorization_codes ADD COLUMN family_id TEXT;
ALTER TABLE authorization_codes ADD COLUMN session_id TEXT;
ALTER TABLE authorization_codes ADD COLUMN auth_time DATETIME;

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT,
    auth_time DATETIME NOT NULL,
    mfa_verified INTEGER NOT NULL DEFAULT 0,
    user_agent TEXT,
    ip TEXT,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS session_clients (
    sid TEXT NOT NULL,
    client_id TEXT NOT NULL,
    PRIMARY KEY (sid, client_id)
);

CREATE TABLE IF NOT EXISTS email_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS login_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    success INTEGER NOT NULL,
    mfa INTEGER NOT NULL DEFAULT 0,
    ip TEXT,
    user_agent TEXT,
    created_at DATETIME NOT NULL
);
