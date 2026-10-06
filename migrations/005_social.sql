-- Record of the social-login tables. The running server applies these
-- statements from internal/database/database.go Migrate, not from this file.

CREATE TABLE IF NOT EXISTS social_logins (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    params_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS social_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id TEXT NOT NULL,
    email TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (provider, subject)
);
