-- Record of the push-device tables. The live migrator is database.Migrate.

CREATE TABLE IF NOT EXISTS push_registration_tokens (
    jti TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS push_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT,
    jwk TEXT NOT NULL,
    jkt TEXT NOT NULL,
    credential_hash TEXT NOT NULL,
    platform TEXT,
    push_address TEXT,
    interaction_types TEXT NOT NULL,
    attestation TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
