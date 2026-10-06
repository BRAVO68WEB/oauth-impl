-- Record only. The running server applies the same changes in database.Migrate.
-- This file is not executed on startup.

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    ip TEXT,
    user_agent TEXT,
    metadata TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    status TEXT NOT NULL,
    private_pem TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retire_at TEXT
);

ALTER TABLE users ADD COLUMN attributes TEXT NOT NULL DEFAULT '{}';
ALTER TABLE clients ADD COLUMN registration_source TEXT NOT NULL DEFAULT 'management';
ALTER TABLE clients ADD COLUMN dcr_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN cimd_enabled INTEGER NOT NULL DEFAULT 0;
