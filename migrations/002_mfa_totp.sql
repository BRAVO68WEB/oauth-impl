-- 002_mfa_totp.sql
-- Add MFA columns to users table

ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_verified INTEGER DEFAULT 0;

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);
