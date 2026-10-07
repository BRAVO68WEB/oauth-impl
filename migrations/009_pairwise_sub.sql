-- Record only. database.Migrate applies the same changes.
ALTER TABLE clients ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'public';
ALTER TABLE clients ADD COLUMN sector_identifier_uri TEXT;
CREATE TABLE IF NOT EXISTS pairwise_subjects (
    sector_id TEXT NOT NULL,
    ppid TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (sector_id, ppid)
);
