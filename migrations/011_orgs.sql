-- Record only. database.Migrate applies the same changes.
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS organization_domains (
    domain TEXT PRIMARY KEY,
    org_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_memberships (
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id, user_id)
);
ALTER TABLE clients ADD COLUMN org_id TEXT;
ALTER TABLE authorization_codes ADD COLUMN org_id TEXT;
