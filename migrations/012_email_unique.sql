-- Record of the live migrator step in database.Migrate.
-- Empty addresses stay allowed. A non-empty mailbox can belong to one user.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower
    ON users (lower(email))
    WHERE email IS NOT NULL AND email <> '';
