-- Record only. database.Migrate applies the same ALTER.
ALTER TABLE ciba_requests ADD COLUMN scopes TEXT;
