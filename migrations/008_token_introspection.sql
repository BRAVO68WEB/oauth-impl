-- Record only. database.Migrate applies the same ALTERs.
ALTER TABLE access_tokens ADD COLUMN iat DATETIME;
ALTER TABLE access_tokens ADD COLUMN jti TEXT;
ALTER TABLE access_tokens ADD COLUMN org_id TEXT;
ALTER TABLE access_tokens ADD COLUMN act TEXT;
ALTER TABLE refresh_tokens ADD COLUMN iat DATETIME;
ALTER TABLE refresh_tokens ADD COLUMN jti TEXT;
ALTER TABLE refresh_tokens ADD COLUMN org_id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN act TEXT;
