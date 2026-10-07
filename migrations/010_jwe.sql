-- Record only. database.Migrate applies the same ALTERs.
ALTER TABLE clients ADD COLUMN id_token_encrypted_response_alg TEXT;
ALTER TABLE clients ADD COLUMN id_token_encrypted_response_enc TEXT;
ALTER TABLE clients ADD COLUMN userinfo_encrypted_response_alg TEXT;
ALTER TABLE clients ADD COLUMN userinfo_encrypted_response_enc TEXT;
