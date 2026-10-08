-- Record of the live migrator step in database.Migrate.
-- Authorization codes can name the actor the user consented to.
ALTER TABLE authorization_codes ADD COLUMN requested_actor TEXT;
