-- Stable product identities exist before a user has supplied a verified email.
-- Better Auth's email-required schema remains unchanged.
CREATE TABLE identity.subjects (id text PRIMARY KEY, display_name text NOT NULL, imported boolean NOT NULL DEFAULT false);
INSERT INTO identity.subjects(id,display_name) SELECT id,email FROM public.auth_user;
CREATE FUNCTION identity.register_auth_subject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO identity.subjects(id,display_name) VALUES(NEW.id,NEW.email) ON CONFLICT(id) DO NOTHING;
  RETURN NEW;
END $$;
CREATE TRIGGER auth_subject_create BEFORE INSERT ON public.auth_user FOR EACH ROW EXECUTE FUNCTION identity.register_auth_subject();
CREATE FUNCTION identity.delete_auth_subject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM identity.subjects WHERE id=OLD.id;
  RETURN OLD;
END $$;
CREATE TRIGGER auth_subject_delete AFTER DELETE ON public.auth_user FOR EACH ROW EXECUTE FUNCTION identity.delete_auth_subject();
ALTER TABLE identity.members DROP CONSTRAINT members_user_id_fkey;
ALTER TABLE identity.members ADD FOREIGN KEY(user_id) REFERENCES identity.subjects(id) ON DELETE CASCADE;
ALTER TABLE identity.api_keys DROP CONSTRAINT api_keys_user_id_fkey;
ALTER TABLE identity.api_keys ADD FOREIGN KEY(user_id) REFERENCES identity.subjects(id) ON DELETE CASCADE;
ALTER TABLE identity.mcp_sessions DROP CONSTRAINT mcp_sessions_user_id_fkey;
ALTER TABLE identity.mcp_sessions ADD FOREIGN KEY(user_id) REFERENCES identity.subjects(id) ON DELETE CASCADE;
CREATE TABLE identity.legacy_enrollment (
  user_id text PRIMARY KEY REFERENCES identity.subjects(id) ON DELETE CASCADE,
  username text NOT NULL UNIQUE,
  credential text NOT NULL
);
CREATE TABLE identity.legacy_invite_targets (
  user_id text PRIMARY KEY REFERENCES identity.subjects(id) ON DELETE CASCADE,
  username text NOT NULL UNIQUE
);
CREATE TABLE identity.enrollment_claims (
  token_hash text PRIMARY KEY,
  user_id text NOT NULL REFERENCES identity.subjects(id) ON DELETE CASCADE,
  invitation_id text REFERENCES identity.invitations(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  expires_at bigint NOT NULL,
  email text,
  email_token_hash text UNIQUE,
  email_sent boolean NOT NULL DEFAULT false,
  CHECK ((email IS NULL) = (email_token_hash IS NULL))
);
CREATE INDEX enrollment_claim_user ON identity.enrollment_claims(user_id);
CREATE INDEX enrollment_claim_expiry ON identity.enrollment_claims(expires_at);
ALTER TABLE identity.invitations ALTER COLUMN email DROP NOT NULL;
ALTER TABLE identity.invitations ADD COLUMN legacy_username text;
ALTER TABLE identity.invitations ADD CHECK ((email IS NULL) <> (legacy_username IS NULL));
CREATE UNIQUE INDEX legacy_invite_target_lookup ON identity.invitations(legacy_username,id) WHERE legacy_username IS NOT NULL;
