CREATE TABLE public.auth_user (
  id text PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  "emailVerified" boolean NOT NULL DEFAULT false,
  image text,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.auth_session (
  id text PRIMARY KEY,
  token text NOT NULL UNIQUE,
  "userId" text NOT NULL REFERENCES public.auth_user(id) ON DELETE CASCADE,
  "expiresAt" timestamptz NOT NULL,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now(),
  "ipAddress" text,
  "userAgent" text
);
CREATE INDEX auth_session_user ON public.auth_session("userId");
CREATE TABLE public.auth_account (
  id text PRIMARY KEY,
  "accountId" text NOT NULL,
  "providerId" text NOT NULL,
  "userId" text NOT NULL REFERENCES public.auth_user(id) ON DELETE CASCADE,
  "accessToken" text,
  "refreshToken" text,
  "idToken" text,
  "accessTokenExpiresAt" timestamptz,
  "refreshTokenExpiresAt" timestamptz,
  scope text,
  password text,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now(),
  UNIQUE("providerId","accountId")
);
CREATE INDEX auth_account_user ON public.auth_account("userId");
CREATE TABLE public.auth_verification (
  id text PRIMARY KEY,
  identifier text NOT NULL,
  value text NOT NULL,
  "expiresAt" timestamptz NOT NULL,
  "createdAt" timestamptz NOT NULL DEFAULT now(),
  "updatedAt" timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX auth_verification_identifier ON public.auth_verification(identifier);
CREATE TABLE public.auth_rate_limit (
  id text PRIMARY KEY,
  key text NOT NULL UNIQUE,
  count integer NOT NULL,
  "lastRequest" bigint NOT NULL
);
CREATE SCHEMA identity;
CREATE TABLE identity.members (
  account_id text NOT NULL REFERENCES engine.accounts(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES public.auth_user(id) ON DELETE CASCADE,
  role text NOT NULL CHECK(role IN ('owner','editor','viewer')),
  PRIMARY KEY(account_id,user_id)
);
CREATE TABLE identity.api_keys (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES public.auth_user(id) ON DELETE CASCADE,
  account_id text NOT NULL REFERENCES engine.accounts(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  name text NOT NULL,
  scope text NOT NULL CHECK(scope IN ('read','write','manage')),
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  last_used_at bigint,
  parent_key_id text REFERENCES identity.api_keys(id) ON DELETE CASCADE,
  CHECK(expires_at > created_at)
);
CREATE INDEX identity_key_parent ON identity.api_keys(parent_key_id);
CREATE INDEX identity_key_owner ON identity.api_keys(account_id,user_id);
CREATE TABLE identity.invitations (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES engine.accounts(id) ON DELETE CASCADE,
  email text NOT NULL,
  role text NOT NULL CHECK(role IN ('owner','editor','viewer')),
  token_hash text NOT NULL UNIQUE,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  status text NOT NULL CHECK(status IN ('pending','accepted','revoked'))
);
CREATE INDEX identity_invitation_account ON identity.invitations(account_id);
CREATE TABLE identity.attempts (key text PRIMARY KEY,count integer NOT NULL,expires_at bigint NOT NULL);
CREATE INDEX identity_attempts_expiry ON identity.attempts(expires_at);
CREATE TABLE identity.slugs (slug text PRIMARY KEY,account_id text NOT NULL UNIQUE REFERENCES engine.accounts(id) ON DELETE CASCADE);
CREATE TABLE identity.audit (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id text NOT NULL UNIQUE,
  account_id text NOT NULL REFERENCES engine.accounts(id) ON DELETE CASCADE,
  actor text NOT NULL,
  action text NOT NULL,
  subject text NOT NULL,
  occurred_at bigint NOT NULL,
  api_key_id text
);
CREATE INDEX identity_audit_account_sequence ON identity.audit(account_id,sequence);
CREATE TABLE identity.mcp_sessions (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES public.auth_user(id) ON DELETE CASCADE,
  account_id text NOT NULL REFERENCES engine.accounts(id) ON DELETE CASCADE,
  auth_binding text NOT NULL,
  protocol_version text NOT NULL,
  expires_at bigint NOT NULL,
  initialized boolean NOT NULL DEFAULT false
);
CREATE INDEX identity_mcp_expiry ON identity.mcp_sessions(expires_at);
