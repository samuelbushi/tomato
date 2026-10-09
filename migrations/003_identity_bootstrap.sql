CREATE TABLE identity.bootstraps (
  account_id text PRIMARY KEY REFERENCES engine.accounts(id) ON DELETE CASCADE,
  -- Completion survives legitimate removal/deletion of the initial user.
  original_user_id text NOT NULL CHECK (original_user_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  original_email text NOT NULL CHECK (length(original_email) <= 254),
  created_at bigint NOT NULL
);
