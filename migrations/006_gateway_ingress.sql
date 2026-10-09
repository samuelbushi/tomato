CREATE TABLE identity.gateway_nonces (
  key_id text NOT NULL,
  nonce text NOT NULL,
  expires_at bigint NOT NULL,
  PRIMARY KEY(key_id,nonce)
);
CREATE INDEX gateway_nonce_expiry ON identity.gateway_nonces(expires_at);
