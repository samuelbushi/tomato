#!/bin/sh
set -eu
# Local Compose secrets retain host ownership. Copy only this service's mounted
# files into private tmpfs, then replace PID1 with the unprivileged Node process.
mkdir -p /run/tomato-secrets
chmod 700 /run/tomato-secrets
if [ "${TOMATO_CONTAINER_SERVER:-}" = '1' ]; then
  # The prober receives one capability, never database/auth/admin credentials.
  for key in DATABASE_URL POSTGRES_PASSWORD POSTGRES_PASSWORD_FILE TOMATO_DB_PASSWORD_FILE TOMATO_AUTH_SECRET_FILE DATA_KEY DATA_KEY_FILE AUTH_SECRET AUTH_PEPPER ENGINE_TOKEN TOMATO_ENGINE_TOKEN_FILE TOMATO_OWNER_PASSWORD_FILE TOMATO_SMTP_PASSWORD_FILE TOMATO_GITHUB_CLIENT_SECRET_FILE TOMATO_GOOGLE_CLIENT_SECRET_FILE TOMATO_LEGACY_PEPPER_FILE PGHOST PGUSER PGPASSWORD PGDATABASE; do
    if printenv "$key" >/dev/null 2>&1; then
      echo 'prober_forbidden_configuration' >&2
      exit 1
    fi
  done
  cp "${TOMATO_PROBER_TOKEN_FILE:-/run/secrets/prober_token}" /run/tomato-secrets/prober_token
  chmod 600 /run/tomato-secrets/prober_token
  chown node:node /run/tomato-secrets/prober_token
  export TOMATO_PROBER_TOKEN_FILE=/run/tomato-secrets/prober_token
else
  for key in TOMATO_DB_PASSWORD_FILE TOMATO_AUTH_SECRET_FILE DATA_KEY_FILE TOMATO_ENGINE_TOKEN_FILE TOMATO_PROBER_TOKEN_FILE TOMATO_OWNER_PASSWORD_FILE TOMATO_SMTP_PASSWORD_FILE TOMATO_SMTP_CA_FILE TOMATO_GITHUB_CLIENT_SECRET_FILE TOMATO_GOOGLE_CLIENT_SECRET_FILE TOMATO_LEGACY_PEPPER_FILE PGSSL_CA_FILE; do
    value="$(printenv "$key" || true)"
    if [ -n "$value" ]; then
      cp "$value" "/run/tomato-secrets/$key"
      chmod 600 "/run/tomato-secrets/$key"
      chown node:node "/run/tomato-secrets/$key"
      export "$key=/run/tomato-secrets/$key"
    fi
  done
fi
chown node:node /run/tomato-secrets
exec gosu node "$@"
