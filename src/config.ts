import { readFile, stat } from "node:fs/promises";
import type { PoolConfig } from "pg";
import type { IdentityConfig, ProvisionInput } from "./identity";
import { validateLegacyMigrationRuntime } from "./identity-legacy";

/** Secret-file inputs avoid credentials in Compose environment or process arguments. */
export async function secret(name: string, required = true): Promise<string | undefined> {
  const path = process.env[`${name}_FILE`];
  if (!path) { if (required) throw new Error(`missing_${name.toLowerCase()}_file`); return undefined; }
  const info = await stat(path);
  if (!info.isFile() || info.size > 16_384) throw new Error("invalid_secret_file");
  const value = (await readFile(path, "utf8")).replace(/\r?\n$/, "");
  if (!value) throw new Error("empty_secret_file");
  return value;
}

export async function databaseConfig(admin = false): Promise<PoolConfig> {
  const ca = await secret("PGSSL_CA", false);
  const host = process.env.PGHOST ?? "postgres";
  const sslMode = process.env.PGSSLMODE ?? "verify-full";
  if (sslMode !== "disable" && sslMode !== "verify-full") throw new Error("database_tls_requires_verify_full_or_explicit_private_disable");
  if (sslMode === "disable" && !["postgres", "localhost", "127.0.0.1", "::1"].includes(host)) throw new Error("remote_database_requires_verified_tls");
  return {
    host, port: Number(process.env.PGPORT ?? 5432),
    database: process.env.PGDATABASE ?? "tomato", user: admin ? process.env.PGADMIN_USER ?? "postgres" : "tomato_app",
    password: await secret(admin ? "POSTGRES_PASSWORD" : "TOMATO_DB_PASSWORD"),
    ssl: sslMode === "disable" ? false : { ...(ca ? { ca } : {}), rejectUnauthorized: true },
    max: admin ? 1 : 12, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30_000,
    application_name: admin ? "tomato-migrate" : "tomato-runtime",
  };
}

export async function identityConfig(): Promise<IdentityConfig> {
  const baseURL = process.env.TOMATO_ORIGIN;
  if (!baseURL) throw new Error("missing_tomato_origin");
  const config: IdentityConfig = { baseURL, secret: (await secret("TOMATO_AUTH_SECRET"))!, signupEnabled: process.env.TOMATO_SIGNUP_ENABLED === "true" };
  if (process.env.TOMATO_SMTP_HOST) {
    const from = process.env.TOMATO_EMAIL_FROM;
    if (!from) throw new Error("smtp_sender_required");
    const port = Number(process.env.TOMATO_SMTP_PORT ?? 587);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("invalid_smtp_port");
    config.smtp = { host: process.env.TOMATO_SMTP_HOST, port, secure: process.env.TOMATO_SMTP_SECURE === "true", from,
      user: process.env.TOMATO_SMTP_USER, password: await secret("TOMATO_SMTP_PASSWORD", Boolean(process.env.TOMATO_SMTP_USER)), ca: await secret("TOMATO_SMTP_CA", false) };
  }
  for (const provider of ["github", "google"] as const) {
    const prefix = `TOMATO_${provider.toUpperCase()}`;
    const clientId = process.env[`${prefix}_CLIENT_ID`];
    const clientSecret = await secret(`${prefix}_CLIENT_SECRET`, false);
    if (Boolean(clientId) !== Boolean(clientSecret)) throw new Error("incomplete_oauth_configuration");
    if (clientId && clientSecret) config[provider] = { clientId, clientSecret };
  }
  const legacyPepper = await secret("TOMATO_LEGACY_PEPPER", false);
  const expiresAt = process.env.TOMATO_LEGACY_CUTOVER_EXPIRES_AT;
  if (Boolean(legacyPepper) !== Boolean(expiresAt)) throw new Error("incomplete_legacy_cutover_configuration");
  if (legacyPepper && expiresAt) {
    const deadline = Number(expiresAt);
    config.legacyMigration = { pepper: legacyPepper, expiresAt: deadline };
    validateLegacyMigrationRuntime(config.legacyMigration);
  }
  return config;
}

export async function ownerConfig(): Promise<ProvisionInput | undefined> {
  const email = process.env.TOMATO_OWNER_EMAIL;
  if (!email) return undefined;
  const name = process.env.TOMATO_OWNER_NAME;
  if (!name) throw new Error("owner_name_required");
  return { id: process.env.TOMATO_ACCOUNT_ID ?? "main", name: process.env.TOMATO_ACCOUNT_NAME ?? "Tomato",
    owner: { email, name, password: (await secret("TOMATO_OWNER_PASSWORD"))!, emailVerified: process.env.TOMATO_OWNER_EMAIL_VERIFIED === "true" } };
}
