import { betterAuth } from "better-auth";
import { hashPassword } from "better-auth/crypto";
import { createAuthMiddleware, APIError as AuthApiError } from "better-auth/api";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import nodemailer from "nodemailer";
import type { PgDatabase } from "./database";
import type { PoolClient } from "pg";
import { ApiError, identifier, json } from "./validation";
import { verifyCutoverPassword, validateLegacyMigrationRuntime, rehashSuccessfulCutoverLogin, type LegacyMigrationConfig } from "./identity-legacy";

export interface IdentityConfig {
  baseURL: string;
  secret: string;
  allowLoopback?: boolean;
  signupEnabled?: boolean;
  smtp?: { host: string; port: number; secure: boolean; user?: string; password?: string; from: string; ca?: string };
  github?: { clientId: string; clientSecret: string };
  google?: { clientId: string; clientSecret: string };
  legacyMigration?: LegacyMigrationConfig;
}
export interface ProvisionInput { id: string; name: string; owner: { email: string; name: string; password: string; emailVerified?: boolean } }
interface ProvisionResult { account: { id: string; name: string; role: "owner" }; owner: { id: string; username: string } }
export interface ControlledOAuthConfig { issuer: string; clientId: string; clientSecret: string }
export function emailIdentity(value: unknown): string {
  if (typeof value !== "string") throw new ApiError(400, "real_email_required");
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@\u0000-\u001f]+@[^\s@\u0000-\u001f]+\.[^\s@\u0000-\u001f]+$/.test(email)) throw new ApiError(400, "real_email_required");
  return email;
}
export function createAuth(database: PgDatabase, config: IdentityConfig, controlled?: ControlledOAuthConfig) {
  const origin = new URL(config.baseURL);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname);
  if (origin.username || origin.password || origin.search || origin.hash || origin.pathname !== "/" || (origin.protocol !== "https:" && !(config.allowLoopback && loopback && origin.protocol === "http:"))) throw new Error("AUTH baseURL must be an HTTPS origin (HTTP only on explicitly enabled loopback)");
  if (config.secret.length < 32) throw new Error("AUTH_SECRET must contain at least 32 characters");
  for (const provider of [config.github, config.google]) if (provider && (!provider.clientId || !provider.clientSecret)) throw new Error("OAuth requires both actual client ID and secret");
  if (config.legacyMigration) validateLegacyMigrationRuntime(config.legacyMigration);
  if (config.smtp && (!config.smtp.host || !config.smtp.from || !Number.isInteger(config.smtp.port) || config.smtp.port < 1 || config.smtp.port > 65535 || Boolean(config.smtp.user) !== Boolean(config.smtp.password))) throw new Error("Incomplete SMTP configuration");
  if (config.signupEnabled && !config.smtp) throw new Error("Public signup requires configured SMTP email verification");
  if (controlled) {
    const issuer = new URL(controlled.issuer);
    if (process.env.NODE_ENV !== "test" || !config.allowLoopback || !loopback || issuer.protocol !== "https:" || !["localhost", "127.0.0.1", "[::1]"].includes(issuer.hostname) || issuer.pathname !== "/" || issuer.search || issuer.hash || issuer.username || issuer.password || !controlled.clientId || !controlled.clientSecret) throw new Error("controlled_oauth_requires_isolated_test_loopback_and_actual_owned_tls_provider");
  }
  const transporter = config.smtp ? nodemailer.createTransport({ host: config.smtp.host, port: config.smtp.port, secure: config.smtp.secure, requireTLS: !config.smtp.secure, connectionTimeout: 5000, greetingTimeout: 5000, socketTimeout: 10000, dnsTimeout: 5000, auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.password! } : undefined, tls: { rejectUnauthorized: true, ca: config.smtp.ca } }) : null;
  const pending = new Set<Promise<void>>();
  const send = async (to: string, subject: string, text: string): Promise<void> => {
    if (!transporter || !config.smtp) throw new AuthApiError("SERVICE_UNAVAILABLE", { message: "smtp_not_configured" });
    const task = transporter.sendMail({ from: config.smtp.from, to, subject, text }).then(() => undefined);
    pending.add(task); void task.then(() => pending.delete(task), () => pending.delete(task));
    try { await task; } catch { throw new AuthApiError("SERVICE_UNAVAILABLE", { message: "smtp_unavailable" }); }
  };
  const revokeCredentials = async (userId: string, action: string) => {
    const client = await database.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query('SELECT id FROM auth_user WHERE id=$1 FOR UPDATE', [userId]);
      await client.query("DELETE FROM identity.api_keys WHERE user_id=$1", [userId]);
      await client.query("DELETE FROM identity.mcp_sessions WHERE user_id=$1", [userId]);
      await client.query("INSERT INTO identity.audit(id,account_id,actor,action,subject,occurred_at) SELECT $1||'-'||m.account_id,m.account_id,u.id,$3,u.id,$4 FROM identity.members m JOIN public.auth_user u ON u.id=m.user_id WHERE m.user_id=$2", [crypto.randomUUID(), userId, action, Date.now()]);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  };
  const auth = betterAuth({
    appName: "Tomato", baseURL: origin.origin, basePath: "/api/auth", secret: config.secret,
    database: database.pool,
    trustedOrigins: [origin.origin],
    user: { modelName: "auth_user" },
    session: { modelName: "auth_session", expiresIn: 12 * 3600, disableSessionRefresh: true, cookieCache: { enabled: false } },
    account: { modelName: "auth_account", encryptOAuthTokens: true, accountLinking: { enabled: false } },
    verification: { modelName: "auth_verification" },
    emailAndPassword: {
      enabled: true, minPasswordLength: 14, maxPasswordLength: 256, autoSignIn: false,
      requireEmailVerification: true, revokeSessionsOnPasswordReset: true,
      password: { hash: hashPassword, verify: data => verifyCutoverPassword(data, config.legacyMigration) },
      sendResetPassword: ({ user, url }) => send(user.email, "Reset your Tomato password", `Reset your password using this expiring, single-use link:\n${url}\nIf you did not request this, ignore this message.`),
      onPasswordReset: async ({ user }) => { await revokeCredentials(user.id, "password.recovery"); },
    },
    emailVerification: {
      sendOnSignUp: Boolean(transporter), sendOnSignIn: Boolean(transporter), autoSignInAfterVerification: false,
      sendVerificationEmail: ({ user, url }) => send(user.email, "Verify your Tomato email", `Verify your email using this expiring link:\n${url}\nIf you did not request this, ignore this message.`),
    },
    socialProviders: {
      ...(config.github ? { github: { ...config.github, scope: ["read:user", "user:email"], disableSignUp: !config.signupEnabled, requireEmailVerification: true } } : {}),
      ...(config.google ? { google: { ...config.google, disableSignUp: !config.signupEnabled, requireEmailVerification: true } } : {}),
    },
    advanced: { useSecureCookies: origin.protocol === "https:", defaultCookieAttributes: { httpOnly: true, sameSite: "lax", path: "/", secure: origin.protocol === "https:" }, cookies: { session_token: { name: "tomato-session" } }, ipAddress: { ipAddressHeaders: ["x-tomato-client-ip"] } },
    rateLimit: { enabled: true, storage: "database", modelName: "auth_rate_limit", window: 60, max: 100, customRules: { "/sign-in/email": { window: 900, max: 10 }, "/sign-up/email": { window: 900, max: 10 }, "/request-password-reset": { window: 900, max: 10 }, "/send-verification-email": { window: 900, max: 10 } } },
    plugins: controlled ? [genericOAuth({ config: [{ providerId: "tomato-controlled-idp", clientId: controlled.clientId, clientSecret: controlled.clientSecret, authorizationUrl: new URL("/authorize", controlled.issuer).href, tokenUrl: new URL("/token", controlled.issuer).href, userInfoUrl: new URL("/userinfo", controlled.issuer).href, scopes: ["email", "profile"], pkce: true, tokenEndpointAuth: { method: "client_secret_post" }, requireEmailVerification: true, disableSignUp: false }] })] : [],
    hooks: { before: createAuthMiddleware(async ctx => {
      if (ctx.path === "/change-password" && ctx.body) ctx.body.revokeOtherSessions = true;
      for (const field of ["password", "newPassword", "currentPassword"]) if (typeof ctx.body?.[field] === "string" && Buffer.byteLength(ctx.body[field]) > 256) throw new AuthApiError("BAD_REQUEST", { message: "password_requires_14_to_256_bytes" });
      // Uniform service-health gate before account lookup, inside Better Auth's rate-limited handler.
      if (["/sign-up/email", "/request-password-reset", "/send-verification-email"].includes(ctx.path)) {
        if (!transporter) throw new AuthApiError("SERVICE_UNAVAILABLE", { message: "smtp_not_configured" });
        try { await transporter.verify(); } catch { throw new AuthApiError("SERVICE_UNAVAILABLE", { message: "smtp_unavailable" }); }
      }
    }), after: createAuthMiddleware(async ctx => {
      if (ctx.path === "/change-password" && ctx.context.session && ctx.context.returned && !(ctx.context.returned instanceof Error)) await revokeCredentials(ctx.context.session.user.id, "password.change");
      if (ctx.path === "/sign-in/email" && ctx.context.newSession && typeof ctx.body?.password === "string") await rehashSuccessfulCutoverLogin(database, ctx.context.newSession.user.id, ctx.body.password);
    }) },
  });
  const authHandler = async (request: Request): Promise<Response> => {
    const url = new URL(request.url), path = url.pathname.slice("/api/auth".length);
    if (url.origin !== origin.origin) return json({ error: "origin_mismatch" }, 403);
    if (request.headers.has("Authorization")) return json({ error: "cookie_authentication_required" }, 403);
    if (request.method !== "GET" && request.method !== "HEAD" && request.headers.get("Origin") !== origin.origin) return json({ error: "origin_mismatch" }, 403);
    if (path === "/sign-up/email" && !config.signupEnabled) return json({ error: "signup_disabled" }, 403);
    if (!transporter && ["/request-password-reset", "/reset-password", "/send-verification-email", "/sign-up/email"].includes(path)) return json({ error: "smtp_not_configured" }, 503);
    if (path === "/sign-in/social") {
      const input: unknown = await request.clone().json().catch(() => null);
      const provider = input && typeof input === "object" && "provider" in input && typeof input.provider === "string" ? input.provider : "";
      const enabled = provider === "github" ? Boolean(config.github) : provider === "google" ? Boolean(config.google) : provider === "tomato-controlled-idp" && Boolean(controlled);
      if (!enabled) return json({ error: "oauth_provider_not_configured" }, 503);
    }
    const response = await auth.handler(request);
    response.headers.set("Cache-Control", "no-store");
    response.headers.delete("set-auth-token");
    return response;
  };
  const insertProvision = async (client: PoolClient, input: ProvisionInput): Promise<ProvisionResult> => {
    const id = identifier(input.id), email = emailIdentity(input.owner?.email);
    if (!input.name?.trim() || input.name.length > 120 || !input.owner?.name?.trim() || input.owner.name.length > 120) throw new ApiError(400, "invalid_name");
    if (typeof input.owner.password !== "string" || input.owner.password.length < 14 || Buffer.byteLength(input.owner.password) > 256) throw new ApiError(400, "password_requires_14_to_256_bytes");
    if (!transporter && !input.owner.emailVerified) throw new ApiError(503, "verified_email_attestation_or_smtp_required");
    const password = await hashPassword(input.owner.password), userId = crypto.randomUUID();
    await client.query('INSERT INTO public.auth_user(id,name,email,"emailVerified","createdAt","updatedAt") VALUES($1,$2,$3,$4,NOW(),NOW())', [userId, input.owner.name.trim(), email, input.owner.emailVerified === true]);
    await client.query('INSERT INTO public.auth_account(id,"accountId","providerId","userId",password,"createdAt","updatedAt") VALUES($1,$2,\'credential\',$2,$3,NOW(),NOW())', [crypto.randomUUID(), userId, password]);
    await client.query("INSERT INTO engine.accounts(id,name) VALUES($1,$2)", [id, input.name.trim()]);
    await client.query("INSERT INTO identity.members(account_id,user_id,role) VALUES($1,$2,'owner')", [id, userId]);
    await client.query("INSERT INTO identity.audit(id,account_id,actor,action,subject,occurred_at) VALUES($1,$2,'operator','account.provision',$2,$3)", [crypto.randomUUID(), id, Date.now()]);
    return { account: { id, name: input.name.trim(), role: "owner" }, owner: { id: userId, username: email } };
  };
  const provision = async (input: ProvisionInput): Promise<ProvisionResult> => {
    const client = await database.pool.connect();
    let result: ProvisionResult;
    try {
      await client.query("BEGIN");
      result = await insertProvision(client, input);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); if (error && typeof error === "object" && "code" in error && error.code === "23505") throw new ApiError(409, "account_or_user_exists"); throw error; }
    finally { client.release(); }
    if (!input.owner.emailVerified && transporter) await auth.api.sendVerificationEmail({ body: { email: result.owner.username, callbackURL: "/login" } });
    return result;
  };
  const ensureBootstrapOwner = async (input: ProvisionInput): Promise<ProvisionResult> => {
    const id = identifier(input.id), email = emailIdentity(input.owner.email), client = await database.pool.connect();
    let result: ProvisionResult, created = false;
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('tomato.identity.bootstrap',0))");
      const marker = (await client.query<{ original_email: string }>("SELECT original_email FROM identity.bootstraps WHERE account_id=$1", [id])).rows[0];
      if (marker) {
        if (marker.original_email !== email) throw new ApiError(409, "bootstrap_identity_conflict");
        const owner = (await client.query<{ name: string; userId: string; email: string }>('SELECT a.name,u.id AS "userId",u.email FROM engine.accounts a JOIN identity.members m ON m.account_id=a.id AND m.role=\'owner\' JOIN public.auth_user u ON u.id=m.user_id WHERE a.id=$1 ORDER BY u.id LIMIT 1 FOR UPDATE OF a', [id])).rows[0];
        if (!owner) throw new ApiError(409, "bootstrap_workspace_owner_missing");
        result = { account: { id, name: owner.name, role: "owner" }, owner: { id: owner.userId, username: owner.email } };
      } else {
        // Adopt only an exact still-owner provisioning commit from before this completion marker existed.
        const recovered = (await client.query<{ name: string; userId: string; email: string }>('SELECT a.name,u.id AS "userId",u.email FROM engine.accounts a JOIN identity.members m ON m.account_id=a.id AND m.role=\'owner\' JOIN public.auth_user u ON u.id=m.user_id WHERE a.id=$1 AND u.email=$2 AND EXISTS(SELECT 1 FROM identity.audit audit WHERE audit.account_id=a.id AND audit.action=\'account.provision\' AND audit.subject=a.id) FOR UPDATE OF a', [id, email])).rows[0];
        if (recovered) result = { account: { id, name: recovered.name, role: "owner" }, owner: { id: recovered.userId, username: recovered.email } };
        else {
          if ((await client.query("SELECT id FROM engine.accounts WHERE id=$1 UNION ALL SELECT id FROM public.auth_user WHERE email=$2", [id, email])).rows.length) throw new ApiError(409, "bootstrap_identity_conflict");
          result = await insertProvision(client, input); created = true;
        }
        await client.query("INSERT INTO identity.bootstraps(account_id,original_user_id,original_email,created_at) VALUES($1,$2,$3,$4)", [id, result.owner.id, email, Date.now()]);
      }
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); if (error && typeof error === "object" && "code" in error && error.code === "23505") throw new ApiError(409, "bootstrap_identity_conflict"); throw error; }
    finally { client.release(); }
    if (created && !input.owner.emailVerified && transporter) await auth.api.sendVerificationEmail({ body: { email, callbackURL: "/login" } });
    return result;
  };
  return { auth, config, authHandler, provision, ensureBootstrapOwner, revokeCredentials, drain: async () => { await Promise.all(pending); transporter?.close(); } };
}
