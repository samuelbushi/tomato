import { createHmac } from "node:crypto";
import { isIP } from "node:net";
import { hashPassword } from "better-auth/crypto";
import { isAPIError } from "better-auth/api";
import { createAuth, emailIdentity, type ControlledOAuthConfig, type IdentityConfig, type ProvisionInput } from "./auth";
import type { PgDatabase, PgTransaction } from "./database";
import { ApiError, body, digest, identifier, integer, json } from "./validation";
import type { AccountRole, AccountSummary, ApiKeyScope, ApiKeyView, AuditView, InvitationView, Principal } from "./product-types";
export type { ControlledOAuthConfig, IdentityConfig, ProvisionInput } from "./auth";
export interface IdentityService {
  fetch(request: Request): Promise<Response>;
  authHandler(request: Request): Promise<Response>;
  provision(input: ProvisionInput): Promise<{ account: AccountSummary; owner: { id: string; username: string } }>;
  ensureBootstrapOwner(input: ProvisionInput): Promise<{ account: AccountSummary; owner: { id: string; username: string } }>;
  drain(): Promise<void>;
  capabilities: { signup: boolean; email: boolean; github: boolean; google: boolean };
}
type Queryable = Pick<PgTransaction, "query">;
type UserRow = { id: string; email: string; emailVerified: boolean };
type KeyRow = { id: string; user_id: string; account_id: string; token_hash: string; name: string; scope: ApiKeyScope; created_at: number; expires_at: number; last_used_at: number | null; parent_key_id: string | null };
type InviteRow = { id: string; account_id: string; email: string; role: AccountRole; token_hash: string; created_at: number; expires_at: number; status: "pending" | "accepted" | "revoked" };
type McpRow = { id: string; user_id: string; account_id: string; auth_binding: string; protocol_version: string; expires_at: number; initialized: boolean };
const LEVEL: Record<ApiKeyScope, number> = { read: 0, write: 1, manage: 2 };
const PROTOCOL = "2025-11-25";
export function randomToken(prefix = ""): string { return prefix + Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url"); }
function text(value: unknown, name: string, max = 120): string { if (typeof value !== "string" || !value.trim() || value.length > max || /[\u0000-\u001f]/.test(value)) throw new ApiError(400, `invalid_${name}`); return value.trim(); }
function credentialPassword(value: unknown): string { if (typeof value !== "string" || value.length < 14 || Buffer.byteLength(value) > 256) throw new ApiError(400, "password_requires_14_to_256_bytes"); return value; }
function role(value: unknown): AccountRole { if (value !== "owner" && value !== "editor" && value !== "viewer") throw new ApiError(400, "invalid_role"); return value; }
function auditKey(input: Record<string, unknown>): string | null { const key = input.apiKeyId ?? input.sourceKeyId; return key === undefined || key === null ? null : identifier(String(key)); }
function keyView(row: KeyRow): ApiKeyView { return { id: row.id, name: row.name, scope: row.scope, createdAt: row.created_at, expiresAt: row.expires_at, lastUsedAt: row.last_used_at, parentKeyId: row.parent_key_id }; }
function inviteView(row: InviteRow): InvitationView { return { id: row.id, username: row.email, role: row.role, createdAt: row.created_at, expiresAt: row.expires_at, status: row.status === "pending" && row.expires_at <= Date.now() ? "expired" : row.status }; }
export function createIdentity(database: PgDatabase, config: IdentityConfig): IdentityService { return createIdentityService(database, config); }
/** Never selectable by production environment/config; actual TLS controlled IdP acceptance only. */
export function createControlledOAuthIdentity(database: PgDatabase, config: IdentityConfig, provider: ControlledOAuthConfig): IdentityService { return createIdentityService(database, config, provider); }
function createIdentityService(database: PgDatabase, config: IdentityConfig, controlled?: ControlledOAuthConfig): IdentityService {
  const maintained = createAuth(database, config, controlled);
  const user = async (db: Queryable, id: string): Promise<UserRow> => { const row = (await db.query<UserRow>('SELECT id,email,"emailVerified" FROM public.auth_user WHERE id=$1', [id]))[0]; if (!row) throw new ApiError(404, "user_not_found"); return row; };
  const memberships = (db: Queryable, userId: string) => db.query<AccountSummary>("SELECT a.id,a.name,m.role FROM engine.accounts a JOIN identity.members m ON a.id=m.account_id WHERE m.user_id=$1 ORDER BY a.name,a.id", [userId]);
  const appendAudit = async (db: Queryable, accountId: string, actor: string, action: string, subject: string, key: string | null = null) => { await db.query("INSERT INTO identity.audit(id,account_id,actor,action,subject,occurred_at,api_key_id) VALUES($1,$2,$3,$4,$5,$6,$7)", [crypto.randomUUID(), accountId, actor, action, subject, Date.now(), key]); };
  const ensureVerifiedWorkspace = async (userId: string, sessionId: string): Promise<AccountSummary[]> => {
    const client = await database.pool.connect();
    try {
      await client.query("BEGIN");
      const owner = (await client.query<{ name: string; email: string; emailVerified: boolean }>('SELECT name,email,"emailVerified" FROM public.auth_user WHERE id=$1 FOR UPDATE', [userId])).rows[0];
      if (!owner?.emailVerified || !(await client.query('SELECT id FROM public.auth_session WHERE id=$1 AND "userId"=$2 AND "expiresAt">NOW() FOR SHARE', [sessionId, userId])).rowCount) throw new ApiError(401, "unauthorized");
      const accounts = (await client.query<AccountSummary>("SELECT a.id,a.name,m.role FROM engine.accounts a JOIN identity.members m ON a.id=m.account_id WHERE m.user_id=$1 ORDER BY a.name,a.id", [userId])).rows;
      if (!accounts.length) {
        const id = crypto.randomUUID(), name = `${owner.name}'s workspace`.slice(0, 120);
        await client.query("INSERT INTO engine.accounts(id,name) VALUES($1,$2)", [id, name]);
        await client.query("INSERT INTO identity.members(account_id,user_id,role) VALUES($1,$2,'owner')", [id, userId]);
        await client.query("INSERT INTO identity.audit(id,account_id,actor,action,subject,occurred_at) VALUES($1,$2,$3,'account.create',$2,$4)", [crypto.randomUUID(), id, userId, Date.now()]);
        accounts.push({ id, name, role: "owner" });
      }
      await client.query("COMMIT");
      return accounts;
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  };
  const validateChain = async (db: Queryable, key: KeyRow) => {
    const seen = new Set<string>(); let current = key;
    for (let depth = 0; depth < 20; depth++) {
      if (seen.has(current.id) || current.expires_at <= Date.now()) throw new ApiError(401, "unauthorized");
      seen.add(current.id); if (!current.parent_key_id) return depth + 1;
      const parent = (await db.query<KeyRow>("SELECT * FROM identity.api_keys WHERE id=$1 AND user_id=$2 AND account_id=$3", [current.parent_key_id, key.user_id, key.account_id]))[0];
      if (!parent || current.expires_at > parent.expires_at || LEVEL[current.scope] > LEVEL[parent.scope]) throw new ApiError(401, "unauthorized");
      current = parent;
    }
    throw new ApiError(401, "unauthorized");
  };
  const authorize = async (db: Queryable, input: Record<string, unknown>, owner = false) => {
    const actor = await user(db, identifier(String(input.actorId ?? ""))), accountId = identifier(String(input.accountId ?? ""));
    const membership = (await memberships(db, actor.id)).find(item => item.id === accountId);
    if (!membership) throw new ApiError(404, "account_not_found");
    if (owner && membership.role !== "owner") throw new ApiError(403, "owner_required");
    const keyId = auditKey(input);
    if (keyId) { const key = (await db.query<KeyRow>("SELECT * FROM identity.api_keys WHERE id=$1 AND user_id=$2 AND account_id=$3", [keyId, actor.id, accountId]))[0]; if (!key) throw new ApiError(401, "unauthorized"); await validateChain(db, key); }
    if (input.authSessionId !== undefined && input.authSessionId !== null && !(await db.query('SELECT id FROM public.auth_session WHERE id=$1 AND "userId"=$2 AND "expiresAt">NOW()', [input.authSessionId, actor.id])).length) throw new ApiError(401, "unauthorized");
    return { actor, accountId, membership };
  };
  const transaction = <T>(input: Record<string, unknown>, fn: (tx: PgTransaction) => Promise<T>) => database.transaction(identifier(String(input.accountId ?? "")), fn);
  const authenticate = async (input: Record<string, unknown>): Promise<Principal> => {
    let key: KeyRow | undefined, sessionId: string | null = null, userId: string;
    if (typeof input.token === "string") {
      if (!input.token.startsWith("tomato_key_") || input.token.length !== 54) throw new ApiError(401, "unauthorized");
      key = (await database.query<KeyRow>("SELECT * FROM identity.api_keys WHERE token_hash=$1", [await digest(input.token)]))[0];
      if (!key) throw new ApiError(401, "unauthorized"); await validateChain(database, key); userId = key.user_id;
    } else {
      const headers = new Headers(); if (typeof input.cookie === "string") headers.set("Cookie", input.cookie);
      const session = await maintained.auth.api.getSession({ headers, query: { disableCookieCache: true } });
      if (!session || !session.user.emailVerified) throw new ApiError(401, "unauthorized");
      userId = session.user.id; sessionId = session.session.id;
    }
    const actor = await user(database, userId);
    let accounts = await memberships(database, userId);
    if (sessionId && !accounts.length) accounts = await ensureVerifiedWorkspace(userId, sessionId);
    const requested = input.accountId === undefined ? null : identifier(String(input.accountId));
    const account = requested ? accounts.find(item => item.id === requested) ?? null : null;
    if (requested && !account) throw new ApiError(404, "account_not_found");
    if (key && (!accounts.some(item => item.id === key!.account_id) || (requested && key.account_id !== requested))) throw new ApiError(404, "account_not_found");
    if (key) await database.query("UPDATE identity.api_keys SET last_used_at=$1 WHERE id=$2", [Date.now(), key.id]);
    return { actor: { id: actor.id, username: actor.email }, accounts: key ? accounts.filter(item => item.id === key!.account_id) : accounts, account, sessionId, csrfToken: sessionId ? createHmac("sha256", config.secret).update(`tomato-domain-csrf:${sessionId}`).digest("base64url") : "", apiKeyId: key?.id ?? null, apiKeyExpiresAt: key?.expires_at ?? null, scope: key?.scope ?? "manage" };
  };
  const invitation = async (db: Queryable, token: unknown): Promise<InviteRow> => { if (typeof token !== "string" || !/^tomato_invite_[A-Za-z0-9_-]{43}$/.test(token)) throw new ApiError(404, "invitation_not_found"); const row = (await db.query<InviteRow>("SELECT * FROM identity.invitations WHERE token_hash=$1", [await digest(token)]))[0]; if (!row || row.status !== "pending" || row.expires_at <= Date.now()) throw new ApiError(404, "invitation_not_found"); return row; };
  const mcpBinding = async (db: Queryable, input: Record<string, unknown>) => {
    const { actor, accountId } = await authorize(db, input), binding = identifier(String(input.authBinding ?? ""));
    const key = (await db.query<KeyRow>("SELECT * FROM identity.api_keys WHERE id=$1 AND user_id=$2 AND account_id=$3", [binding, actor.id, accountId]))[0];
    if (key) { await validateChain(db, key); return { userId: actor.id, accountId, binding, expiresAt: key.expires_at }; }
    const session = (await db.query<{ expiresAt: Date }>('SELECT "expiresAt" FROM public.auth_session WHERE id=$1 AND "userId"=$2 AND "expiresAt">NOW()', [binding, actor.id]))[0];
    if (!session) throw new ApiError(404, "mcp_session_not_found");
    return { userId: actor.id, accountId, binding, expiresAt: session.expiresAt.getTime() };
  };
  const mcpView = (row: McpRow) => ({ sessionId: row.id, protocolVersion: row.protocol_version, expiresAt: row.expires_at, initialized: row.initialized });
  const dispatch = async (path: string, input: Record<string, unknown>): Promise<unknown> => {
    if (path === "/authenticate") return authenticate(input);
    if (path === "/provision") {
      if (!input.owner || typeof input.owner !== "object" || Array.isArray(input.owner)) throw new ApiError(400, "invalid_owner");
      const owner = input.owner;
      return maintained.provision({ id: String(input.id ?? ""), name: text(input.name, "name"), owner: { email: emailIdentity("email" in owner ? owner.email : undefined), name: text("name" in owner ? owner.name : undefined, "name"), password: credentialPassword("password" in owner ? owner.password : undefined), emailVerified: "emailVerified" in owner && owner.emailVerified === true } });
    }
    if (path === "/password" || path === "/recovery") {
      const userId = identifier(String(input.userId ?? "")), actor = await user(database, userId), newPassword = credentialPassword(input.newPassword), authContext = await maintained.auth.$context;
      const client = await database.pool.connect();
      try {
        await client.query("BEGIN"); await client.query("SELECT id FROM public.auth_user WHERE id=$1 FOR UPDATE", [userId]);
        const credential = (await client.query<{ id: string; password: string }>('SELECT id,password FROM public.auth_account WHERE "userId"=$1 AND "providerId"=\'credential\' FOR UPDATE', [userId])).rows[0];
        if (!credential) throw new ApiError(400, "password_login_not_configured");
        if (path === "/password" && (typeof input.currentPassword !== "string" || Buffer.byteLength(input.currentPassword) > 256 || !await authContext.password.verify({ hash: credential.password, password: input.currentPassword }))) throw new ApiError(401, "invalid_credentials");
        await client.query('UPDATE public.auth_account SET password=$1,"updatedAt"=NOW() WHERE id=$2', [await hashPassword(newPassword), credential.id]);
        await client.query('DELETE FROM public.auth_session WHERE "userId"=$1 AND ($2::text IS NULL OR id<>$2)', [userId, path === "/password" && typeof input.sessionId === "string" ? input.sessionId : null]);
        await client.query("DELETE FROM identity.api_keys WHERE user_id=$1", [userId]); await client.query("DELETE FROM identity.mcp_sessions WHERE user_id=$1", [userId]);
        await client.query("INSERT INTO identity.audit(id,account_id,actor,action,subject,occurred_at) SELECT $1||'-'||account_id,account_id,$2,$3,$4,$5 FROM identity.members WHERE user_id=$4", [crypto.randomUUID(), path === "/password" ? actor.id : "operator", path === "/password" ? "password.change" : "password.recovery", userId, Date.now()]);
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
      return path === "/password" ? { changed: true } : { reset: true, sessionsRevoked: true, apiKeysRevoked: true };
    }
    if (path === "/sessions") {
      const rows = await database.query<{ id: string; createdAt: Date; expiresAt: Date }>('SELECT id,"createdAt","expiresAt" FROM public.auth_session WHERE "userId"=$1 AND "expiresAt">NOW() ORDER BY "createdAt" DESC', [identifier(String(input.userId ?? ""))]);
      return { sessions: rows.map(row => ({ id: row.id, createdAt: row.createdAt.getTime(), expiresAt: row.expiresAt.getTime(), current: row.id === input.sessionId })) };
    }
    if (path === "/logout") { await database.query("DELETE FROM public.auth_session WHERE id=$1", [input.sessionId]); return { revoked: true }; }
    if (path === "/sessions/revoke" || path === "/sessions/revoke-others") {
      const userId = identifier(String(input.userId ?? ""));
      if (path === "/sessions/revoke") { if (!(await database.query('DELETE FROM public.auth_session WHERE id=$1 AND "userId"=$2 RETURNING id', [identifier(String(input.id ?? "")), userId])).length) throw new ApiError(404, "session_not_found"); }
      else await database.query('DELETE FROM public.auth_session WHERE "userId"=$1 AND ($2::text IS NULL OR id<>$2)', [userId, typeof input.sessionId === "string" ? input.sessionId : null]);
      return { revoked: true };
    }
    if (path === "/invitations/preview") { const row = await invitation(database, input.token), account = (await database.query<{ name: string }>("SELECT name FROM engine.accounts WHERE id=$1", [row.account_id]))[0]; return { invitation: inviteView(row), accountName: account!.name, existingUser: Boolean((await database.query("SELECT id FROM public.auth_user WHERE email=$1", [row.email])).length) }; }
    if (path === "/invitations/register") {
      const row = await invitation(database, input.token); if (!config.smtp) throw new ApiError(503, "smtp_not_configured");
      const clientIp = typeof input.trustedClientIp === "string" ? input.trustedClientIp : "", ipVersion = isIP(clientIp);
      if (!ipVersion) throw new ApiError(503, "trusted_caller_address_required");
      const canonicalIp = ipVersion === 6 ? new URL(`http://[${clientIp}]/`).hostname : clientIp;
      const callerKey = `invitation-register-caller:${createHmac("sha256", config.secret).update(canonicalIp).digest("hex")}`, invitationKey = `invitation-register:${row.id}`, now = Date.now();
      await database.transaction(row.account_id, async tx => {
        await invitation(tx, input.token);
        const attempts = await tx.query<{ key: string; count: number }>("INSERT INTO identity.attempts(key,count,expires_at) VALUES($1,1,$3),($2,1,$3) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN identity.attempts.expires_at<=$4 THEN 1 ELSE identity.attempts.count+1 END,expires_at=CASE WHEN identity.attempts.expires_at<=$4 THEN EXCLUDED.expires_at ELSE identity.attempts.expires_at END RETURNING key,count", [callerKey, invitationKey, now + 15 * 60000, now]);
        if (attempts.some(attempt => attempt.count > (attempt.key === callerKey ? 10 : 3))) throw new ApiError(429, "invitation_registration_rate_limited");
      });
      // Native Better Auth APIs run maintained hooks, not the HTTP router's rate limiter.
      // Commit admission first: genuine SMTP failures still consume the invitation/caller budget.
      const callbackURL = new URL("/login", config.baseURL); callbackURL.searchParams.set("next", `/invite/${String(input.token)}`);
      await maintained.auth.api.signUpEmail({ headers: { Origin: callbackURL.origin, "X-Tomato-Client-IP": clientIp }, body: { email: row.email, name: text(input.name, "name"), password: credentialPassword(input.password), callbackURL: callbackURL.href } });
      return { verificationRequired: true };
    }
    if (path === "/invitations/accept") {
      const row = await invitation(database, input.token), actor = await user(database, identifier(String(input.userId ?? "")));
      if (!actor.emailVerified || actor.email !== row.email) throw new ApiError(403, "invited_email_required");
      if (!(await database.query('SELECT id FROM public.auth_session WHERE id=$1 AND "userId"=$2 AND "expiresAt">NOW()', [input.sessionId, actor.id])).length) throw new ApiError(401, "unauthorized");
      return database.transaction(row.account_id, async tx => { const latest = await invitation(tx, input.token); if ((await tx.query("SELECT user_id FROM identity.members WHERE account_id=$1 AND user_id=$2", [row.account_id, actor.id])).length) throw new ApiError(409, "already_member"); await tx.query("INSERT INTO identity.members(account_id,user_id,role) VALUES($1,$2,$3)", [row.account_id, actor.id, latest.role]); await tx.query("UPDATE identity.invitations SET status='accepted' WHERE id=$1", [row.id]); await appendAudit(tx, row.account_id, actor.id, "invitation.accept", row.id); return { accepted: true, accountId: row.account_id }; });
    }
    if (path === "/slugs/lookup") return { accountId: (await database.query<{ account_id: string }>("SELECT account_id FROM identity.slugs WHERE slug=$1", [input.slug]))[0]?.account_id ?? null };
    if (path === "/slugs/claim" || path === "/slugs/release") return transaction(input, async tx => {
      const accountId = identifier(String(input.accountId ?? ""));
      if (path === "/slugs/release") { await tx.query("DELETE FROM identity.slugs WHERE account_id=$1 AND ($2::text IS NULL OR slug=$2)", [accountId, input.slug ?? null]); return { released: true }; }
      const slug = String(input.slug ?? ""); if (!/^[a-z0-9][a-z0-9-]{2,62}$/.test(slug)) throw new ApiError(400, "invalid_status_slug");
      const previous = (await tx.query<{ slug: string }>("SELECT slug FROM identity.slugs WHERE account_id=$1", [accountId]))[0]; if (previous && previous.slug !== slug) throw new ApiError(409, "status_slug_immutable_until_unpublished");
      const claimed = await tx.query<{ account_id: string }>("INSERT INTO identity.slugs(slug,account_id) VALUES($1,$2) ON CONFLICT(slug) DO UPDATE SET slug=excluded.slug RETURNING account_id", [slug, accountId]); if (claimed[0]?.account_id !== accountId) throw new ApiError(409, "status_slug_unavailable"); return { claimed: true };
    });
    if (path === "/audit/append") return transaction(input, async tx => { const actor = input.actorId === undefined ? identifier(String(input.actor ?? "")) : (await authorize(tx, input)).actor.id; await appendAudit(tx, String(input.accountId), actor, text(input.action, "action"), text(input.subject, "subject", 256), auditKey(input)); return { recorded: true }; });
    return transaction(input, async tx => {
      const auth = await authorize(tx, input, ["/workspace/rename", "/members/change", "/invitations", "/invitations/create", "/invitations/revoke"].includes(path));
      const { actor, accountId, membership } = auth, now = Date.now();
      if (path === "/workspace/get") return { account: membership };
      if (path === "/workspace/rename") { const name = text(input.name, "account_name"); await tx.query("UPDATE engine.accounts SET name=$1 WHERE id=$2", [name, accountId]); await appendAudit(tx, accountId, actor.id, "account.rename", accountId, auditKey(input)); return { account: { ...membership, name } }; }
      if (path === "/management/admit") { const credential = input.apiKeyId ?? input.authSessionId; if (typeof credential !== "string") throw new ApiError(401, "unauthorized"); const key = `management:${actor.id}:${credential}`; const row = (await tx.query<{ count: number; expires_at: number }>("INSERT INTO identity.attempts(key,count,expires_at) VALUES($1,1,$2) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN identity.attempts.expires_at<=$3 THEN 1 ELSE identity.attempts.count+1 END,expires_at=CASE WHEN identity.attempts.expires_at<=$3 THEN excluded.expires_at ELSE identity.attempts.expires_at END RETURNING count,expires_at", [key, now + 60000, now]))[0]!; if (row.count > 120) throw new ApiError(429, "management_rate_limited"); return { admitted: true, limit: 120, resetsAt: row.expires_at }; }
      if (path === "/members") return { members: await tx.query('SELECT u.id AS "userId",u.email AS username,m.role FROM identity.members m JOIN public.auth_user u ON u.id=m.user_id WHERE m.account_id=$1 ORDER BY u.email', [accountId]) };
      if (path === "/members/change") {
        const userId = identifier(String(input.userId ?? "")), next = input.remove === true ? null : role(input.role), member = (await tx.query<{ role: AccountRole }>("SELECT role FROM identity.members WHERE account_id=$1 AND user_id=$2", [accountId, userId]))[0];
        if (!member) throw new ApiError(404, "member_not_found");
        if (member.role === "owner" && next !== "owner" && (await tx.query<{ count: number }>("SELECT count(*) FROM identity.members WHERE account_id=$1 AND role='owner'", [accountId]))[0]!.count <= 1) throw new ApiError(409, "last_owner_required");
        if (next) await tx.query("UPDATE identity.members SET role=$1 WHERE account_id=$2 AND user_id=$3", [next, accountId, userId]);
        else { await tx.query("DELETE FROM identity.members WHERE account_id=$1 AND user_id=$2", [accountId, userId]); await tx.query("DELETE FROM identity.api_keys WHERE account_id=$1 AND user_id=$2", [accountId, userId]); await tx.query("DELETE FROM identity.mcp_sessions WHERE account_id=$1 AND user_id=$2", [accountId, userId]); }
        await appendAudit(tx, accountId, actor.id, next ? "member.role" : "member.remove", userId, auditKey(input)); return { changed: true };
      }
      if (path === "/invitations") return { invitations: (await tx.query<InviteRow>("SELECT * FROM identity.invitations WHERE account_id=$1 ORDER BY created_at DESC LIMIT 100", [accountId])).map(inviteView) };
      if (path === "/invitations/create") {
        if ((await tx.query<{ count: number }>("SELECT count(*) FROM identity.invitations WHERE account_id=$1 AND status='pending' AND expires_at>$2", [accountId, now]))[0]!.count >= 100) throw new ApiError(409, "invitation_limit");
        const token = randomToken("tomato_invite_"), row: InviteRow = { id: crypto.randomUUID(), account_id: accountId, email: emailIdentity(input.username), role: role(input.role), token_hash: await digest(token), created_at: now, expires_at: now + 7 * 86400000, status: "pending" };
        await tx.query("INSERT INTO identity.invitations(id,account_id,email,role,token_hash,created_at,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", [row.id, accountId, row.email, row.role, row.token_hash, row.created_at, row.expires_at, row.status]); await appendAudit(tx, accountId, actor.id, "invitation.create", row.id, auditKey(input)); return { invitation: inviteView(row), invitationToken: token };
      }
      if (path === "/invitations/revoke") { if (!(await tx.query("UPDATE identity.invitations SET status='revoked' WHERE id=$1 AND account_id=$2 RETURNING id", [identifier(String(input.id ?? "")), accountId])).length) throw new ApiError(404, "invitation_not_found"); await appendAudit(tx, accountId, actor.id, "invitation.revoke", String(input.id), auditKey(input)); return { revoked: true }; }
      if (path === "/api-keys") return { keys: (await tx.query<KeyRow>("SELECT * FROM identity.api_keys WHERE account_id=$1 AND user_id=$2 AND expires_at>$3 ORDER BY created_at DESC", [accountId, actor.id, now])).map(keyView) };
      if (path === "/api-keys/create") {
        const scope = input.scope; if (scope !== "read" && scope !== "write" && scope !== "manage") throw new ApiError(400, "invalid_scope");
        if (scope === "write" && membership.role === "viewer") throw new ApiError(403, "editor_required");
        const sourceId = typeof input.sourceKeyId === "string" ? identifier(input.sourceKeyId) : null;
        if (input.apiKeyId && sourceId !== input.apiKeyId) throw new ApiError(403, "source_key_required");
        const source = sourceId ? (await tx.query<KeyRow>("SELECT * FROM identity.api_keys WHERE id=$1 AND user_id=$2 AND account_id=$3", [sourceId, actor.id, accountId]))[0] : undefined;
        if (sourceId && !source) throw new ApiError(401, "source_key_not_available");
        if (source && await validateChain(tx, source) >= 20) throw new ApiError(400, "source_key_depth_exceeded");
        let expiresAt = input.expiresAt === undefined ? now + integer(input.expiresInDays ?? 30, 1, 90, "api_key_expiry") * 86400000 : integer(input.expiresAt, now + 1, now + 90 * 86400000, "api_key_expiry");
        if (source) { if (LEVEL[scope] > LEVEL[source.scope]) throw new ApiError(403, "source_key_scope_exceeded"); if (input.expiresAt === undefined && input.expiresInDays === undefined) expiresAt = Math.min(expiresAt, source.expires_at); if (expiresAt > source.expires_at) throw new ApiError(403, "source_key_expiry_exceeded"); }
        if ((await tx.query<{ count: number }>("SELECT count(*) FROM identity.api_keys WHERE user_id=$1 AND account_id=$2 AND expires_at>$3", [actor.id, accountId, now]))[0]!.count >= 20) throw new ApiError(409, "api_key_limit");
        const token = randomToken("tomato_key_"), row: KeyRow = { id: crypto.randomUUID(), user_id: actor.id, account_id: accountId, token_hash: await digest(token), name: text(input.name, "api_key_name"), scope, created_at: now, expires_at: expiresAt, last_used_at: null, parent_key_id: sourceId };
        await tx.query("INSERT INTO identity.api_keys(id,user_id,account_id,token_hash,name,scope,created_at,expires_at,parent_key_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", [row.id, actor.id, accountId, row.token_hash, row.name, scope, now, expiresAt, sourceId]); await appendAudit(tx, accountId, actor.id, "api_key.create", row.id, auditKey(input)); return { key: keyView(row), apiKey: token };
      }
      if (path === "/api-keys/revoke") { const id = identifier(String(input.id ?? "")); if (!(await tx.query("SELECT id FROM identity.api_keys WHERE id=$1 AND user_id=$2 AND account_id=$3", [id, actor.id, accountId])).length) throw new ApiError(404, "api_key_not_found"); await tx.query("WITH RECURSIVE descendants(id) AS (SELECT id FROM identity.api_keys WHERE id=$1 UNION SELECT k.id FROM identity.api_keys k JOIN descendants d ON k.parent_key_id=d.id WHERE k.user_id=$2 AND k.account_id=$3) DELETE FROM identity.api_keys WHERE id IN (SELECT id FROM descendants) AND user_id=$2 AND account_id=$3", [id, actor.id, accountId]); await appendAudit(tx, accountId, actor.id, "api_key.revoke", id, auditKey(input)); return { revoked: true }; }
      if (path.startsWith("/mcp/")) {
        const binding = await mcpBinding(tx, input); if (input.protocolVersion !== undefined && input.protocolVersion !== PROTOCOL) throw new ApiError(400, "unsupported_protocol_version");
        if (path === "/mcp/create") { const row: McpRow = { id: randomToken(), user_id: actor.id, account_id: accountId, auth_binding: binding.binding, protocol_version: PROTOCOL, expires_at: Math.min(binding.expiresAt, now + 3600000), initialized: false }; await tx.query("INSERT INTO identity.mcp_sessions(id,user_id,account_id,auth_binding,protocol_version,expires_at,initialized) VALUES($1,$2,$3,$4,$5,$6,$7)", [row.id, actor.id, accountId, row.auth_binding, PROTOCOL, row.expires_at, false]); return mcpView(row); }
        const row = (await tx.query<McpRow>("SELECT * FROM identity.mcp_sessions WHERE id=$1 AND user_id=$2 AND account_id=$3 AND auth_binding=$4", [identifier(String(input.sessionId ?? "")), actor.id, accountId, binding.binding]))[0];
        if (!row || row.expires_at <= now || row.expires_at > binding.expiresAt) throw new ApiError(404, "mcp_session_not_found");
        if (path === "/mcp/delete") { await tx.query("DELETE FROM identity.mcp_sessions WHERE id=$1", [row.id]); return { deleted: true }; }
        if (path === "/mcp/initialized") { await tx.query("UPDATE identity.mcp_sessions SET initialized=true WHERE id=$1", [row.id]); return mcpView({ ...row, initialized: true }); }
        if (path === "/mcp/validate") { if (input.requireInitialized === true && !row.initialized) throw new ApiError(409, "mcp_session_not_initialized"); return mcpView(row); }
      }
      if (path === "/audit") {
        const limit = integer(input.limit ?? 100, 1, 100, "audit_limit"); let before = input.before === undefined ? Number.MAX_SAFE_INTEGER : integer(input.before, 0, Number.MAX_SAFE_INTEGER, "audit_before"), cursor = Number.MAX_SAFE_INTEGER;
        if (input.cursor !== undefined && input.cursor !== null) { if (typeof input.cursor !== "string" || input.cursor.length > 128) throw new ApiError(400, "invalid_audit_cursor"); let decoded: unknown; try { decoded = JSON.parse(atob(input.cursor)); } catch { throw new ApiError(400, "invalid_audit_cursor"); } if (!Array.isArray(decoded) || decoded.length !== 3 || decoded[0] !== accountId) throw new ApiError(400, "invalid_audit_cursor"); const nextBefore = integer(decoded[2], 0, Number.MAX_SAFE_INTEGER, "audit_cursor"); if (input.before !== undefined && nextBefore !== before) throw new ApiError(400, "invalid_audit_cursor"); before = nextBefore; cursor = integer(decoded[1], 1, Number.MAX_SAFE_INTEGER, "audit_cursor"); }
        const rows = await tx.query<{ sequence: number; id: string; actor: string; action: string; subject: string; occurred_at: number; api_key_id: string | null }>("SELECT sequence,id,actor,action,subject,occurred_at,api_key_id FROM identity.audit WHERE account_id=$1 AND occurred_at<$2 AND sequence<$3 ORDER BY sequence DESC LIMIT $4", [accountId, before, cursor, limit + 1]), page = rows.slice(0, limit);
        const entries: AuditView[] = page.map(row => ({ id: row.id, actor: row.actor, action: row.action, subject: row.subject, occurredAt: row.occurred_at, apiKeyId: row.api_key_id })); return { entries, cursor: rows.length > limit ? btoa(JSON.stringify([accountId, page[page.length - 1]!.sequence, before])) : null };
      }
      throw new ApiError(404, "not_found");
    });
  };
  return { capabilities: { signup: Boolean(config.signupEnabled), email: Boolean(config.smtp), github: Boolean(config.github), google: Boolean(config.google) }, provision: maintained.provision, ensureBootstrapOwner: maintained.ensureBootstrapOwner, authHandler: maintained.authHandler, drain: maintained.drain, fetch: async request => {
    try { if (request.method !== "POST") throw new ApiError(405, "method_not_allowed"); return json(await dispatch(new URL(request.url).pathname, await body(request))); }
    catch (error) { if (error instanceof ApiError) return json({ error: error.message }, error.status); if (isAPIError(error)) return json({ error: error.body?.message ?? "authentication_failed" }, error.statusCode); throw error; }
  } };
}
