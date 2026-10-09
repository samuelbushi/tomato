import { hashPassword } from "better-auth/crypto";
import type { PgDatabase } from "./database";
import { emailIdentity } from "./auth";
import { identifier, integer } from "./validation";
import type { AccountRole, ApiKeyScope } from "./product-types";
import { legacyCredential, verifyCutoverPassword, validateLegacyMigration, type LegacyMigrationConfig } from "./identity-legacy";

/** One-shot approved cutover. Legacy verification remains exclusively inside Better Auth until the explicit deadline. */
export interface LegacyIdentityExport {
  users: { id: string; username: string; salt: string; verifier: string }[];
  accounts: { id: string; name: string }[];
  members: { account_id: string; user_id: string; role: AccountRole }[];
  api_keys: { id: string; user_id: string; account_id: string; token_hash: string; name: string; scope: ApiKeyScope; created_at: number; expires_at: number; last_used_at: number | null; parent_key_id: string | null }[];
  invitations: { id: string; account_id: string; username: string; role: AccountRole; token_hash: string; created_at: number; expires_at: number; status: "pending" | "accepted" | "revoked" }[];
  slugs: { slug: string; account_id: string }[];
  audit: { id: string; account_id: string; actor: string; action: string; subject: string; occurred_at: number; api_key_id?: string | null }[];
  mcp_sessions: { id: string; user_id: string; account_id: string; auth_binding: string; protocol_version: string; expires_at: number; initialized: number }[];
}
export interface LegacyEmailMapping { email: string; name: string; emailVerified: boolean }
export interface IdentityCutoverInput {
  export: LegacyIdentityExport;
  /** Every legacy username, including invitation-only names, must have a real mapping. */
  emailMap: Record<string, LegacyEmailMapping>;
  /** Supplied by each user through an approved cutover process; never persisted or logged. */
  passwordProofs?: Record<string, string>;
  migration: LegacyMigrationConfig;
  acknowledgeLegacySessionInvalidation: true;
}
function requireText(value: unknown): asserts value is string { if (typeof value !== "string" || !value || /[\u0000-\u001f]/.test(value)) throw new Error("invalid_identity_export"); }
function validRole(value: unknown): asserts value is AccountRole { if (value !== "owner" && value !== "editor" && value !== "viewer") throw new Error("invalid_identity_export_role"); }
function timestamp(value: unknown): number { return integer(value, 0, Number.MAX_SAFE_INTEGER, "identity_export_timestamp"); }
export async function importLegacyIdentity(database: PgDatabase, input: IdentityCutoverInput): Promise<{ users: number; accounts: number; keys: number; legacySessionsInvalidated: true }> {
  if (!input || input.acknowledgeLegacySessionInvalidation !== true) throw new Error("approved_email_mapping_export_pepper_and_deadline_required");
  validateLegacyMigration(input.migration);
  const source = input.export;
  if (!source || ![source.users, source.accounts, source.members, source.api_keys, source.invitations, source.slugs, source.audit, source.mcp_sessions].every(Array.isArray)) throw new Error("complete_identity_export_required");
  const users = new Map<string, { email: string; name: string; emailVerified: boolean; password: string }>(), accounts = new Set<string>(), emailOwners = new Set<string>();
  const mapping = (username: string): LegacyEmailMapping => { requireText(username); const row = input.emailMap[username]; if (!row || typeof row.name !== "string" || !row.name.trim() || typeof row.emailVerified !== "boolean") throw new Error("real_email_mapping_required"); return { email: emailIdentity(row.email), name: row.name.trim(), emailVerified: row.emailVerified }; };
  for (const row of source.users) {
    identifier(row.id); requireText(row.salt); requireText(row.verifier);
    const actual = mapping(row.username), proof = input.passwordProofs?.[row.id], legacy = legacyCredential(row.salt, row.verifier);
    if (users.has(row.id) || emailOwners.has(actual.email)) throw new Error("ambiguous_legacy_email_mapping");
    if (proof !== undefined && (typeof proof !== "string" || proof.length < 14 || Buffer.byteLength(proof) > 256 || !await verifyCutoverPassword({ hash: legacy, password: proof }, input.migration))) throw new Error("legacy_password_proof_failed");
    users.set(row.id, { ...actual, password: proof === undefined ? legacy : await hashPassword(proof) }); emailOwners.add(actual.email);
  }
  for (const row of source.accounts) { identifier(row.id); requireText(row.name); if (accounts.has(row.id)) throw new Error("duplicate_legacy_account"); accounts.add(row.id); }
  for (const row of source.members) { validRole(row.role); if (!users.has(row.user_id) || !accounts.has(row.account_id)) throw new Error("invalid_legacy_membership"); }
  for (const accountId of accounts) if (!source.members.some(row => row.account_id === accountId && row.role === "owner")) throw new Error("legacy_account_owner_required");
  const keys = new Map(source.api_keys.map(row => [row.id, row]));
  if (keys.size !== source.api_keys.length) throw new Error("duplicate_legacy_key");
  const levels: Record<ApiKeyScope, number> = { read: 0, write: 1, manage: 2 };
  for (const row of source.api_keys) {
    identifier(row.id); requireText(row.token_hash); requireText(row.name); timestamp(row.created_at); timestamp(row.expires_at); if (row.last_used_at !== null) timestamp(row.last_used_at);
    if (!users.has(row.user_id) || !accounts.has(row.account_id) || !(row.scope in levels) || row.expires_at <= row.created_at || !source.members.some(member => member.user_id === row.user_id && member.account_id === row.account_id)) throw new Error("invalid_legacy_key");
    let current = row; const seen = new Set<string>();
    while (current.parent_key_id) { if (seen.has(current.id) || seen.size >= 19) throw new Error("invalid_legacy_key_chain"); seen.add(current.id); const parent = keys.get(current.parent_key_id); if (!parent || parent.account_id !== row.account_id || parent.user_id !== row.user_id || levels[current.scope] > levels[parent.scope] || current.expires_at > parent.expires_at) throw new Error("invalid_legacy_key_chain"); current = parent; }
  }
  for (const row of source.invitations) { identifier(row.id); validRole(row.role); mapping(row.username); requireText(row.token_hash); timestamp(row.created_at); timestamp(row.expires_at); if (!accounts.has(row.account_id) || !["pending", "accepted", "revoked"].includes(row.status)) throw new Error("invalid_legacy_invitation"); }
  for (const row of source.slugs) if (!accounts.has(row.account_id) || !/^[a-z0-9][a-z0-9-]{2,62}$/.test(row.slug)) throw new Error("invalid_legacy_slug");
  for (const row of source.audit) { requireText(row.id); requireText(row.actor); requireText(row.action); requireText(row.subject); timestamp(row.occurred_at); if (!accounts.has(row.account_id)) throw new Error("invalid_legacy_audit"); }
  const client = await database.pool.connect();
  try {
    await client.query("BEGIN"); await client.query("SELECT pg_advisory_xact_lock(746662092)");
    if ((await client.query("SELECT id FROM public.auth_user LIMIT 1")).rowCount || (await client.query("SELECT user_id FROM identity.members LIMIT 1")).rowCount) throw new Error("identity_cutover_requires_empty_target_identity");
    for (const row of source.accounts) {
      const existing = await client.query<{ name: string }>("SELECT name FROM engine.accounts WHERE id=$1 FOR UPDATE", [row.id]);
      if (existing.rows[0] && existing.rows[0].name !== row.name) throw new Error("legacy_account_mapping_conflict");
      await client.query("INSERT INTO engine.accounts(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING", [row.id, row.name]);
    }
    for (const [id, row] of users) {
      await client.query('INSERT INTO public.auth_user(id,name,email,"emailVerified","createdAt","updatedAt") VALUES($1,$2,$3,$4,NOW(),NOW())', [id, row.name, row.email, row.emailVerified]);
      await client.query(`INSERT INTO public.auth_account(id,"accountId","providerId","userId",password,"createdAt","updatedAt") VALUES($1,$2,'credential',$2,$3,NOW(),NOW())`, [crypto.randomUUID(), id, row.password]);
    }
    for (const row of source.members) await client.query("INSERT INTO identity.members(account_id,user_id,role) VALUES($1,$2,$3)", [row.account_id, row.user_id, row.role]);
    for (const row of source.api_keys) await client.query("INSERT INTO identity.api_keys(id,user_id,account_id,token_hash,name,scope,created_at,expires_at,last_used_at,parent_key_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL)", [row.id, row.user_id, row.account_id, row.token_hash, row.name, row.scope, row.created_at, row.expires_at, row.last_used_at]);
    for (const row of source.api_keys) if (row.parent_key_id) await client.query("UPDATE identity.api_keys SET parent_key_id=$1 WHERE id=$2", [row.parent_key_id, row.id]);
    for (const row of source.invitations) await client.query("INSERT INTO identity.invitations(id,account_id,email,role,token_hash,created_at,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", [row.id, row.account_id, mapping(row.username).email, row.role, row.token_hash, row.created_at, row.expires_at, row.status]);
    for (const row of source.slugs) await client.query("INSERT INTO identity.slugs(slug,account_id) VALUES($1,$2)", [row.slug, row.account_id]);
    for (const row of source.audit) await client.query("INSERT INTO identity.audit(id,account_id,actor,action,subject,occurred_at,api_key_id) VALUES($1,$2,$3,$4,$5,$6,$7)", [row.id, row.account_id, row.actor, row.action, row.subject, row.occurred_at, row.api_key_id ?? null]);
    for (const row of source.mcp_sessions) {
      // Cookie-bound legacy sessions cannot become maintained sessions. Key-bound bindings retain identity.
      const key = keys.get(row.auth_binding); if (!key) continue;
      identifier(row.id); timestamp(row.expires_at);
      if (key.user_id !== row.user_id || key.account_id !== row.account_id || row.expires_at > key.expires_at || row.protocol_version !== "2025-11-25" || ![0, 1].includes(row.initialized)) throw new Error("invalid_legacy_mcp_binding");
      await client.query("INSERT INTO identity.mcp_sessions(id,user_id,account_id,auth_binding,protocol_version,expires_at,initialized) VALUES($1,$2,$3,$4,$5,$6,$7)", [row.id, row.user_id, row.account_id, row.auth_binding, row.protocol_version, row.expires_at, row.initialized === 1]);
    }
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  return { users: users.size, accounts: accounts.size, keys: keys.size, legacySessionsInvalidated: true };
}
