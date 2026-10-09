import { createHmac, scrypt, timingSafeEqual } from "node:crypto";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import type { PgDatabase } from "./database";

const PREFIX = "tomato-legacy-v1:";
export interface LegacyMigrationConfig { pepper: string; expiresAt: number }
export function legacyCredential(salt: string, verifier: string): string {
  if (!salt || !/^[a-f0-9]{64}$/i.test(verifier)) throw new Error("invalid_legacy_credential_export");
  return `${PREFIX}${Buffer.from(JSON.stringify({ salt, verifier })).toString("base64url")}`;
}
export function isLegacyCredential(hash: string): boolean { return hash.startsWith(PREFIX); }
/** Runtime keeps the approved absolute deadline unchanged; expiry disables only legacy verification. */
export function validateLegacyMigrationRuntime(config: LegacyMigrationConfig): void {
  if (typeof config.pepper !== "string" || config.pepper.length < 32 || !Number.isSafeInteger(config.expiresAt) || config.expiresAt <= 0 || config.expiresAt > Date.now() + 30 * 86400000) throw new Error("legacy_cutover_requires_pepper_and_explicit_bounded_deadline");
}
/** Approval/import must start within a fresh, explicitly approved future window. */
export function validateLegacyMigration(config: LegacyMigrationConfig): void {
  validateLegacyMigrationRuntime(config);
  if (config.expiresAt <= Date.now()) throw new Error("legacy_cutover_requires_explicit_future_deadline_within_30_days");
}
/** Called only by Better Auth's maintained credential verifier during an approved cutover. */
export async function verifyCutoverPassword(data: { hash: string; password: string }, config?: LegacyMigrationConfig): Promise<boolean> {
  if (!isLegacyCredential(data.hash)) return verifyPassword(data);
  if (!config || Date.now() >= config.expiresAt || Buffer.byteLength(data.password) > 256) return false;
  let payload: unknown;
  try { payload = JSON.parse(Buffer.from(data.hash.slice(PREFIX.length), "base64url").toString("utf8")); } catch { return false; }
  if (!payload || typeof payload !== "object" || !("salt" in payload) || typeof payload.salt !== "string" || !("verifier" in payload) || typeof payload.verifier !== "string" || !/^[a-f0-9]{64}$/i.test(payload.verifier)) return false;
  const material = createHmac("sha256", config.pepper).update(data.password).digest();
  const completion = Promise.withResolvers<Buffer>();
  scrypt(material, payload.salt, 32, { N: 16384, r: 8, p: 5, maxmem: 32 * 1024 * 1024 }, (error, key) => error ? completion.reject(error) : completion.resolve(key));
  const result = await completion.promise;
  try { return timingSafeEqual(result, Buffer.from(payload.verifier, "hex")); } finally { material.fill(0); result.fill(0); }
}
export async function rehashSuccessfulCutoverLogin(database: PgDatabase, userId: string, password: string): Promise<void> {
  const row = (await database.query<{ id: string; password: string }>(`SELECT id,password FROM public.auth_account WHERE "userId"=$1 AND "providerId"='credential'`, [userId]))[0];
  if (!row || !isLegacyCredential(row.password)) return;
  await database.query('UPDATE public.auth_account SET password=$1,"updatedAt"=NOW() WHERE id=$2 AND password=$3', [await hashPassword(password), row.id, row.password]);
}
/** Refuse completion until every imported credential is rehashed or replaced by maintained password reset. */
export async function finalizeLegacyIdentityCutover(database: PgDatabase): Promise<void> {
  const rows = await database.query<{ count: number }>("SELECT COUNT(*)::integer AS count FROM public.auth_account WHERE password LIKE $1", [`${PREFIX}%`]);
  if (rows[0]?.count !== 0) throw new Error("legacy_cutover_not_complete_all_users_must_rehash_or_reset");
}
