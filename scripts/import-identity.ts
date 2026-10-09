import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import pg from "pg";
import { z } from "zod";
import { PgDatabase } from "../src/database.ts";
import { importLegacyIdentity } from "../src/identity-import.ts";
import { finalizeLegacyIdentityCutover } from "../src/identity-legacy.ts";

const role = z.enum(["owner", "editor", "viewer"]), scope = z.enum(["read", "write", "manage"]), time = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER), id = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const exported = z.object({
  users: z.array(z.object({ id, username: z.string().min(1), salt: z.string().min(1), verifier: z.string().regex(/^[a-f0-9]{64}$/i) })),
  accounts: z.array(z.object({ id, name: z.string().min(1).max(120) })),
  members: z.array(z.object({ account_id: id, user_id: id, role })),
  api_keys: z.array(z.object({ id, user_id: id, account_id: id, token_hash: z.string().min(1), name: z.string().min(1).max(120), scope, created_at: time, expires_at: time, last_used_at: time.nullable(), parent_key_id: id.nullable().default(null) })),
  invitations: z.array(z.object({ id, account_id: id, username: z.string().min(1), role, token_hash: z.string().min(1), created_at: time, expires_at: time, status: z.enum(["pending", "accepted", "revoked"]) })),
  slugs: z.array(z.object({ slug: z.string(), account_id: id })),
  audit: z.array(z.object({ id: z.string().min(1), account_id: id, actor: z.string().min(1), action: z.string().min(1), subject: z.string().min(1), occurred_at: time, api_key_id: id.nullable().optional() })),
  mcp_sessions: z.array(z.object({ id, user_id: id, account_id: id, auth_binding: id, protocol_version: z.string(), expires_at: time, initialized: z.union([z.literal(0), z.literal(1)]) })),
});
const emailMap = z.record(z.string(), z.object({ email: z.email(), name: z.string().min(1).max(120), emailVerified: z.boolean() }));
const proofs = z.record(z.string(), z.string().min(1).max(256));
const argumentsByName: Record<string, string | true> = Object.create(null);
const allowed: Record<string, true> = { "--export": true, "--email-map": true, "--pepper-file": true, "--expires-at": true, "--password-proofs": true, "--acknowledge-session-invalidation": true, "--finalize": true };
for (let index = 2; index < process.argv.length; index++) {
  const argument = process.argv[index]!;
  if (!allowed[argument] || argumentsByName[argument]) throw new Error("invalid_identity_import_arguments");
  if (argument === "--acknowledge-session-invalidation" || argument === "--finalize") argumentsByName[argument] = true;
  else { const value = process.argv[++index]; if (!value || value.startsWith("--")) throw new Error("missing_identity_import_argument"); argumentsByName[argument] = value; }
}
async function explicitFile(name: string): Promise<string> {
  const value = argumentsByName[name]; if (typeof value !== "string") throw new Error("explicit_approved_identity_input_required");
  const candidate = path.resolve(value), actual = await realpath(candidate);
  for (const filename of [candidate, actual]) if (filename.split(path.sep).some(part => [".tomato-local", ".tomato-dev", ".wrangler"].includes(part))) throw new Error("protected_identity_input_forbidden");
  return readFile(actual, "utf8");
}
if (!process.env.DATABASE_URL) throw new Error("explicit_target_database_required");
const database = new PgDatabase(new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 2 }));
try {
  if (argumentsByName["--finalize"]) {
    await finalizeLegacyIdentityCutover(database);
    console.log("Identity cutover complete: no legacy credentials remain. Remove legacy migration configuration and securely retire the exported pepper.");
  } else {
    if (argumentsByName["--acknowledge-session-invalidation"] !== true) throw new Error("explicit_legacy_session_invalidation_acknowledgement_required");
    const expiresAt = Number(argumentsByName["--expires-at"]);
    const result = await importLegacyIdentity(database, {
      export: exported.parse(JSON.parse(await explicitFile("--export"))),
      emailMap: argumentsByName["--email-map"] ? emailMap.parse(JSON.parse(await explicitFile("--email-map"))) : undefined,
      passwordProofs: argumentsByName["--password-proofs"] ? proofs.parse(JSON.parse(await explicitFile("--password-proofs"))) : undefined,
      migration: { pepper: (await explicitFile("--pepper-file")).trim(), expiresAt },
      acknowledgeLegacySessionInvalidation: true,
    });
    console.log(JSON.stringify(result));
  }
} catch {
  // Input data includes verifier/credential material; never print raw errors or schemas containing it.
  console.error("Identity import failed. Check approved complete export, optional actual-contact mappings, target emptiness, pepper and full-login bridge deadline. No partial import was committed.");
  process.exitCode = 1;
} finally { await database.close(); }
