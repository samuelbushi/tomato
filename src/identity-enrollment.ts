import { createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { hashPassword } from "better-auth/crypto";
import type { PgDatabase } from "./database";
import { emailIdentity, type IdentityConfig } from "./auth";
import { verifyLegacyEnrollmentPassword } from "./identity-legacy";
import { ApiError, digest } from "./validation";

const CLAIM_MS = 30 * 60000;
type Legacy = { user_id: string; username: string; credential: string };
type Claim = { token_hash: string; user_id: string; invitation_id: string | null; password_hash: string; expires_at: number; email: string | null; email_token_hash: string | null; email_sent: boolean };
type Invitation = { id: string; account_id: string; legacy_username: string | null; role: string; expires_at: number; status: string };
const token = () => randomBytes(32).toString("base64url");
function claimToken(value: unknown): string { if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new ApiError(401, "enrollment_claim_expired"); return value; }

/** Original credentials authorize only bounded contact claims, even after the full-login bridge expires. */
export function createLegacyEnrollment(database: PgDatabase, config: IdentityConfig, send: (email: string, url: string) => Promise<void>) {
  const admit = async (input: Record<string, unknown>, scope: string, binding: string) => {
    const ip = typeof input.trustedClientIp === "string" ? input.trustedClientIp : "", version = isIP(ip);
    if (!version) throw new ApiError(503, "trusted_caller_address_required");
    const canonical = version === 6 ? new URL(`http://[${ip}]/`).hostname : ip;
    const caller = createHmac("sha256", config.secret).update(canonical).digest("hex"), subject = createHmac("sha256", config.secret).update(binding).digest("hex"), now = Date.now();
    const rows = await database.query<{ count: number }>("INSERT INTO identity.attempts(key,count,expires_at) VALUES($1,1,$3),($2,1,$3) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN identity.attempts.expires_at<=$4 THEN 1 ELSE identity.attempts.count+1 END,expires_at=CASE WHEN identity.attempts.expires_at<=$4 THEN EXCLUDED.expires_at ELSE identity.attempts.expires_at END RETURNING count", [`enrollment:${scope}:caller:${caller}`, `enrollment:${scope}:subject:${subject}`, now + 15 * 60000, now]);
    if (rows.some(row => row.count > 10)) throw new ApiError(429, "enrollment_rate_limited");
  };
  const current = async (value: unknown): Promise<Claim> => {
    const row = (await database.query<Claim>("SELECT c.* FROM identity.enrollment_claims c LEFT JOIN identity.invitations i ON i.id=c.invitation_id WHERE c.token_hash=$1 AND c.expires_at>$2 AND (c.invitation_id IS NULL OR (i.status='pending' AND i.expires_at>$2 AND i.legacy_username IS NOT NULL))", [await digest(claimToken(value)), Date.now()]))[0];
    if (!row) throw new ApiError(401, "enrollment_claim_expired");
    return row;
  };
  return {
    async start(input: Record<string, unknown>) {
      if (!config.smtp) throw new ApiError(503, "smtp_not_configured");
      if (!config.legacyMigration) throw new ApiError(503, "legacy_enrollment_pepper_required");
      if (typeof input.username !== "string" || !input.username || input.username.length > 120 || /[\u0000-\u001f]/.test(input.username) || typeof input.password !== "string" || !input.password || Buffer.byteLength(input.password) > 256) throw new ApiError(401, "invalid_legacy_credentials");
      await admit(input, "proof", input.username);
      const row = (await database.query<Legacy>("SELECT * FROM identity.legacy_enrollment WHERE username=$1", [input.username]))[0];
      // Unknown usernames spend the same verifier cost, without exposing stored hashes.
      const dummy = `tomato-legacy-v1:${Buffer.from(JSON.stringify({ salt: "tomato-enrollment-unknown", verifier: "0".repeat(64) })).toString("base64url")}`;
      const valid = await verifyLegacyEnrollmentPassword({ hash: row?.credential ?? dummy, password: input.password }, config.legacyMigration.pepper);
      if (!row || !valid) throw new ApiError(401, "invalid_legacy_credentials");
      const value = token(), passwordHash = await hashPassword(input.password), now = Date.now(), client = await database.pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("SELECT id FROM identity.subjects WHERE id=$1 FOR UPDATE", [row.user_id]);
        const latest = (await client.query<Legacy>("SELECT * FROM identity.legacy_enrollment WHERE user_id=$1", [row.user_id])).rows[0];
        if (!latest || latest.credential !== row.credential) throw new ApiError(401, "invalid_legacy_credentials");
        await client.query("DELETE FROM identity.enrollment_claims WHERE user_id=$1 AND expires_at<=$2", [row.user_id, now]);
        if ((await client.query<{ count: number }>("SELECT count(*)::integer AS count FROM identity.enrollment_claims WHERE user_id=$1", [row.user_id])).rows[0]!.count >= 3) throw new ApiError(429, "enrollment_active_claim_limit");
        await client.query("INSERT INTO identity.enrollment_claims(token_hash,user_id,password_hash,expires_at) VALUES($1,$2,$3,$4)", [await digest(value), row.user_id, passwordHash, now + CLAIM_MS]);
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
      return { claim: value, expiresAt: now + CLAIM_MS };
    },
    async startInvitation(input: Record<string, unknown>) {
      if (!config.smtp) throw new ApiError(503, "smtp_not_configured");
      if (typeof input.invitationToken !== "string" || !/^tomato_invite_[A-Za-z0-9_-]{43}$/.test(input.invitationToken) || typeof input.username !== "string") throw new ApiError(404, "invitation_not_found");
      if (typeof input.password !== "string" || input.password.length < 14 || Buffer.byteLength(input.password) > 256) throw new ApiError(400, "password_requires_14_to_256_bytes");
      await admit(input, "invite", input.invitationToken);
      const inviteHash = await digest(input.invitationToken), value = token(), passwordHash = await hashPassword(input.password), client = await database.pool.connect(), now = Date.now();
      try {
        await client.query("BEGIN");
        const target = (await client.query<{ user_id: string; username: string }>("SELECT t.* FROM identity.legacy_invite_targets t JOIN identity.invitations i ON i.legacy_username=t.username WHERE i.token_hash=$1 AND t.username=$2", [inviteHash, input.username])).rows[0];
        if (!target) throw new ApiError(403, "invitation_target_or_legacy_credentials_required");
        await client.query("SELECT id FROM identity.subjects WHERE id=$1 FOR UPDATE", [target.user_id]);
        const invite = (await client.query<Invitation>("SELECT * FROM identity.invitations WHERE token_hash=$1 FOR UPDATE", [inviteHash])).rows[0];
        if (!invite || invite.legacy_username !== target.username || invite.status !== "pending" || invite.expires_at <= now || !(await client.query("SELECT user_id FROM identity.legacy_invite_targets WHERE user_id=$1", [target.user_id])).rowCount) throw new ApiError(404, "invitation_not_found");
        await client.query("DELETE FROM identity.enrollment_claims WHERE user_id=$1 AND expires_at<=$2", [target.user_id, now]);
        if ((await client.query<{ count: number }>("SELECT count(*)::integer AS count FROM identity.enrollment_claims WHERE user_id=$1", [target.user_id])).rows[0]!.count >= 3) throw new ApiError(429, "enrollment_active_claim_limit");
        const expiresAt = Math.min(now + CLAIM_MS, invite.expires_at);
        await client.query("INSERT INTO identity.enrollment_claims(token_hash,user_id,invitation_id,password_hash,expires_at) VALUES($1,$2,$3,$4,$5)", [await digest(value), target.user_id, invite.id, passwordHash, expiresAt]);
        await client.query("COMMIT");
        return { claim: value, expiresAt };
      } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
    },
    async status(value: unknown) { const row = await current(value); return { expiresAt: row.expires_at, email: row.email, sent: row.email_sent }; },
    async contact(input: Record<string, unknown>) {
      if (!config.smtp) throw new ApiError(503, "smtp_not_configured");
      const row = await current(input.claim), email = emailIdentity(input.email);
      await admit(input, "contact", row.user_id);
      if ((await database.query("SELECT id FROM public.auth_user WHERE email=$1", [email])).length) throw new ApiError(409, "enrollment_email_unavailable");
      const value = token(), hash = await digest(value);
      if (!(await database.query("UPDATE identity.enrollment_claims SET email=$1,email_token_hash=$2,email_sent=false WHERE token_hash=$3 AND expires_at>$4 RETURNING user_id", [email, hash, row.token_hash, Date.now()])).length) throw new ApiError(401, "enrollment_claim_expired");
      const url = new URL("/enroll/verify", config.baseURL); url.searchParams.set("token", value);
      try { await send(email, url.href); } catch (error) {
        await database.query("UPDATE identity.enrollment_claims SET email=NULL,email_token_hash=NULL,email_sent=false WHERE token_hash=$1 AND email_token_hash=$2", [row.token_hash, hash]);
        throw error;
      }
      if (!(await database.query("UPDATE identity.enrollment_claims SET email_sent=true WHERE token_hash=$1 AND email_token_hash=$2 AND expires_at>$3 RETURNING user_id", [row.token_hash, hash, Date.now()])).length) throw new ApiError(409, "enrollment_contact_changed_or_expired");
      return { sent: true };
    },
    async complete(input: Record<string, unknown>) {
      const hash = await digest(claimToken(input.claim)), emailHash = await digest(claimToken(input.emailToken));
      await admit(input, "finish", hash);
      const client = await database.pool.connect();
      try {
        await client.query("BEGIN");
        const subject = (await client.query<{ id: string }>("SELECT s.id FROM identity.subjects s JOIN identity.enrollment_claims c ON c.user_id=s.id WHERE c.token_hash=$1 FOR UPDATE OF s", [hash])).rows[0];
        const row = (await client.query<Claim>("SELECT * FROM identity.enrollment_claims WHERE token_hash=$1 FOR UPDATE", [hash])).rows[0];
        if (!subject || !row || row.expires_at <= Date.now() || !row.email_sent || row.email_token_hash !== emailHash || !row.email) throw new ApiError(401, "enrollment_verification_invalid_or_expired");
        const legacy = (await client.query<{ username: string }>(row.invitation_id ? "SELECT username FROM identity.legacy_invite_targets WHERE user_id=$1" : "SELECT username FROM identity.legacy_enrollment WHERE user_id=$1", [subject.id])).rows[0];
        if (!legacy) throw new ApiError(401, "enrollment_verification_invalid_or_expired");
        let invite: Invitation | undefined;
        if (row.invitation_id) {
          invite = (await client.query<Invitation>("SELECT * FROM identity.invitations WHERE id=$1 FOR UPDATE", [row.invitation_id])).rows[0];
          if (!invite || invite.status !== "pending" || invite.expires_at <= Date.now() || invite.legacy_username !== legacy.username) throw new ApiError(404, "invitation_not_found");
        }
        if ((await client.query("SELECT id FROM public.auth_user WHERE email=$1 OR id=$2", [row.email, subject.id])).rowCount) throw new ApiError(409, "enrollment_email_unavailable");
        await client.query('INSERT INTO public.auth_user(id,name,email,"emailVerified","createdAt","updatedAt") VALUES($1,$2,$3,true,NOW(),NOW())', [subject.id, legacy.username, row.email]);
        await client.query('INSERT INTO public.auth_account(id,"accountId","providerId","userId",password,"createdAt","updatedAt") VALUES($1,$2,\'credential\',$2,$3,NOW(),NOW())', [crypto.randomUUID(), subject.id, row.password_hash]);
        if (invite) {
          await client.query("INSERT INTO identity.members(account_id,user_id,role) VALUES($1,$2,$3)", [invite.account_id, subject.id, invite.role]);
          await client.query("UPDATE identity.invitations SET status='accepted' WHERE id=$1", [invite.id]);
        }
        await client.query("UPDATE identity.invitations SET email=$1,legacy_username=NULL WHERE legacy_username=$2", [row.email, legacy.username]);
        await client.query("INSERT INTO identity.audit(id,account_id,actor,action,subject,occurred_at) SELECT $1||'-'||account_id,account_id,$2,'identity.enroll',$2,$3 FROM identity.members WHERE user_id=$2", [crypto.randomUUID(), subject.id, Date.now()]);
        await client.query("DELETE FROM identity.enrollment_claims WHERE user_id=$1", [subject.id]);
        await client.query("DELETE FROM identity.legacy_enrollment WHERE user_id=$1", [subject.id]);
        await client.query("DELETE FROM identity.legacy_invite_targets WHERE user_id=$1", [subject.id]);
        await client.query("COMMIT");
        return { enrolled: true, email: row.email };
      } catch (error) {
        await client.query("ROLLBACK");
        if (error && typeof error === "object" && "code" in error && error.code === "23505") throw new ApiError(409, "enrollment_email_unavailable");
        throw error;
      } finally { client.release(); }
    },
  };
}
