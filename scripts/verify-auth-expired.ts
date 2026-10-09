import assert from "node:assert/strict";
import { createHmac, randomBytes, scrypt } from "node:crypto";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { randomToken, type IdentityConfig } from "../src/identity.ts";
import { importLegacyIdentity, type LegacyIdentityExport } from "../src/identity-import.ts";
import { finalizeLegacyIdentityCutover, isLegacyCredential, validateLegacyMigration, validateLegacyMigrationRuntime, type LegacyMigrationConfig } from "../src/identity-legacy.ts";
import type { Principal } from "../src/product-types.ts";
import { digest } from "../src/validation.ts";
import { createProductionTestRuntime } from "./production-test-runtime.ts";
import { createSmtpFixture } from "./smtp-fixture.ts";

/** Natural deadline expiry, actual runtime restart and maintained reset through a real owned TLS SMTP receipt. */
export async function verifyExpiredLegacyAuth(): Promise<void> {
  const smtp = await createSmtpFixture(), password = randomBytes(24).toString("hex"), resetPassword = randomBytes(24).toString("hex"), pepper = randomBytes(32).toString("hex"), salt = randomBytes(24).toString("hex");
  const options: { mode: "self-host"; smtp: NonNullable<IdentityConfig["smtp"]>; legacyMigration?: LegacyMigrationConfig } = { mode: "self-host", smtp: smtp.smtp };
  try {
    const runtime = await createProductionTestRuntime({ runtime: options });
    try {
      const derived = Promise.withResolvers<Buffer>();
      scrypt(createHmac("sha256", pepper).update(password).digest(), salt, 32, { N: 16384, r: 8, p: 5, maxmem: 32 * 1024 * 1024 }, (error, value) => error ? derived.reject(error) : derived.resolve(value));
      const verifier = (await derived.promise).toString("hex"), legacyKey = randomToken("tomato_key_"), now = Date.now();
      const source: LegacyIdentityExport = { users: [{ id: "expired-modern-user", username: "modern-before-cutoff", salt, verifier }, { id: "expired-legacy-user", username: "legacy-after-cutoff", salt, verifier }], accounts: [{ id: "expired-workspace", name: "Expired Bridge Workspace" }], members: [{ account_id: "expired-workspace", user_id: "expired-modern-user", role: "owner" }, { account_id: "expired-workspace", user_id: "expired-legacy-user", role: "viewer" }], api_keys: [{ id: "expired-legacy-key", user_id: "expired-legacy-user", account_id: "expired-workspace", token_hash: await digest(legacyKey), name: "Preserved exported read key", scope: "read", created_at: now, expires_at: now + 3600000, last_used_at: null, parent_key_id: null }], invitations: [], slugs: [], audit: [], mcp_sessions: [] };
      // Explicit controlled operator approval; the test waits for real clock expiry, never rewrites/extends this deadline.
      const approvedDeadline = Date.now() + 15000, migration = { pepper, expiresAt: approvedDeadline };
      await importLegacyIdentity(runtime.database, { export: source, emailMap: { "modern-before-cutoff": { email: "expired-modern@example.test", name: "Modern Controlled Identity", emailVerified: true }, "legacy-after-cutoff": { email: "expired-legacy@example.test", name: "Legacy Controlled Identity", emailVerified: true } }, migration, acknowledgeLegacySessionInvalidation: true });
      options.legacyMigration = migration; await runtime.restart();
      const invoke = (endpoint: string, input: unknown) => runtime.fetch(`/api/auth${endpoint}`, { method: "POST", headers: { Origin: runtime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify(input), redirect: "manual" });
      const modernLogin = await invoke("/sign-in/email", { email: "expired-modern@example.test", password }); assert.equal(modernLogin.status, 200);
      const modernCookie = modernLogin.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; "), session = await runtime.fetch("/api/session", { headers: { Cookie: modernCookie } }); assert.equal(session.status, 200); const principal = await session.json() as Principal; assert.equal(principal.actor.id, "expired-modern-user");
      const converted = (await runtime.database.query<{ password: string }>('SELECT password FROM public.auth_account WHERE "userId"=$1 AND "providerId"=\'credential\'', [principal.actor.id]))[0]!; assert(!isLegacyCredential(converted.password));
      const issued = await runtime.fetch("/api/accounts/expired-workspace/api-keys", { method: "POST", headers: { Origin: runtime.baseUrl, Cookie: modernCookie, "Content-Type": "application/json", "X-CSRF-Token": principal.csrfToken }, body: JSON.stringify({ name: "Modern key survives bridge expiry", scope: "manage" }) }); assert.equal(issued.status, 201); const modernKey = await issued.json() as { apiKey: string };
      const keyHeaders = { Authorization: `Bearer ${modernKey.apiKey}` };
      const created = await runtime.fetch("/api/accounts/expired-workspace/monitors", { method: "POST", headers: { ...keyHeaders, "Content-Type": "application/json" }, body: JSON.stringify({ check: { kind: "http", url: `${runtime.fixtures.httpUrl}/expired-bridge-target` } }) }); assert.equal(created.status, 201); const monitor = await created.json() as { monitor: { id: string } };
      await delay(Math.max(0, approvedDeadline - Date.now()) + 50);
      validateLegacyMigrationRuntime(migration); assert.throws(() => validateLegacyMigration(migration), /explicit_future_deadline/);
      assert.throws(() => validateLegacyMigrationRuntime({ pepper, expiresAt: Date.now() + 31 * 86400000 }), /explicit_bounded_deadline/);
      await runtime.restart(); assert.equal(options.legacyMigration.expiresAt, approvedDeadline);
      assert.equal((await runtime.fetch("/health/ready")).status, 200);
      assert.equal((await invoke("/sign-in/email", { email: "expired-modern@example.test", password })).status, 200);
      assert.equal((await invoke("/sign-in/email", { email: "expired-legacy@example.test", password })).status, 401);
      assert.equal((await runtime.fetch("/api/accounts/expired-workspace/state", { headers: { Authorization: `Bearer ${legacyKey}` } })).status, 200);
      let observed = false; const observationDeadline = Date.now() + 15000;
      while (Date.now() < observationDeadline) {
        const response = await runtime.fetch("/api/accounts/expired-workspace/state", { headers: keyHeaders }); assert.equal(response.status, 200);
        const state = await response.json() as { monitors: { id: string; state: string; lastObservedAt: number | null }[] };
        if (state.monitors.some(value => value.id === monitor.monitor.id && value.state === "UP" && value.lastObservedAt !== null)) { observed = true; break; } await delay(25);
      }
      assert(observed); assert((runtime.fixtures.hits.get("expired-bridge-target") ?? 0) > 0);
      const stillLegacy = (await runtime.database.query<{ password: string }>('SELECT password FROM public.auth_account WHERE "userId"=\'expired-legacy-user\' AND "providerId"=\'credential\''))[0]!; assert(isLegacyCredential(stillLegacy.password));
      const before = smtp.messages.length;
      assert.equal((await invoke("/request-password-reset", { email: "expired-legacy@example.test", redirectTo: `${runtime.baseUrl}/reset-password` })).status, 200);
      let receipt: string | undefined; const receiptDeadline = Date.now() + 10000;
      while (Date.now() < receiptDeadline) { receipt = smtp.messages.slice(before).find(value => value.includes("Reset your Tomato password")); if (receipt) break; await delay(20); }
      assert(receipt); const decoded = receipt.replace(/=\r\n/g, "").replace(/=3D/g, "="), resetLink = decoded.match(/http[^\s<>]+\/api\/auth\/reset-password\/[^\s<>]+/); assert(resetLink);
      const redirected = await runtime.fetch(resetLink[0], { redirect: "manual" }); assert.equal(redirected.status, 302); const resetToken = new URL(redirected.headers.get("Location")!).searchParams.get("token"); assert(resetToken);
      assert.equal((await invoke("/reset-password", { token: resetToken, newPassword: resetPassword })).status, 200);
      const replacement = (await runtime.database.query<{ password: string }>('SELECT password FROM public.auth_account WHERE "userId"=\'expired-legacy-user\' AND "providerId"=\'credential\''))[0]!; assert(!isLegacyCredential(replacement.password));
      assert.equal((await invoke("/sign-in/email", { email: "expired-legacy@example.test", password })).status, 401);
      const recovered = await invoke("/sign-in/email", { email: "expired-legacy@example.test", password: resetPassword }); assert.equal(recovered.status, 200);
      const recoveredCookie = recovered.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; "), recoveredSession = await runtime.fetch("/api/session", { headers: { Cookie: recoveredCookie } }); assert.equal(recoveredSession.status, 200); const recoveredPrincipal = await recoveredSession.json() as Principal; assert.equal(recoveredPrincipal.actor.id, "expired-legacy-user"); assert.equal(recoveredPrincipal.accounts.find(value => value.id === "expired-workspace")?.role, "viewer");
      assert.equal((await runtime.fetch("/api/accounts/expired-workspace/state", { headers: { Authorization: `Bearer ${legacyKey}` } })).status, 401);
      assert.equal((await runtime.fetch("/api/accounts/expired-workspace/state", { headers: keyHeaders })).status, 200);
      await finalizeLegacyIdentityCutover(runtime.database);
    } finally { await runtime.close(); }
  } finally { await smtp.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await verifyExpiredLegacyAuth();
  console.log("PASS expired legacy bridge preserves modern auth/runtime and actual SMTP reset upgrades the legacy credential");
}
