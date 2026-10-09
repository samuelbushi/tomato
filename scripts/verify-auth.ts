import assert from "node:assert/strict";
import { createHmac, randomBytes, scrypt } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { createIdentity, randomToken, type IdentityService } from "../src/identity.ts";
import { importLegacyIdentity, type LegacyIdentityExport } from "../src/identity-import.ts";
import { finalizeLegacyIdentityCutover, isLegacyCredential } from "../src/identity-legacy.ts";
import type { ApiKeyView, InvitationView, Principal } from "../src/product-types.ts";
import { digest } from "../src/validation.ts";
import { createProductionTestRuntime } from "./production-test-runtime.ts";
import { verifyControlledOAuth } from "./controlled-oauth.ts";
import { verifyBootstrapIdentity } from "./bootstrap-identity.ts";
import { verifyClosedInvitationFlow, type InvitationAcceptanceFixture } from "./invitation-auth.ts";
import { createSmtpFixture } from "./smtp-fixture.ts";
import { verifyExpiredLegacyAuth } from "./verify-auth-expired.ts";

const runtime = await createProductionTestRuntime({ background: false });
const password = randomBytes(24).toString("hex"), nextPassword = randomBytes(24).toString("hex");
let scenarios = 0;
async function scenario(name: string, run: () => Promise<void>) { await run(); scenarios++; console.log(`PASS ${name}`); }
async function internal<T>(endpoint: string, input: unknown, status = 200): Promise<T> {
  const response = await runtime.env.identity.fetch(new Request(`https://identity.internal${endpoint}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) }));
  assert.equal(response.status, status, `${endpoint}: unexpected status`); return await response.json() as T;
}
async function auth(endpoint: string, input: unknown, cookie = "", status = 200): Promise<Response> {
  const response = await runtime.fetch(`/api/auth${endpoint}`, { method: "POST", headers: { Origin: runtime.baseUrl, "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}) }, body: JSON.stringify(input), redirect: "manual" });
  assert.equal(response.status, status, `${endpoint}: unexpected status`); return response;
}
const cookies = (response: Response) => response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");
async function login(email: string, value = password): Promise<{ cookie: string; principal: Principal }> {
  const result = await auth("/sign-in/email", { email, password: value }), cookie = cookies(result);
  const principal = await internal<Principal>("/authenticate", { cookie });
  return { cookie, principal };
}
try {
  const alice = await internal<{ owner: { id: string } }>("/provision", { id: "alpha", name: "Alpha", owner: { email: "alice@example.test", name: "Alice Test", password, emailVerified: true } });
  const bob = await internal<{ owner: { id: string } }>("/provision", { id: "beta", name: "Beta", owner: { email: "bob@example.test", name: "Bob Test", password, emailVerified: true } });
  let browser = await login("alice@example.test");
  const actor = { actorId: alice.owner.id, accountId: "alpha", authSessionId: browser.principal.sessionId };
  await scenario("maintained PostgreSQL email login cookies, exact origin and immediate revocation", async () => {
    assert.equal(browser.principal.actor.id, alice.owner.id); assert.equal(browser.principal.actor.username, "alice@example.test");
    assert(browser.principal.csrfToken.length >= 43); assert(browser.cookie.includes("tomato-session="));
    await auth("/sign-in/email", { email: "alice@example.test", password: "wrong-current-password" }, "", 401);
    const foreign = await runtime.fetch("/api/auth/sign-in/email", { method: "POST", headers: { Origin: "https://untrusted.invalid", "Content-Type": "application/json" }, body: JSON.stringify({ email: "alice@example.test", password }) }); assert.equal(foreign.status, 403);
    await internal("/authenticate", { cookie: browser.cookie, accountId: "beta" }, 404);
    const second = await login("alice@example.test"); await internal("/sessions/revoke", { userId: alice.owner.id, id: second.principal.sessionId }); await internal("/authenticate", { cookie: second.cookie }, 401);
    const list = await internal<{ sessions: unknown[] }>("/sessions", { userId: alice.owner.id, sessionId: browser.principal.sessionId }); assert(!JSON.stringify(list).includes(browser.cookie));
  });
  await scenario("signup, SMTP and absent actual OAuth credentials fail closed", async () => {
    await auth("/sign-up/email", { email: "new@example.test", name: "New Test", password }, "", 403);
    await auth("/request-password-reset", { email: "alice@example.test" }, "", 503);
    await auth("/sign-in/social", { provider: "github" }, "", 503);
    await auth("/sign-in/social", { provider: "google" }, "", 503);
    await internal("/provision", { id: "bad-email", name: "Bad", owner: { username: "invented", name: "Bad", password } }, 400);
  });
  const carol = await internal<{ owner: { id: string } }>("/provision", { id: "carol", name: "Carol", owner: { email: "carol@example.test", name: "Carol Test", password, emailVerified: true } });
  const carolBrowser = await login("carol@example.test");
  await scenario("verified email-bound invitation single-use and last-owner/current-role rules", async () => {
    const invitation = await internal<{ invitation: InvitationView; invitationToken: string }>("/invitations/create", { ...actor, username: "carol@example.test", role: "viewer" });
    await internal("/invitations/accept", { token: invitation.invitationToken, userId: bob.owner.id, sessionId: (await login("bob@example.test")).principal.sessionId }, 403);
    await internal("/invitations/accept", { token: invitation.invitationToken, userId: carol.owner.id, sessionId: carolBrowser.principal.sessionId });
    await internal("/invitations/accept", { token: invitation.invitationToken, userId: carol.owner.id, sessionId: carolBrowser.principal.sessionId }, 404);
    await internal("/members/change", { ...actor, userId: alice.owner.id, role: "viewer" }, 409);
    await internal("/api-keys/create", { actorId: carol.owner.id, accountId: "alpha", name: "forbidden", scope: "write" }, 403);
    const revoked = await internal<{ invitation: InvitationView; invitationToken: string }>("/invitations/create", { ...actor, username: "david@example.test", role: "editor" });
    await internal("/invitations/revoke", { ...actor, id: revoked.invitation.id }); await internal("/invitations/preview", { token: revoked.invitationToken }, 404);
  });
  await scenario("delegated chain scope/expiry/cascade revocation and MCP binding", async () => {
    const root = await internal<{ key: ApiKeyView; apiKey: string }>("/api-keys/create", { ...actor, name: "parent", scope: "manage", expiresInDays: 1 });
    const child = await internal<{ key: ApiKeyView; apiKey: string }>("/api-keys/create", { actorId: alice.owner.id, accountId: "alpha", sourceKeyId: root.key.id, name: "child", scope: "read" });
    assert.equal(child.key.parentKeyId, root.key.id); assert(child.key.expiresAt <= root.key.expiresAt);
    await internal("/api-keys/create", { actorId: alice.owner.id, accountId: "alpha", sourceKeyId: child.key.id, name: "excess", scope: "write" }, 403);
    await internal("/api-keys/create", { actorId: alice.owner.id, accountId: "alpha", sourceKeyId: root.key.id, name: "long", scope: "read", expiresAt: root.key.expiresAt + 1 }, 403);
    const mcp = await internal<{ sessionId: string }>("/mcp/create", { ...actor, authBinding: child.key.id, protocolVersion: "2025-11-25" });
    await internal("/mcp/validate", { ...actor, authBinding: child.key.id, sessionId: mcp.sessionId, requireInitialized: true }, 409);
    await internal("/mcp/initialized", { ...actor, authBinding: child.key.id, sessionId: mcp.sessionId });
    await internal("/api-keys/revoke", { ...actor, id: root.key.id });
    await internal("/authenticate", { token: child.apiKey }, 401); await internal("/mcp/validate", { ...actor, authBinding: child.key.id, sessionId: mcp.sessionId }, 404);
  });
  await scenario("password change revokes keys and other sessions; operator recovery revokes all", async () => {
    const other = await login("alice@example.test"), key = await internal<{ apiKey: string }>("/api-keys/create", { ...actor, name: "password-key", scope: "read" });
    await internal("/password", { userId: alice.owner.id, sessionId: browser.principal.sessionId, currentPassword: password, newPassword: nextPassword });
    await internal("/authenticate", { cookie: browser.cookie }); await internal("/authenticate", { cookie: other.cookie }, 401); await internal("/authenticate", { token: key.apiKey }, 401);
    await internal("/recovery", { userId: alice.owner.id, newPassword: password }); await internal("/authenticate", { cookie: browser.cookie }, 401); browser = await login("alice@example.test");
    const entries = await internal<{ entries: { action: string }[] }>("/audit", { actorId: alice.owner.id, accountId: "alpha" }); assert(entries.entries.some(row => row.action === "password.recovery"));
  });
  await scenario("HTTPS host cookies and untrusted origins are enforced in maintained handler", async () => {
    const secure = createIdentity(runtime.database, { baseURL: "https://auth.example.test", secret: randomBytes(32).toString("hex") });
    try {
      const response = await secure.authHandler(new Request("https://auth.example.test/api/auth/sign-in/email", { method: "POST", headers: { Origin: "https://auth.example.test", "Content-Type": "application/json", "x-tomato-client-ip": "192.0.2.40" }, body: JSON.stringify({ email: "alice@example.test", password }) })); assert.equal(response.status, 200);
      const cookie = response.headers.getSetCookie().find(value => value.includes("tomato-session")); assert(cookie); assert(cookie.startsWith("__Secure-tomato-session=")); assert(cookie.includes("Secure")); assert(cookie.includes("HttpOnly")); assert(cookie.includes("SameSite=Lax")); assert(cookie.includes("Path=/")); assert(!cookie.includes("Domain="));
    } finally { await secure.drain(); }
  });
  await scenario("real TLS SMTP and maintained OAuth, usable verified workspaces and email boundary", async () => {
    const smtpFixture = await createSmtpFixture(), { certificate, privateKey, messages } = smtpFixture;
    let invitationFixture: InvitationAcceptanceFixture | undefined;
    try {
      const signupRuntime = await createProductionTestRuntime({ runtime: { mode: "self-host", signupEnabled: true, smtp: smtpFixture.smtp } });
    const email = signupRuntime.env.identity;
    const invoke = (endpoint: string, input: unknown) => signupRuntime.fetch(`/api/auth${endpoint}`, { method: "POST", headers: { Origin: signupRuntime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify(input), redirect: "manual" });
    const receipt = async (subject: string, after = 0): Promise<string> => { const deadline = Date.now() + 10000; while (Date.now() < deadline) { const message = messages.slice(after).find(value => value.includes(subject)); if (message) return message.replace(/=\r\n/g, "").replace(/=3D/g, "="); await delay(20); } throw new Error("SMTP receipt timeout"); };
    try {
      assert.equal((await invoke("/sign-up/email", { email: "smtp-user@example.test", name: "SMTP Fixture", password, callbackURL: "/login" })).status, 200);
      assert.equal((await invoke("/sign-in/email", { email: "smtp-user@example.test", password })).status, 403);
      const delivered = await receipt("Verify your Tomato email"), match = delivered.match(/http[^\s<>]+\/api\/auth\/verify-email\?[^\s<>]+/); assert(match);
      const verified = await signupRuntime.fetch(match[0], { redirect: "manual" }); assert([200, 302].includes(verified.status));
      const signedIn = await invoke("/sign-in/email", { email: "smtp-user@example.test", password }); assert.equal(signedIn.status, 200);
      const cookie = cookies(signedIn);
      const concurrent = await Promise.all(Array.from({ length: 4 }, () => signupRuntime.fetch("/api/session", { headers: { Cookie: cookie } })));
      assert(concurrent.every(response => response.status === 200));
      const principals = await Promise.all(concurrent.map(async response => await response.json() as Principal));
      const owner = principals[0]!, account = owner.accounts[0]!;
      assert.equal(owner.accounts.length, 1); assert.equal(account.role, "owner");
      assert(principals.every(value => value.accounts.length === 1 && value.accounts[0]!.id === account.id));
      assert.equal(signupRuntime.env.MODE, "self-host");
      const target = `${signupRuntime.fixtures.httpUrl}/verified-signup-target`;
      const created = await signupRuntime.fetch(`/api/accounts/${account.id}/monitors`, { method: "POST", headers: { Cookie: cookie, Origin: signupRuntime.baseUrl, "Content-Type": "application/json", "X-CSRF-Token": owner.csrfToken }, body: JSON.stringify({ check: { kind: "http", url: target } }) });
      assert.equal(created.status, 201);
      const monitor = await created.json() as { monitor: { id: string; revision: number } };
      let observed = false;
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        const response = await signupRuntime.fetch(`/api/accounts/${account.id}/state`, { headers: { Cookie: cookie } }); assert.equal(response.status, 200);
        const state = await response.json() as { monitors: { id: string; state: string; lastObservedAt: number | null }[] };
        if (state.monitors.some(value => value.id === monitor.monitor.id && value.state === "UP" && value.lastObservedAt !== null)) { observed = true; break; }
        await delay(25);
      }
      assert(observed, "Verified real email signup must own a usable workspace and reach real UP through production prober");
      assert((signupRuntime.fixtures.hits.get("verified-signup-target") ?? 0) > 0);
      const usageResponse = await signupRuntime.fetch(`/api/accounts/${account.id}/usage`, { headers: { Cookie: cookie } }); assert.equal(usageResponse.status, 200);
      const usage = await usageResponse.json() as { mode: string; creditEnforced: boolean; balance: number; usage: number; grants: unknown[] };
      assert.equal(usage.mode, "self-host"); assert.equal(usage.creditEnforced, false); assert.equal(usage.balance, 0); assert.equal(usage.grants.length, 0); assert(usage.usage >= 1);
      const before = messages.length; assert.equal((await invoke("/request-password-reset", { email: "smtp-user@example.test", redirectTo: `${signupRuntime.baseUrl}/reset-password` })).status, 200);
      const resetMail = await receipt("Reset your Tomato password", before), resetLink = resetMail.match(/http[^\s<>]+\/api\/auth\/reset-password\/[^\s<>]+/); assert(resetLink);
      const redirect = await signupRuntime.fetch(resetLink[0], { redirect: "manual" }); const token = new URL(redirect.headers.get("Location")!).searchParams.get("token"); assert(token);
      assert.equal((await invoke("/reset-password", { token, newPassword: nextPassword })).status, 200);
      assert.equal((await invoke("/reset-password", { token, newPassword: password })).status, 400);
      const oldCookie = cookies(signedIn); const revoked = await email.fetch(new Request("https://identity.internal/authenticate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cookie: oldCookie }) })); assert.equal(revoked.status, 401);
      const renewed = await invoke("/sign-in/email", { email: "smtp-user@example.test", password: nextPassword }); assert.equal(renewed.status, 200);
      await verifyControlledOAuth(signupRuntime, { baseURL: signupRuntime.baseUrl, secret: signupRuntime.env.AUTH_SECRET, allowLoopback: true, signupEnabled: true, smtp: smtpFixture.smtp }, certificate, privateKey);
      const boundaryEmail = `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(56)}.test`, displayName = "Zoë 张 🌱", boundaryBefore = messages.length; assert.equal(boundaryEmail.length, 254);
      assert.equal((await invoke("/sign-up/email", { email: boundaryEmail, name: displayName, password, callbackURL: "/login" })).status, 200);
      const boundaryMail = await receipt("Verify your Tomato email", boundaryBefore), boundaryLink = boundaryMail.match(/http[^\s<>]+\/api\/auth\/verify-email\?[^\s<>]+/); assert(boundaryLink);
      const boundaryVerified = await signupRuntime.fetch(boundaryLink[0], { redirect: "manual" }); assert([200, 302].includes(boundaryVerified.status));
      const boundaryLogin = await invoke("/sign-in/email", { email: boundaryEmail, password }); assert.equal(boundaryLogin.status, 200);
      const boundaryCookie = cookies(boundaryLogin), boundarySession = await signupRuntime.fetch("/api/session", { headers: { Cookie: boundaryCookie } }); assert.equal(boundarySession.status, 200);
      const boundary = await boundarySession.json() as Principal, boundaryAccount = boundary.accounts[0]!; assert.equal(boundary.actor.username, boundaryEmail); assert.match(boundary.actor.id, /^[A-Za-z0-9_-]{1,64}$/); assert(boundaryAccount.name.includes(displayName));
      const savedUser = (await signupRuntime.database.query<{ name: string }>("SELECT name FROM public.auth_user WHERE id=$1", [boundary.actor.id]))[0]!; assert.equal(savedUser.name, displayName);
      const unicodeMonitor = await signupRuntime.fetch(`/api/accounts/${boundaryAccount.id}/monitors`, { method: "POST", headers: { Cookie: boundaryCookie, Origin: signupRuntime.baseUrl, "Content-Type": "application/json", "X-CSRF-Token": boundary.csrfToken }, body: JSON.stringify({ name: "边界 🥫 Zoë", check: { kind: "http", url: `${signupRuntime.fixtures.httpUrl}/email-boundary-target` } }) }); assert.equal(unicodeMonitor.status, 201);
      assert.equal((await unicodeMonitor.json() as { monitor: { name: string } }).monitor.name, "边界 🥫 Zoë");
      const boundaryAudit = await signupRuntime.fetch(`/api/accounts/${boundaryAccount.id}/audit`, { headers: { Cookie: boundaryCookie } }); assert.equal(boundaryAudit.status, 200);
      const entries = await boundaryAudit.json() as { entries: { actor: string; action: string }[] }; assert(entries.entries.some(entry => entry.action === "monitor.create")); assert(entries.entries.every(entry => entry.actor === boundary.actor.id));
      const boundaryUi = await signupRuntime.fetch(`/app/accounts/${boundaryAccount.id}/settings`, { headers: { Cookie: boundaryCookie } }); assert.equal(boundaryUi.status, 200); assert((await boundaryUi.text()).includes(displayName));
      const renewedPrincipalResponse = await signupRuntime.fetch("/api/session", { headers: { Cookie: cookies(renewed) } }); assert.equal(renewedPrincipalResponse.status, 200); const renewedPrincipal = await renewedPrincipalResponse.json() as Principal;
      const longInvitation = await signupRuntime.fetch(`/api/accounts/${account.id}/invitations`, { method: "POST", headers: { Cookie: cookies(renewed), Origin: signupRuntime.baseUrl, "Content-Type": "application/json", "X-CSRF-Token": renewedPrincipal.csrfToken }, body: JSON.stringify({ username: boundaryEmail, role: "viewer" }) }); assert.equal(longInvitation.status, 201);
      const invitationBody = await longInvitation.json() as { invitationToken: string; invitation: { username: string } }; assert.equal(invitationBody.invitation.username, boundaryEmail);
      const acceptedLongInvitation = await signupRuntime.fetch(`/invite/${invitationBody.invitationToken}`, { method: "POST", headers: { Cookie: boundaryCookie, Origin: signupRuntime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ csrfToken: boundary.csrfToken }), redirect: "manual" }); assert([302, 303].includes(acceptedLongInvitation.status));
      const sharedResponse = await signupRuntime.fetch("/api/session", { headers: { Cookie: boundaryCookie } }); assert.equal(sharedResponse.status, 200); const sharedPrincipal = await sharedResponse.json() as Principal; assert.equal(sharedPrincipal.accounts.find(value => value.id === account.id)?.role, "viewer"); assert.equal(sharedPrincipal.accounts.find(value => value.id === boundaryAccount.id)?.role, "owner");
      invitationFixture = await verifyClosedInvitationFlow(smtpFixture.smtp, messages);
      await smtpFixture.stop();
      await invitationFixture.verifyOutage();
      const knownOutage = await invoke("/request-password-reset", { email: "smtp-user@example.test" }), unknownOutage = await invoke("/request-password-reset", { email: "unknown-smtp@example.test" });
      assert.equal(knownOutage.status, 503); assert.equal(unknownOutage.status, 503);
      assert.equal(await knownOutage.text(), await unknownOutage.text());
      } finally { await invitationFixture?.close(); await signupRuntime.close(); }
    } finally { await smtpFixture.close(); }
  });
  await scenario("bounded Better Auth legacy verifier rehash preserves identities and key lineage", async () => {
    const legacy = await createProductionTestRuntime({ background: false });
    const pepper = randomBytes(32).toString("hex"), salt = randomBytes(24).toString("hex"), migration = { pepper, expiresAt: Date.now() + 86400000 };
    const derived = Promise.withResolvers<Buffer>();
    scrypt(createHmac("sha256", pepper).update(password).digest(), salt, 32, { N: 16384, r: 8, p: 5, maxmem: 32 * 1024 * 1024 }, (error, value) => error ? derived.reject(error) : derived.resolve(value));
    const verifier = (await derived.promise).toString("hex");
    const source: LegacyIdentityExport = { users: [{ id: "legacy-user", username: "old-username", salt, verifier }], accounts: [{ id: "legacy-workspace", name: "Legacy" }], members: [{ account_id: "legacy-workspace", user_id: "legacy-user", role: "owner" }], api_keys: [], invitations: [], slugs: [], audit: [], mcp_sessions: [] };
    const rootToken = randomToken("tomato_key_"), childToken = randomToken("tomato_key_"), now = Date.now();
    source.api_keys = [
      { id: "legacy-root", user_id: "legacy-user", account_id: "legacy-workspace", token_hash: await digest(rootToken), name: "Root", scope: "manage", created_at: now, expires_at: now + 86400000, last_used_at: null, parent_key_id: null },
      { id: "legacy-child", user_id: "legacy-user", account_id: "legacy-workspace", token_hash: await digest(childToken), name: "Child", scope: "read", created_at: now, expires_at: now + 3600000, last_used_at: null, parent_key_id: "legacy-root" },
    ];
    let identity: IdentityService | undefined;
    try {
      await assert.rejects(importLegacyIdentity(legacy.database, { export: source, emailMap: { "old-username": { email: "actual@example.test", name: "", emailVerified: true } }, migration, acknowledgeLegacySessionInvalidation: true }), /real_email_mapping_required/);
      await importLegacyIdentity(legacy.database, { export: source, emailMap: { "old-username": { email: "legacy-owner@example.test", name: "Legacy Owner", emailVerified: true } }, migration, acknowledgeLegacySessionInvalidation: true });
      await assert.rejects(finalizeLegacyIdentityCutover(legacy.database), /legacy_cutover_not_complete/);
      identity = createIdentity(legacy.database, { baseURL: legacy.baseUrl, allowLoopback: true, secret: legacy.env.AUTH_SECRET, legacyMigration: migration });
      const response = await identity.authHandler(new Request(`${legacy.baseUrl}/api/auth/sign-in/email`, { method: "POST", headers: { Origin: legacy.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email: "legacy-owner@example.test", password }) })); assert.equal(response.status, 200);
      const credential = (await legacy.database.query<{ password: string }>(`SELECT password FROM public.auth_account WHERE "userId"='legacy-user'`))[0]!; assert(!isLegacyCredential(credential.password));
      await finalizeLegacyIdentityCutover(legacy.database);
      const authenticated = await identity.fetch(new Request("https://identity.internal/authenticate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cookie: cookies(response), accountId: "legacy-workspace" }) })); assert.equal(authenticated.status, 200); const principal = await authenticated.json() as Principal; assert.equal(principal.actor.id, "legacy-user"); assert.equal(principal.account?.role, "owner");
      const keyRequest = () => identity!.fetch(new Request("https://identity.internal/authenticate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: childToken, accountId: "legacy-workspace" }) }));
      assert.equal((await keyRequest()).status, 200);
      const removal = await identity.fetch(new Request("https://identity.internal/api-keys/revoke", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actorId: "legacy-user", accountId: "legacy-workspace", id: "legacy-root", authSessionId: principal.sessionId }) })); assert.equal(removal.status, 200);
      assert.equal((await keyRequest()).status, 401);
    } finally { await identity?.drain(); await legacy.close(); }
  });
  await scenario("durable one-time bootstrap preserves actual ownership transfer and credential changes across restart", verifyBootstrapIdentity);
  await scenario("expired bridge preserves modern authority and real SMTP reset upgrades legacy credentials", verifyExpiredLegacyAuth);
  console.log(`PASS maintained PostgreSQL identity: ${scenarios} scenarios`);
} finally { await runtime.close(); }
