import assert from "node:assert/strict";
import { createHmac, randomBytes, scrypt } from "node:crypto";
import { mkdtemp, copyFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import tls from "node:tls";
import pg from "pg";
import { setTimeout as delay } from "node:timers/promises";
import { PgDatabase } from "../src/database.ts";
import { createAuth } from "../src/auth.ts";
import { createIdentity, createControlledOAuthIdentity, randomToken } from "../src/identity.ts";
import { importLegacyIdentity, type LegacyIdentityExport } from "../src/identity-import.ts";
import { importLegacyEngine } from "../src/engine-import.ts";
import { AccountSecrets } from "../src/account-secrets.ts";
import { digest } from "../src/validation.ts";
import { executeMessage } from "../src/worker.ts";
import type { EngineSnapshot, MonitorRecord, NotificationRecord } from "../src/types.ts";
import type { Principal, WalletView } from "../src/product-types.ts";
import { createProductionTestRuntime, type ProductionTestRuntime } from "./production-test-runtime.ts";
import { createSmtpFixture } from "./smtp-fixture.ts";
import { NativeClient, htmlCsrf } from "./local-client.ts";
import { createControlledIdp } from "./oauth-fixture.ts";

if (process.argv.slice(2).some(argument => !["--backfill", "--continuity", "--recovery"].includes(argument))) throw new Error("invalid_enrollment_verification_selection");
let passed = 0;
async function scenario(name: string, action: () => Promise<void>) { await action(); passed++; console.log(`PASS ${name}`); }
async function legacyUser(id: string, username: string, password: string, pepper: string) {
  const salt = randomBytes(24).toString("hex"), material = createHmac("sha256", pepper).update(password).digest(), result = Promise.withResolvers<Buffer>();
  scrypt(material, salt, 32, { N: 16384, r: 8, p: 5, maxmem: 32 * 1024 * 1024 }, (error, key) => error ? result.reject(error) : result.resolve(key));
  const verifier = await result.promise;
  try { return { id, username, salt, verifier: verifier.toString("hex") }; } finally { material.fill(0); verifier.fill(0); }
}
async function internal<T>(runtime: ProductionTestRuntime, endpoint: string, input: unknown, status = 200): Promise<T> {
  const response = await runtime.env.identity.fetch(new Request(`https://identity.internal${endpoint}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) }));
  assert.equal(response.status, status, `${endpoint}: unexpected status`); return await response.json() as T;
}
async function engine<T>(runtime: ProductionTestRuntime, endpoint: string, method = "GET", input?: unknown): Promise<T> {
  const response = await runtime.internalFetch("continuity", endpoint, { method, headers: { "Content-Type": "application/json" }, ...(input === undefined ? {} : { body: JSON.stringify(input) }) });
  assert.equal(response.status, endpoint === "/monitors" && method === "POST" ? 201 : 200, `${endpoint}: unexpected engine status`); return await response.json() as T;
}
async function form(client: NativeClient, page: string, action: string, input: Record<string, string>, expected = 303) {
  const rendered = await client.request(page, { expected: 200 });
  return client.request(action, { form: new URLSearchParams({ csrfToken: htmlCsrf(rendered.text), ...input }), expected });
}

if (process.argv[2] !== "--continuity") await scenario("append migration backfills modern IDs and preserves live cookies, keys, roles and revocation", async () => {
  const adminUrl = new URL(process.env.TEST_DATABASE_ADMIN_URL ?? "postgresql://localhost/postgres");
  assert(["localhost", "127.0.0.1", "[::1]"].includes(adminUrl.hostname));
  const id = `tomato_backfill_${randomBytes(12).toString("hex")}`, admin = new pg.Pool({ connectionString: adminUrl.href, max: 1 }), password = randomBytes(32).toString("hex"), url = new URL(adminUrl);
  url.pathname = `/${id}`; url.username = id; url.password = password;
  const database = new PgDatabase(new pg.Pool({ connectionString: url.href, max: 2 })), scratch = await mkdtemp(path.join(tmpdir(), "tomato-enrollment-backfill-"));
  let created = false, roleCreated = false;
  try {
    await admin.query(`CREATE ROLE "${id}" LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`); roleCreated = true;
    await admin.query(`CREATE DATABASE "${id}" OWNER "${id}"`); created = true;
    for (const file of ["001_engine.sql", "002_identity.sql", "003_identity_bootstrap.sql"]) await copyFile(path.join("migrations", file), path.join(scratch, file));
    await database.migrate(scratch);
    const config = { baseURL: "http://127.0.0.1:49151", allowLoopback: true, secret: randomBytes(32).toString("hex") }, maintained = createAuth(database, config), ownerPassword = randomBytes(24).toString("hex");
    try {
      const owner = await maintained.provision({ id: "modern", name: "Existing modern", owner: { email: "modern@example.test", name: "Modern", password: ownerPassword, emailVerified: true } });
      const login = await maintained.authHandler(new Request(`${config.baseURL}/api/auth/sign-in/email`, { method: "POST", headers: { Origin: config.baseURL, "Content-Type": "application/json", "X-Tomato-Client-IP": "127.0.0.1" }, body: JSON.stringify({ email: "modern@example.test", password: ownerPassword }) })); assert.equal(login.status, 200);
      const cookie = login.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; "), key = randomToken("tomato_key_");
      await database.query("INSERT INTO identity.api_keys(id,user_id,account_id,token_hash,name,scope,created_at,expires_at) VALUES('modern-key',$1,'modern',$2,'Preserved','manage',$3,$4)", [owner.owner.id, await digest(key), Date.now(), Date.now() + 86400000]);
      await database.migrate();
      const identity = createIdentity(database, config);
      try {
        for (const credentials of [{ cookie }, { token: key }]) {
          const response = await identity.fetch(new Request("https://identity.internal/authenticate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...credentials, accountId: "modern" }) })); assert.equal(response.status, 200); const principal = await response.json() as Principal; assert.equal(principal.actor.id, owner.owner.id); assert.equal(principal.account?.role, "owner");
        }
        await database.query("DELETE FROM public.auth_user WHERE id=$1", [owner.owner.id]);
        assert.equal((await database.query("SELECT id FROM identity.subjects WHERE id=$1", [owner.owner.id])).length, 0);
        assert.equal((await database.query("SELECT id FROM identity.api_keys WHERE id='modern-key'")).length, 0);
      } finally { await identity.drain(); }
    } finally { await maintained.drain(); }
  } finally {
    await database.close(); if (created) await admin.query(`DROP DATABASE "${id}" WITH (FORCE)`); if (roleCreated) await admin.query(`DROP ROLE "${id}"`); await admin.end(); await rm(scratch, { recursive: true, force: true });
  }
});
if (process.argv[2] === "--backfill") process.exit(0);

const smtp = await createSmtpFixture(), pepper = randomBytes(32).toString("hex"), migration = { pepper, expiresAt: Date.now() + 86400000 };
const ownerPassword = "oldpass9", viewerPassword = "viewold9", otherPassword = "otherold9", mappedPassword = randomBytes(24).toString("hex"), invitePassword = randomBytes(24).toString("hex");
const sourceRuntime = await createProductionTestRuntime({ background: false });
let runtime: ProductionTestRuntime | undefined;
try {
  await engine(sourceRuntime, "/credits/continuity-grant", "PUT", { credits: 200, reason: "Owned enrollment proof" });
  const secretHeader = randomBytes(24).toString("hex");
  await engine(sourceRuntime, "/monitors", "POST", { id: "preserved-monitor", name: "Preserved actual monitor", check: { kind: "http", url: `${sourceRuntime.fixtures.httpUrl}/enrollment-running`, contains: "TOMATOOK", headers: { "X-Private": secretHeader } }, intervalMs: 60000, timeoutMs: 1000, confirmationDelayMs: 100, executionWindowMs: 30000 });
  await engine(sourceRuntime, "/tick", "POST");
  const scheduled = await engine<EngineSnapshot>(sourceRuntime, "/state"), job = scheduled.jobs.find(row => row.status === "pending" && row.role === "primary"); assert(job);
  await executeMessage(sourceRuntime.env, { kind: "check", accountId: "continuity", jobId: job.id });
  const before = await engine<EngineSnapshot>(sourceRuntime, "/state"); assert.equal(before.usage, 1); assert.equal(before.monitors[0]!.state, "UP");
  await executeMessage(sourceRuntime.env, { kind: "archive", accountId: "continuity" });
  const columns: Record<string, string[]> = {
    metadata: ["key", "value"], wallet: ["id", "balance", "reserved", "usage", "missed", "archive_sequence"], deposits: ["id", "credits"], monitors: ["id", "next_due", "paused", "data"], jobs: ["id", "monitor_id", "status", "expires_at", "scheduled_at", "data"], observations: ["id", "observed_at", "archived", "data", "cursor AS rowid"], incidents: ["id", "data", "cursor AS rowid"], notifications: ["id", "status", "next_due", "data", "cursor AS rowid"], pulses: ["monitor_id", "pulse_id", "received_at"], coverage: ["monitor_id", "started_at", "ended_at", "state", "evidence_mode", "cursor AS rowid"], outbox: ["id", "next_due", "message"], retired_monitors: ["id", "name", "deleted_at"], grants: ["id", "reason", "created_at"], audit: ["id", "data", "cursor AS rowid"], maintenance: ["id", "monitor_id", "starts_at", "ends_at", "data"], freshness: ["monitor_id", "observed_at", "fresh_until"],
  };
  const exported = await sourceRuntime.database.transaction("continuity", async tx => {
    const tables: Record<string, Record<string, unknown>[]> = {}, secrets = new AccountSecrets(sourceRuntime.env.DATA_KEY, "continuity");
    for (const [table, fields] of Object.entries(columns)) {
      const rows = await tx.query<Record<string, unknown>>(`SELECT ${fields.join(",")} FROM engine.${table}`);
      for (const row of rows) {
        if (table === "monitors") row.data = JSON.stringify(secrets.decodeMonitor(String(row.data)) as MonitorRecord);
        if (table === "notifications") row.data = JSON.stringify(secrets.decodeNotification(String(row.data)) as NotificationRecord);
        if (table === "metadata" && row.key === "notification-defaults") row.value = JSON.stringify(secrets.decodeDefaults(String(row.value)));
      }
      tables[table] = rows;
    }
    const archives = await tx.query<{ id: string; payload: Buffer; created_at: number }>("SELECT id,payload,created_at FROM engine.archives ORDER BY id");
    return { version: 1, kind: "tomato-engine-export", mode: "hosted", accounts: [{ accountId: "continuity", tables, archives: archives.map(row => ({ id: row.id, payloadBase64: row.payload.toString("base64"), createdAt: row.created_at })) }] };
  });
  runtime = await createProductionTestRuntime({ background: false, fixtures: sourceRuntime.fixtures, runtime: { smtp: smtp.smtp, legacyMigration: migration } });
  const target = runtime;
  const rootKey = randomToken("tomato_key_"), childKey = randomToken("tomato_key_"), viewerKey = randomToken("tomato_key_"), invitations: Record<string, string> = {};
  const users = await Promise.all([
    legacyUser("legacy-owner", "owner-old", ownerPassword, pepper), legacyUser("legacy-viewer", "viewer-old", viewerPassword, pepper), legacyUser("legacy-other", "other-old", otherPassword, pepper), legacyUser("mapped-modern", "mapped-old", mappedPassword, pepper), legacyUser("mapped-legacy", "bridge-old", mappedPassword, pepper),
  ]);
  const now = Date.now();
  const identityExport: LegacyIdentityExport = { users, accounts: [{ id: "continuity", name: "Preserved Workspace" }, { id: "foreign", name: "Other Workspace" }], members: [{ account_id: "continuity", user_id: "legacy-owner", role: "owner" }, { account_id: "continuity", user_id: "legacy-viewer", role: "viewer" }, { account_id: "foreign", user_id: "legacy-other", role: "owner" }, { account_id: "continuity", user_id: "mapped-modern", role: "editor" }, { account_id: "continuity", user_id: "mapped-legacy", role: "viewer" }], api_keys: [], invitations: [], slugs: [{ slug: "preserved-status", account_id: "continuity" }], audit: [], mcp_sessions: [] };
  for (const [id, userId, scope, key, parent] of [["root-key", "legacy-owner", "manage", rootKey, null], ["child-key", "legacy-owner", "read", childKey, "root-key"], ["viewer-key", "legacy-viewer", "manage", viewerKey, null]] as const) identityExport.api_keys.push({ id, user_id: userId, account_id: "continuity", scope, token_hash: await digest(key), name: id, created_at: now, expires_at: now + 86400000, last_used_at: null, parent_key_id: parent });
  for (const [id, username, status, role, expiresAt] of [["invite-new", "new-invited", "pending", "viewer", now + 86400000], ["invite-existing", "other-old", "pending", "editor", now + 86400000], ["invite-revoked", "revoked-name", "revoked", "owner", now + 86400000], ["invite-expired", "expired-name", "pending", "owner", now - 1], ["invite-race", "race-name", "pending", "viewer", now + 86400000]] as const) {
    const value = randomToken("tomato_invite_"); invitations[id] = value; identityExport.invitations.push({ id, username, account_id: "continuity", status, role, token_hash: await digest(value), created_at: now - 86400000, expires_at: expiresAt });
  }
  identityExport.mcp_sessions.push({ id: "preserved-mcp", user_id: "legacy-owner", account_id: "continuity", auth_binding: "child-key", protocol_version: "2025-11-25", initialized: 1, expires_at: now + 3600000 });
  await scenario("unmapped import preserves stable IDs, roles, key lineage, MCP, monitor, history and exact wallet", async () => {
    await importLegacyIdentity(target.database, { export: identityExport, emailMap: { "mapped-old": { email: "mapped-modern@example.test", name: "Mapped modern", emailVerified: true }, "bridge-old": { email: "bridge-old@example.test", name: "Bounded bridge", emailVerified: true } }, passwordProofs: { "mapped-modern": mappedPassword }, migration, acknowledgeLegacySessionInvalidation: true });
    await importLegacyEngine(target.database, exported, target.env.DATA_KEY, true);
    assert.equal((await target.database.query("SELECT id FROM public.auth_user WHERE id LIKE 'legacy-%'")).length, 0);
    const restored = await engine<EngineSnapshot>(target, "/state"); assert.equal(restored.balance, before.balance); assert.equal(restored.usage, before.usage); assert.equal(restored.reserved, before.reserved); assert.equal(restored.monitors[0]!.id, before.monitors[0]!.id);
    for (const key of [rootKey, childKey, viewerKey]) assert.equal((await internal<Principal>(target, "/authenticate", { token: key, accountId: "continuity" })).account?.id, "continuity");
    const lineage = (await target.database.query<{ parent_key_id: string }>("SELECT parent_key_id FROM identity.api_keys WHERE id='child-key'"))[0]!; assert.equal(lineage.parent_key_id, "root-key");
    await internal(target, "/mcp/validate", { actorId: "legacy-owner", accountId: "continuity", authBinding: "child-key", sessionId: "preserved-mcp", requireInitialized: true });
    await target.restart();
  });
  migration.expiresAt = Date.now() - 1;
  await target.restart();
  const owner = new NativeClient(target.baseUrl), viewer = new NativeClient(target.baseUrl), stranger = new NativeClient(target.baseUrl);
  const mailLink = (after: number): string => {
    const message = smtp.messages.slice(after).find(value => value.includes("Verify your Tomato enrollment")); assert(message, "Real TLS SMTP must accept the enrollment message"); const decoded = message.replace(/=\r\n/g, "").replace(/=3D/g, "="), match = decoded.match(/http[^\s<>]+\/enroll\/verify\?token=[^\s<>]+/); assert(match); return match[0];
  };
  async function contact(client: NativeClient, email: string): Promise<string> { const after = smtp.messages.length; await form(client, "/enroll/contact", "/enroll/contact", { email }); return mailLink(after); }
  async function finish(client: NativeClient, link: string, expected = 303) { const page = await client.request(link, { expected: 200 }); const emailToken = new URL(link).searchParams.get("token")!; return client.request("/enroll/verify", { form: new URLSearchParams({ csrfToken: htmlCsrf(page.text), emailToken }), expected }); }
  await scenario("expired full-login bridge cannot log in, but unmapped original short password starts only restricted enrollment", async () => {
    const expired = await target.fetch("/api/auth/sign-in/email", { method: "POST", headers: { Origin: target.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email: "bridge-old@example.test", password: mappedPassword }) }); assert.equal(expired.status, 401);
    const modern = new NativeClient(target.baseUrl); await modern.login("mapped-modern@example.test", mappedPassword);
    const noChange = await target.database.query("SELECT id FROM public.auth_user ORDER BY id");
    await form(owner, "/enroll", "/enroll", { username: "owner-old", password: "wrong-original" }, 401);
    assert.deepEqual(await target.database.query("SELECT id FROM public.auth_user ORDER BY id"), noChange);
    const page = await owner.request("/enroll", { expected: 200 });
    await owner.request("/enroll", { form: new URLSearchParams({ csrfToken: htmlCsrf(page.text), username: "owner-old", password: ownerPassword }), origin: "https://evil.invalid", expected: 403 });
    await owner.request("/enroll", { form: new URLSearchParams({ csrfToken: "wrong", username: "owner-old", password: ownerPassword }), expected: 403 });
    await form(owner, "/enroll", "/enroll", { username: "owner-old", password: ownerPassword });
    assert(owner.cookies.has("tomato-enrollment")); assert(!owner.cookies.has("tomato-session")); await owner.request("/api/session", { expected: 401 });
    await owner.request("/api/accounts/continuity/monitors", { json: { check: { kind: "heartbeat" } }, expected: 401 });
    await form(owner, "/enroll/contact", "/enroll/contact", { email: "mapped-modern@example.test" }, 409);
    await target.restart();
  });
  if (process.argv.includes("--recovery")) await scenario("owned Linux PostgreSQL 18 encrypted full recovery preserves pending claim, keys, original roles and exact engine ledger", async () => {
    assert(target.recover, "Explicit labeled owned PG18 recovery container is required");
    const wallet = await engine<WalletView>(target, "/usage"), memberships = await target.database.query("SELECT * FROM identity.members ORDER BY account_id,user_id");
    await target.recover();
    await owner.request("/enroll/contact", { expected: 200 });
    assert.deepEqual(await target.database.query("SELECT * FROM identity.members ORDER BY account_id,user_id"), memberships);
    const recovered = await engine<WalletView>(target, "/usage"); assert.equal(recovered.balance, wallet.balance); assert.equal(recovered.usage, wallet.usage); assert.equal(recovered.reserved, wallet.reserved);
    assert.equal((await internal<Principal>(target, "/authenticate", { token: childKey })).actor.id, "legacy-owner");
  });
  await scenario("real email verification requires original claim context, consumes all claims once, keeps password and workspace", async () => {
    const link = await contact(owner, "owner-actual@example.test");
    if (process.argv.includes("--recovery")) { assert(target.recover); await target.recover(); }
    await stranger.request(link, { expected: 401 });
    await form(owner, "/enroll/verify?token=wrong", "/enroll/verify", { emailToken: randomBytes(32).toString("base64url") }, 401);
    assert.equal((await target.database.query("SELECT id FROM public.auth_user WHERE id='legacy-owner'")).length, 0);
    await target.restart();
    const savedCookies = new Map(owner.cookies); await finish(owner, link); assert(!owner.cookies.has("tomato-enrollment"));
    const replay = new NativeClient(target.baseUrl); for (const [name, value] of savedCookies) replay.cookies.set(name, value); await replay.request(link, { expected: 401 });
    assert.equal((await target.database.query("SELECT user_id FROM identity.legacy_enrollment WHERE user_id='legacy-owner'")).length, 0);
    assert.equal((await target.database.query("SELECT token_hash FROM identity.enrollment_claims WHERE user_id='legacy-owner'")).length, 0);
    await owner.login("owner-actual@example.test", ownerPassword);
    const principal = JSON.parse((await owner.request("/api/session", { expected: 200 })).text) as Principal; assert.equal(principal.actor.id, "legacy-owner"); assert.equal(principal.accounts.length, 1); assert.equal(principal.accounts[0]!.id, "continuity"); assert.equal(principal.accounts[0]!.role, "owner");
    assert.equal((await internal<Principal>(target, "/authenticate", { token: childKey, accountId: "continuity" })).actor.id, "legacy-owner");
    await target.restart(); await owner.request("/api/session", { expected: 200 });
  });
  await scenario("expired claims permit fresh proof without orphaning users; live viewer and account boundaries remain enforced", async () => {
    await form(viewer, "/enroll", "/enroll", { username: "viewer-old", password: viewerPassword });
    const claim = viewer.cookies.get("tomato-enrollment")!;
    await target.database.query("UPDATE identity.enrollment_claims SET expires_at=$1 WHERE token_hash=$2", [Date.now() - 1, await digest(claim)]);
    await viewer.request("/enroll/contact", { expected: 401 });
    await form(viewer, "/enroll", "/enroll", { username: "viewer-old", password: viewerPassword });
    await finish(viewer, await contact(viewer, "viewer-actual@example.test")); await viewer.login("viewer-actual@example.test", viewerPassword);
    const principal = JSON.parse((await viewer.request("/api/session", { expected: 200 })).text) as Principal; assert.equal(principal.actor.id, "legacy-viewer"); assert.equal(principal.accounts[0]!.role, "viewer");
    await viewer.request("/api/accounts/continuity/monitors", { json: { check: { kind: "heartbeat" } }, csrf: principal.csrfToken, expected: 403 });
    await owner.request("/api/accounts/foreign/workspace", { expected: 404 });
    const denied = await target.fetch("/api/accounts/foreign/workspace", { headers: { Authorization: `Bearer ${childKey}` } }); assert.equal(denied.status, 404);
    assert.equal((await target.database.query("SELECT id FROM public.auth_user WHERE id='legacy-other'")).length, 0);
  });
  await scenario("original invitation tokens grant only verified new targets and exact current role, not legacy principal takeover", async () => {
    const invited = new NativeClient(target.baseUrl), originalHash = await digest(invitations["invite-new"]!);
    for (const id of ["invite-revoked", "invite-expired"]) await invited.request(`/invite/${invitations[id]}`, { expected: 404 });
    await form(invited, `/invite/${invitations["invite-existing"]}`, "/enroll/invitation", { invitationToken: invitations["invite-existing"]!, username: "other-old", password: invitePassword }, 403);
    await form(invited, `/invite/${invitations["invite-new"]}`, "/enroll/invitation", { invitationToken: invitations["invite-new"]!, username: "wrong-target", password: invitePassword }, 403);
    const reserved = (await target.database.query<{ user_id: string }>("SELECT user_id FROM identity.legacy_invite_targets WHERE username='new-invited'"))[0]!.user_id;
    await form(invited, `/invite/${invitations["invite-new"]}`, "/enroll/invitation", { invitationToken: invitations["invite-new"]!, username: "new-invited", password: invitePassword });
    const link = await contact(invited, "new-invited-actual@example.test"); await target.restart(); await finish(invited, link); await invited.login("new-invited-actual@example.test", invitePassword);
    const principal = JSON.parse((await invited.request("/api/session", { expected: 200 })).text) as Principal; assert.equal(principal.actor.id, reserved); assert.deepEqual(principal.accounts.map(row => ({ id: row.id, role: row.role })), [{ id: "continuity", role: "viewer" }]);
    const invitation = (await target.database.query<{ status: string; token_hash: string; role: string }>("SELECT status,token_hash,role FROM identity.invitations WHERE id='invite-new'"))[0]!; assert.equal(invitation.status, "accepted"); assert.equal(invitation.token_hash, originalHash); assert.equal(invitation.role, "viewer");
    await invited.request(`/invite/${invitations["invite-new"]}`, { expected: 404 });
    const race = new NativeClient(target.baseUrl); await form(race, `/invite/${invitations["invite-race"]}`, "/enroll/invitation", { invitationToken: invitations["invite-race"]!, username: "race-name", password: invitePassword }); const raceLink = await contact(race, "race-actual@example.test");
    await target.database.query("UPDATE identity.invitations SET status='revoked' WHERE id='invite-race'"); await race.request(raceLink, { expected: 401 });
    assert.equal((await target.database.query("SELECT id FROM public.auth_user WHERE email='race-actual@example.test'")).length, 0);
  });
  await scenario("maintained real TLS OAuth cannot link or hijack enrolled email collisions", async () => {
    const previous = target.env.identity, authorities = tls.getCACertificates("default"), oldNodeEnv = process.env.NODE_ENV, issuer = await createControlledIdp(smtp.certificate, smtp.privateKey, `${target.baseUrl}/api/auth/callback/tomato-controlled-idp`);
    issuer.identity.email = "owner-actual@example.test";
    process.env.NODE_ENV = "test"; tls.setDefaultCACertificates([...authorities, smtp.certificate]);
    const service = createControlledOAuthIdentity(target.database, { baseURL: target.baseUrl, secret: target.env.AUTH_SECRET, allowLoopback: true, signupEnabled: true, smtp: smtp.smtp, legacyMigration: migration }, issuer); target.env.identity = service;
    try {
      const start = await target.fetch("/api/auth/sign-in/social", { method: "POST", headers: { Origin: target.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ provider: "tomato-controlled-idp", callbackURL: `${target.baseUrl}/app`, disableRedirect: true }) }); assert.equal(start.status, 200);
      const authorization = await start.json() as { url: string }, redirect = await fetch(authorization.url, { redirect: "manual" }); assert.equal(redirect.status, 302);
      const result = await target.fetch(redirect.headers.get("Location")!, { headers: { Cookie: start.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ") }, redirect: "manual" }); assert(result.status >= 400 || result.headers.get("Location")?.includes("error="));
      assert.equal(issuer.tokenCount, 1); assert.equal(issuer.profileCount, 1);
      assert.equal((await target.database.query('SELECT id FROM public.auth_account WHERE "userId"=\'legacy-owner\' AND "providerId"=\'tomato-controlled-idp\'')).length, 0);
      assert.equal((await target.database.query("SELECT id FROM public.auth_user WHERE email='owner-actual@example.test'"))[0]!.id, "legacy-owner");
    } finally { target.env.identity = previous; await service.drain(); await issuer.close(); tls.setDefaultCACertificates(authorities); if (oldNodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = oldNodeEnv; }
  });
  await scenario("genuine monitoring continues without contacts and enrollment cannot mint credits; maintained reset retains revocation", async () => {
    const originalWallet = await engine<WalletView>(target, "/usage"), hits = target.fixtures.hits.get("enrollment-running") ?? 0;
    await target.database.transaction("continuity", tx => tx.query("UPDATE engine.monitors SET next_due=$1,data=jsonb_set(data::jsonb,'{nextDueAt}',to_jsonb($1::bigint))::text WHERE id='preserved-monitor'", [Date.now()]));
    target.startConsumer();
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline && (await engine<WalletView>(target, "/usage")).usage === originalWallet.usage) await delay(25);
    const after = await engine<WalletView>(target, "/usage"); assert.equal(after.usage, originalWallet.usage + 1); assert.equal(after.balance, originalWallet.balance - 1); assert((target.fixtures.hits.get("enrollment-running") ?? 0) > hits);
    assert.equal((await target.database.query("SELECT user_id FROM identity.legacy_enrollment WHERE user_id='legacy-other'")).length, 1);
    const lastMail = smtp.messages.length, reset = await target.fetch("/api/auth/request-password-reset", { method: "POST", headers: { Origin: target.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email: "owner-actual@example.test", redirectTo: `${target.baseUrl}/reset-password` }) }); assert.equal(reset.status, 200);
    const message = smtp.messages.slice(lastMail).find(value => value.includes("Reset your Tomato password")); assert(message); const decoded = message.replace(/=\r\n/g, "").replace(/=3D/g, "="), link = decoded.match(/http[^\s<>]+\/api\/auth\/reset-password\/[^\s<>]+/); assert(link);
    const returned = await target.fetch(link[0], { redirect: "manual" }), resetToken = new URL(returned.headers.get("Location")!).searchParams.get("token"); assert(resetToken);
    const completed = await target.fetch("/api/auth/reset-password", { method: "POST", headers: { Origin: target.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ token: resetToken, newPassword: randomBytes(24).toString("hex") }) }); assert.equal(completed.status, 200);
    await owner.request("/api/session", { expected: 401 }); await internal(target, "/authenticate", { token: childKey }, 401);
    assert.equal((await target.database.query("SELECT account_id FROM identity.members WHERE user_id='legacy-owner'"))[0]!.account_id, "continuity");
  });
  await scenario("verified-email collision races cannot merge another account and do not replace the claimant's original workspace", async () => {
    const other = new NativeClient(target.baseUrl);
    await form(other, "/enroll", "/enroll", { username: "other-old", password: otherPassword });
    const link = await contact(other, "late-collision@example.test");
    const existing = await target.env.identity.provision({ id: "collision-owner", name: "Independently owned collision", owner: { email: "late-collision@example.test", name: "Different verified identity", password: randomBytes(24).toString("hex"), emailVerified: true } });
    const before = await target.database.query("SELECT id,email FROM public.auth_user ORDER BY id"), membership = await target.database.query("SELECT * FROM identity.members WHERE user_id='legacy-other'");
    await finish(other, link, 409);
    assert.deepEqual(await target.database.query("SELECT id,email FROM public.auth_user ORDER BY id"), before); assert.deepEqual(await target.database.query("SELECT * FROM identity.members WHERE user_id='legacy-other'"), membership);
    assert.equal((await target.database.query("SELECT id FROM public.auth_user WHERE email='late-collision@example.test'"))[0]!.id, existing.owner.id);
    await finish(other, await contact(other, "other-actual@example.test")); await other.login("other-actual@example.test", otherPassword);
    const principal = JSON.parse((await other.request("/api/session", { expected: 200 })).text) as Principal; assert.equal(principal.actor.id, "legacy-other"); assert.deepEqual(principal.accounts.map(row => ({ id: row.id, role: row.role })), [{ id: "foreign", role: "owner" }]);
    await other.request("/api/accounts/continuity/workspace", { expected: 404 });
  });
  console.log(`PASS enrollment continuity: ${passed} scenarios; actual PostgreSQL non-BYPASS role, Node, private prober, TLS SMTP, SSR forms and maintained TLS OAuth`);
} finally { await runtime?.close(); await sourceRuntime.close(); await smtp.close(); }
