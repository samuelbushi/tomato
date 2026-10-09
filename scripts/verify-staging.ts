import assert from "node:assert/strict";
import { createHmac, randomBytes, scrypt } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import * as z from "zod";
import { createProductionTestRuntime } from "./production-test-runtime.ts";
import { createSmtpFixture } from "./smtp-fixture.ts";
import { NativeClient, htmlCsrf } from "./local-client.ts";
import { tickAccounts, dispatchOutbox, executeMessage } from "../src/worker.ts";
import { importLegacyIdentity, type LegacyIdentityExport } from "../src/identity-import.ts";
import { digest } from "../src/validation.ts";
import type { EngineSnapshot, MonitorView, NotificationView } from "../src/types.ts";
import type { Principal } from "../src/product-types.ts";

interface PendingNativeInvitation { client: NativeClient; path: string; csrf: string }

const InvitationReceipt = z.object({ invitationToken: z.string() });
const MailFailure = z.object({ message: z.string() });
if (process.argv[2] && !["--mail", "--delivery", "--capacity"].includes(process.argv[2])) throw new Error("invalid_staging_verification_selection");
const smtp = await createSmtpFixture(), pepper = randomBytes(32).toString("hex"), originalPassword = "stageold9", migration = { pepper, expiresAt: Date.now() + 86400000 }, settings = { workloadsEnabled: true, smtp: smtp.smtp, mailBudget: { daily: 3, hourly: 2 }, legacyMigration: migration };
const runtime = await createProductionTestRuntime({ background: false, runtime: settings });
let passed = 0;
async function scenario(name: string, action: () => Promise<void>) { await action(); passed++; console.log(`PASS ${name}`); }
async function account<T>(endpoint: string, method = "GET", input?: unknown, status = 200): Promise<T> {
  const response = await runtime.internalFetch("stage", endpoint, { method, headers: { "Content-Type": "application/json" }, ...(input === undefined ? {} : { body: JSON.stringify(input) }) });
  assert.equal(response.status, status, `${endpoint}: unexpected status`); return await response.json() as T;
}
try {
  const salt = randomBytes(24).toString("hex"), derived = Promise.withResolvers<Buffer>(), material = createHmac("sha256", pepper).update(originalPassword).digest();
  scrypt(material, salt, 32, { N: 16384, r: 8, p: 5, maxmem: 32 * 1024 * 1024 }, (error, key) => error ? derived.reject(error) : derived.resolve(key));
  const verifier = await derived.promise;
  const originalIdentity: LegacyIdentityExport = { users: [{ id: "stage-owner", username: "stage-original", salt, verifier: verifier.toString("hex") }], accounts: [{ id: "stage", name: "Imported owner without contact" }], members: [{ account_id: "stage", user_id: "stage-owner", role: "owner" }], api_keys: [], invitations: [], slugs: [], audit: [], mcp_sessions: [] };
  await importLegacyIdentity(runtime.database, { export: originalIdentity, migration, acknowledgeLegacySessionInvalidation: true });
  material.fill(0); verifier.fill(0);
  await account("/credits/approved-test", "PUT", { credits: 100, reason: "Owned staged freeze proof" });
  const created = await account<{ monitor: MonitorView }>("/monitors", "POST", { id: "active", name: "Do not pause imported configuration", check: { kind: "http", url: `${runtime.fixtures.httpUrl}/staging-frozen`, contains: "TOMATOOK" }, intervalMs: 1000, timeoutMs: 1000, confirmationDelayMs: 100, executionWindowMs: 30000, email: { address: "alert@example.test" } }, 201);
  const heartbeat = await account<{ monitor: MonitorView; heartbeatToken: string }>("/monitors", "POST", { id: "pulse", name: "Original heartbeat", check: { kind: "heartbeat" }, intervalMs: 1000, timeoutMs: 1000, confirmationDelayMs: 100, executionWindowMs: 30000 }, 201);
  await account("/tick", "POST");
  const queued = await account<EngineSnapshot>("/state"), job = queued.jobs.find(row => row.monitorId === "active" && row.role === "primary"); assert(job);
  const pending = await account<{ notifications: NotificationView[] }>("/monitors/active/notification-test", "POST", { revision: created.monitor.revision }); assert(pending.notifications.length > 0);
  const snapshot = () => runtime.database.transaction("stage", async tx => ({ monitors: await tx.query("SELECT id,next_due,paused,data FROM engine.monitors ORDER BY id"), wallet: await tx.query("SELECT * FROM engine.wallet"), jobs: await tx.query("SELECT * FROM engine.jobs ORDER BY id"), notifications: await tx.query("SELECT * FROM engine.notifications ORDER BY id"), outbox: await tx.query("SELECT * FROM engine.outbox ORDER BY id"), coverage: await tx.query("SELECT * FROM engine.coverage ORDER BY cursor") }));
  const before = await snapshot(), hits = runtime.fixtures.hits.get("staging-frozen") ?? 0, receipts = smtp.messages.length;
  if (!process.argv[2]) await scenario("coherent staged freeze retains imported active config while blocking ticks, reservations, probes, pulses and alerts across restart", async () => {
    settings.workloadsEnabled = false; await runtime.restart(); runtime.startConsumer();
    assert.equal((await runtime.fetch("/health/ready")).status, 200);
    assert.equal((await runtime.database.query("SELECT id FROM public.auth_user WHERE id='stage-owner'")).length, 0);
    await tickAccounts(runtime.database, runtime.env); assert.equal(await dispatchOutbox(runtime.database, runtime.env), 0);
    await assert.rejects(executeMessage(runtime.env, { kind: "check", accountId: "stage", jobId: job.id }), /monitoring_workloads_disabled/);
    for (const endpoint of ["/tick", "/claim", "/complete", "/notifications/claim", "/notifications/complete", "/monitors/active/check-now", "/monitors/active/notification-test"]) await account(endpoint, "POST", { jobId: job.id, revision: created.monitor.revision }, 503);
    const pulse = await runtime.fetch("/heartbeat/stage/pulse", { method: "POST", headers: { Authorization: `Bearer ${heartbeat.heartbeatToken}`, "Idempotency-Key": "frozen-pulse" } }); assert.equal(pulse.status, 503);
    await account("/state"); await account("/usage"); await delay(1250); await runtime.restart();
    assert.deepEqual(await snapshot(), before); assert.equal(runtime.fixtures.hits.get("staging-frozen") ?? 0, hits); assert.equal(smtp.messages.length, receipts);
  });
  await runtime.stopConsumer();
  const password = randomBytes(24).toString("hex"), modern = await runtime.env.identity.provision({ id: "mail-owner", name: "Mail-only proof", owner: { email: "mail-owner@example.test", name: "Owned operator proof", password, emailVerified: true } });
  const invoke = (email: string) => runtime.fetch("/api/auth/request-password-reset", { method: "POST", headers: { Origin: runtime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email, redirectTo: `${runtime.baseUrl}/reset-password` }) });
  if (!["--delivery", "--capacity"].includes(process.argv[2] ?? "")) await scenario("durable combined auth and alert SMTP budget survives restart and denies before claimed send", async () => {
    assert.equal((await invoke("mail-owner@example.test")).status, 200); assert.equal(smtp.messages.length, receipts + 1);
    settings.workloadsEnabled = true; await runtime.restart();
    const event = pending.notifications[0]!;
    await executeMessage(runtime.env, { kind: "notification", accountId: "stage", eventId: event.id });
    assert.equal(smtp.messages.length, receipts + 2);
    const delivered = await account<EngineSnapshot>("/state"); assert.equal(delivered.notifications.find(row => row.id === event.id)!.status, "delivered");
    await runtime.restart(); const exhausted = await invoke("mail-owner@example.test"); assert.equal(exhausted.status, 503); const exhaustedPayload: unknown = await exhausted.json(); assert.equal(MailFailure.parse(exhaustedPayload).message, "smtp_budget_exhausted"); assert.equal(smtp.messages.length, receipts + 2);
    const unknownExhausted = await invoke("never-registered@example.test"); assert.equal(unknownExhausted.status, 503); assert.deepEqual(await unknownExhausted.json(), exhaustedPayload);
    const attempted = await account<{ notifications: NotificationView[] }>("/monitors/active/notification-test", "POST", { revision: created.monitor.revision });
    await executeMessage(runtime.env, { kind: "notification", accountId: "stage", eventId: attempted.notifications[0]!.id });
    const failed = await account<EngineSnapshot>("/state"), notification = failed.notifications.find(row => row.id === attempted.notifications[0]!.id)!; assert.notEqual(notification.status, "delivered"); assert.equal(smtp.messages.length, receipts + 2);
    const budget = await runtime.database.query<{ attempts: number }>("SELECT attempts FROM identity.mail_admission ORDER BY period"); assert(budget.every(row => row.attempts === 2));
    // Advance only the owned fixture's persisted hour window; real day admission still limits total sends.
    await runtime.database.query("UPDATE identity.mail_admission SET window_started=window_started-3600000 WHERE period='hour'");
    assert.equal((await invoke("mail-owner@example.test")).status, 200); assert.equal(smtp.messages.length, receipts + 3);
    assert.equal((await invoke("mail-owner@example.test")).status, 503); assert.equal(smtp.messages.length, receipts + 3);
    assert.equal((await invoke("never-registered@example.test")).status, 503);
  });
  if (!["--delivery", "--capacity"].includes(process.argv[2] ?? "")) await scenario("maintained recipient schema rejects CSV/BCC and display-name inputs without SMTP or identity mutation", async () => {
    const client = new NativeClient(runtime.baseUrl), proof = await client.request("/enroll", { expected: 200 });
    await client.request("/enroll", { form: new URLSearchParams({ csrfToken: htmlCsrf(proof.text), username: "stage-original", password: originalPassword }), expected: 303 });
    const value = client.cookies.get("tomato-enrollment")!;
    const beforeUsers = await runtime.database.query("SELECT id,email FROM public.auth_user ORDER BY id"), beforeMail = smtp.messages.length;
    for (const email of ["name,other@example.test", "one@example.test,two.test", "Display <one@example.test>", "one@example.test\r\nBcc:two@example.test"]) {
      const page = await client.request("/enroll/contact", { expected: 200 });
      await client.request("/enroll/contact", { form: new URLSearchParams({ csrfToken: htmlCsrf(page.text), email }), expected: 400 });
    }
    assert.deepEqual(await runtime.database.query("SELECT id,email FROM public.auth_user ORDER BY id"), beforeUsers); assert.equal(smtp.messages.length, beforeMail);
    const claim = (await runtime.database.query<{ email: string | null }>("SELECT email FROM identity.enrollment_claims WHERE token_hash=$1", [await digest(value)]))[0]!; assert.equal(claim.email, null);
    assert.equal((await runtime.database.query("SELECT id FROM public.auth_user WHERE id=$1", [modern.owner.id])).length, 1);
    const owner = new NativeClient(runtime.baseUrl); await owner.login("mail-owner@example.test", password); const principal = JSON.parse((await owner.request("/api/session", { expected: 200 })).text) as Principal; assert.equal(principal.actor.id, modern.owner.id);
  });
  if (!process.argv[2] || process.argv[2] === "--capacity") await scenario("maintained signup verifies its real recipient with only one main transaction connection", async () => {
    const single = await createProductionTestRuntime({ background: false, databaseConnections: 1, runtime: { signupEnabled: true, smtp: smtp.smtp, mailBudget: { daily: 20, hourly: 5 } } });
    const email = "single-client@example.test", password = randomBytes(24).toString("hex"), before = smtp.messages.length;
    try {
      const registered = await single.fetch("/api/auth/sign-up/email", { method: "POST", headers: { Origin: single.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email, name: "Single connection consumer", password }) });
      assert.equal(registered.status, 200);
      const created = (await single.database.query<{ id: string; emailVerified: boolean }>('SELECT id,"emailVerified" FROM public.auth_user WHERE email=$1', [email]))[0]!;
      assert.equal(created.emailVerified, false); assert.equal(smtp.messages.length, before + 1);
      const receipt = smtp.messages[before]!.replace(/=\r\n/g, "").replace(/=3D/g, "="), link = receipt.match(/http[^\s<>]+\/api\/auth\/verify-email\?[^\s<>]+/); assert(link);
      assert.equal((await single.fetch(link[0], { redirect: "manual" })).status, 302);
      const client = new NativeClient(single.baseUrl); await client.login(email, password);
      const principal = JSON.parse((await client.request("/api/session", { expected: 200 })).text) as Principal;
      assert.equal(principal.actor.id, created.id); assert.equal(principal.accounts[0]!.role, "owner");
      assert((await single.database.query<{ attempts: number }>("SELECT attempts FROM identity.mail_admission")).every(row => row.attempts === 1));
    } finally { await single.close(); }
  });
  if (!process.argv[2] || process.argv[2] === "--delivery") await scenario("failed invitation delivery retries the original identity and password, verifies its recipient and grants only its current role", async () => {
    const target = await createProductionTestRuntime({ background: false, runtime: { smtp: smtp.smtp, mailBudget: { daily: 20, hourly: 5 } } });
    const password = randomBytes(24).toString("hex"), address = "retained-invite@example.test", before = smtp.messages.length;
    try {
      await target.env.identity.provision({ id: "retry-invite", name: "Retry invitation owner", owner: { email: "retry-owner@example.test", name: "Owned retry operator", password, emailVerified: true } });
      const owner = new NativeClient(target.baseUrl); await owner.login("retry-owner@example.test", password);
      const team = await owner.request("/app/accounts/retry-invite/team", { expected: 200 }), csrf = htmlCsrf(team.text);
      const invite = async (): Promise<PendingNativeInvitation> => {
        const response = await owner.request("/api/accounts/retry-invite/invitations", { json: { username: address, role: "viewer" }, csrf, expected: 201 });
        const token = InvitationReceipt.parse(JSON.parse(response.text)).invitationToken, client = new NativeClient(target.baseUrl), path = `/invite/${token}`;
        const page = await client.request(path, { expected: 200 });
        return { client, path, csrf: htmlCsrf(page.text) };
      };
      const original = await invite();
      const register = (invitation: PendingNativeInvitation, credential: string, expected: number) => invitation.client.request(invitation.path, { form: new URLSearchParams({ csrfToken: invitation.csrf, register: "true", name: "Retained invitation user", password: credential }), expected });
      smtp.rejectRecipients.add(address);
      await register(original, password, 503);
      const retained = (await target.database.query<{ id: string; emailVerified: boolean }>('SELECT id,"emailVerified" FROM public.auth_user WHERE email=$1', [address]))[0]!;
      assert.equal(retained.emailVerified, false); assert.equal((await target.database.query("SELECT account_id FROM identity.members WHERE user_id=$1", [retained.id])).length, 0);
      const retryPage = await original.client.request(original.path, { expected: 200 }); original.csrf = htmlCsrf(retryPage.text);
      const separate = await invite(); await register(separate, randomBytes(24).toString("hex"), 401);
      await register(original, password, 503); assert.equal(smtp.messages.length, before);
      smtp.rejectRecipients.delete(address);
      const resendPage = await original.client.request(original.path, { expected: 200 }); original.csrf = htmlCsrf(resendPage.text);
      await register(original, password, 303); assert.equal(smtp.messages.length, before + 1);
      const receipt = smtp.messages[before]!.replace(/=\r\n/g, "").replace(/=3D/g, "="), link = receipt.match(/http[^\s<>]+\/api\/auth\/verify-email\?[^\s<>]+/); assert(link);
      assert.equal((await target.fetch(link[0], { redirect: "manual" })).status, 302);
      await original.client.login(address, password);
      const session = JSON.parse((await original.client.request("/api/session", { expected: 200 })).text) as Principal; assert.equal(session.actor.id, retained.id);
      const acceptance = await original.client.request(original.path, { expected: 200 });
      await original.client.request(original.path, { form: new URLSearchParams({ csrfToken: htmlCsrf(acceptance.text) }), expected: 303 });
      const joined = JSON.parse((await original.client.request("/api/session", { expected: 200 })).text) as Principal;
      assert.equal(joined.accounts.find(account => account.id === "retry-invite")?.role, "viewer");
      assert.equal((await target.database.query("SELECT id FROM public.auth_user WHERE email=$1", [address])).length, 1);
      assert((await target.database.query<{ attempts: number }>("SELECT attempts FROM identity.mail_admission")).every(row => row.attempts === 3));
    } finally { smtp.rejectRecipients.delete(address); await target.close(); }
  });
  if (process.argv[2] !== "--capacity") await scenario("actual SMTP callback failure is neutral for public recovery but honest for enrollment and native invitations, with isolated concurrent delivery and 20/day 5/hour admission", async () => {
    const isolated = await createProductionTestRuntime({ background: false, runtime: { smtp: smtp.smtp, mailBudget: { daily: 20, hourly: 5 }, legacyMigration: migration } });
    const email = "smtp-reject-owner@example.test", secret = randomBytes(24).toString("hex"), beforeMail = smtp.messages.length;
    try {
      await importLegacyIdentity(isolated.database, { export: originalIdentity, migration, acknowledgeLegacySessionInvalidation: true });
      await isolated.env.identity.provision({ id: "smtp-reject", name: "Owned actual SMTP rejection proof", owner: { email, name: "Owned proof", password: secret, emailVerified: true } });
      const request = (address = email) => isolated.fetch("/api/auth/request-password-reset", { method: "POST", headers: { Origin: isolated.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email: address, redirectTo: `${isolated.baseUrl}/reset-password` }) });
      const legacy = new NativeClient(isolated.baseUrl), proof = await legacy.request("/enroll", { expected: 200 });
      await legacy.request("/enroll", { form: new URLSearchParams({ csrfToken: htmlCsrf(proof.text), username: "stage-original", password: originalPassword }), expected: 303 });
      smtp.rejectDelivery = true;
      const contact = await legacy.request("/enroll/contact", { expected: 200 });
      await legacy.request("/enroll/contact", { form: new URLSearchParams({ csrfToken: htmlCsrf(contact.text), email: "undelivered-contact@example.test" }), expected: 503 });
      const candidate = (await isolated.database.query<{ email: string | null; email_token_hash: string | null; email_sent: boolean }>("SELECT email,email_token_hash,email_sent FROM identity.enrollment_claims"))[0]!; assert.equal(candidate.email, null); assert.equal(candidate.email_token_hash, null); assert.equal(candidate.email_sent, false); assert.equal((await isolated.database.query("SELECT id FROM public.auth_user WHERE id='stage-owner'")).length, 0);
      const rejected = await request(), unknown = await request("never-registered@example.test"); assert.equal(rejected.status, 200); assert.equal(unknown.status, 200); assert.deepEqual(await rejected.json(), await unknown.json()); assert.equal(smtp.messages.length, beforeMail);
      assert.deepEqual([...rejected.headers.keys()], [...unknown.headers.keys()]); assert.equal(rejected.headers.has("set-cookie"), false); assert.equal(unknown.headers.has("set-cookie"), false);
      for (const header of ["content-type", "cache-control", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy"]) assert.equal(rejected.headers.get(header), unknown.headers.get(header), `Neutral recovery header ${header}`);
      const recoveryUi = new NativeClient(isolated.baseUrl), recoveryPage = await recoveryUi.request("/forgot-password", { expected: 200 });
      await recoveryUi.request("/forgot-password", { form: new URLSearchParams({ csrfToken: htmlCsrf(recoveryPage.text), email: "never-registered@example.test" }), expected: 200 });
      assert.equal(smtp.messages.length, beforeMail);
      smtp.rejectDelivery = false;
      const owner = new NativeClient(isolated.baseUrl); await owner.login(email, secret);
      const team = await owner.request("/app/accounts/smtp-reject/team", { expected: 200 }), ownerCsrf = htmlCsrf(team.text);
      const invite = async (address: string) => {
        const created = await owner.request("/api/accounts/smtp-reject/invitations", { json: { username: address, role: "viewer" }, csrf: ownerCsrf, expected: 201 }), token = InvitationReceipt.parse(JSON.parse(created.text)).invitationToken;
        const client = new NativeClient(isolated.baseUrl), path = `/invite/${token}`, page = await client.request(path, { expected: 200 });
        return { client, path, csrfToken: htmlCsrf(page.text) };
      };
      const failed = await invite("native-rejected@example.test"); smtp.rejectRecipients.add("native-rejected@example.test");
      const [nativeFailure, recoveryAccepted] = await Promise.all([
        failed.client.request(failed.path, { form: new URLSearchParams({ csrfToken: failed.csrfToken, register: "true", name: "Native rejected contact", password: secret }), expected: 503 }), request(),
      ]); assert.equal(nativeFailure.response.status, 503); assert.equal(recoveryAccepted.status, 200); assert.equal(smtp.messages.length, beforeMail + 1);
      const successful = await invite("native-accepted@example.test");
      await successful.client.request(successful.path, { form: new URLSearchParams({ csrfToken: successful.csrfToken, register: "true", name: "Native accepted contact", password: secret }), expected: 303 }); assert.equal(smtp.messages.length, beforeMail + 2);
      assert((await isolated.database.query<{ attempts: number }>("SELECT attempts FROM identity.mail_admission")).every(row => row.attempts === 5), "Each actual failed or accepted envelope reserves exactly one conservative slot");
      const fullKnown = await request(), fullUnknown = await request("never-registered@example.test"); assert.equal(fullKnown.status, 503); assert.equal(fullUnknown.status, 503); assert.deepEqual(await fullKnown.json(), await fullUnknown.json());
      assert(smtp.recipientCounts.every(count => count === 1), "Actual auth/enrollment/alert envelopes always have one recipient");
      await smtp.stop();
      const unavailableKnown = await request(), unavailableUnknown = await request("never-registered@example.test"); assert.equal(unavailableKnown.status, 503); assert.equal(unavailableUnknown.status, 503); assert.deepEqual(await unavailableKnown.json(), await unavailableUnknown.json()); assert.equal(smtp.messages.length, beforeMail + 2);
    } finally { smtp.rejectDelivery = false; smtp.rejectRecipients.clear(); await isolated.close(); }
  });
  console.log(`PASS staged operation and mail admission: ${passed} actual PostgreSQL/Node/prober/TLS SMTP scenarios`);
} finally { await runtime.close(); await smtp.close(); }
