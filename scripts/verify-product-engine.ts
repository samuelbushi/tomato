import assert from "node:assert/strict";
import { createProductionTestRuntime, type ProductionTestRuntime } from "./production-test-runtime.ts";
import { runProbe } from "../src/probes.ts";
import { policy } from "../src/validation.ts";
import { executeMessage } from "../src/worker.ts";
import { setTimeout as sleep } from "node:timers/promises";
import { createHmac, randomBytes } from "node:crypto";
import { AccountSecrets } from "../src/account-secrets.ts";
import { importLegacyEngine } from "../src/engine-import.ts";
import type { ClaimedCheck, EngineSnapshot, MonitorInput, MonitorView, NotificationRecord, NotificationView, ProbeResult } from "../src/types.ts";
import type { AvailabilityReport, PublicPageConfig, PublicStatusView, WalletView } from "../src/product-types.ts";

let runtime: ProductionTestRuntime | undefined;
let passed = 0;
function testRuntime(): ProductionTestRuntime { assert(runtime); return runtime; }
async function sql<T = Record<string, unknown>>(account: string, query: string, values: unknown[] = []): Promise<T[]> {
  return testRuntime().database.transaction(account, tx => tx.query<T>(query, values));
}
async function request(account: string, endpoint: string, method = "GET", value?: unknown, extraHeaders: Record<string, string> = {}) {
  return testRuntime().internalFetch(account, endpoint, { method, headers: { "Content-Type": "application/json", ...extraHeaders }, ...(value === undefined ? (method === "POST" ? { body: "{}" } : {}) : { body: JSON.stringify(value) }) });
}
async function ok<T>(account: string, endpoint: string, method = "GET", value?: unknown): Promise<T> {
  const response = await request(account, endpoint, method, value);
  assert(response.ok, `${method} ${endpoint}: ${response.status} ${await response.clone().text()}`);
  return await response.json() as T;
}
async function rejects(account: string, endpoint: string, method: string, value: unknown, status: number): Promise<void> {
  const response = await request(account, endpoint, method, value);
  assert.equal(response.status, status, await response.clone().text());
}
function config(id = "monitor", extra: Partial<MonitorInput> = {}): MonitorInput {
  return { id, name: "Private target name", check: { kind: "http", url: `${testRuntime().fixtures.httpUrl}/private-path`, headers: { Authorization: "Bearer fixture-private-value", "X-Token": "fixture-header-value" } }, intervalMs: 60000, timeoutMs: 500, confirmationDelayMs: 100, executionWindowMs: 30000, ...extra };
}
async function create(account: string, input = config()): Promise<{ monitor: MonitorView; heartbeatToken?: string }> { return ok(account, "/monitors", "POST", input); }
async function state(account: string): Promise<EngineSnapshot> { return ok(account, "/state"); }
async function fund(account: string): Promise<void> { await ok(account, "/credits/initial", "PUT", { credits: 100, reason: "postgres-product-verification" }); }
async function claim(account: string, monitorId?: string): Promise<ClaimedCheck> {
  await ok(account, "/tick", "POST");
  const snapshot = await state(account);
  const job = snapshot.jobs.find(item => item.status === "pending" && item.role === "primary" && (monitorId === undefined || item.monitorId === monitorId)); assert(job);
  const result = await ok<{ claim: ClaimedCheck | null }>(account, "/claim", "POST", { jobId: job.id }); assert(result.claim);
  return result.claim;
}
async function result(claimed: ClaimedCheck, outcome: ProbeResult["outcome"] = "success"): Promise<ProbeResult> {
  assert(claimed.check.kind !== "heartbeat");
  const fixtures = testRuntime().fixtures;
  if (claimed.check.kind === "http") fixtures.set(new URL(claimed.check.url).pathname.slice(1), outcome === "failure" ? "down" : "up");
  const observed = await runProbe(claimed.check, claimed.timeoutMs, policy(testRuntime().env));
  assert.equal(observed.outcome, outcome, "Completion must be backed by a real protocol execution");
  return observed;
}
async function scenario(name: string, run: () => Promise<void>): Promise<void> { await run(); passed++; console.log(`PASS ${name}`); }
async function makeDue(account: string, eventId: string): Promise<void> {
  await sql(account, "UPDATE engine.notifications SET next_due=0,data=jsonb_set(data::jsonb,'{nextAttemptAt}','0')::text WHERE id=$1", [eventId]);
}
async function dueHeartbeat(account: string, id: string, at: number): Promise<void> {
  await sql(account, "UPDATE engine.monitors SET next_due=$1,data=(data::jsonb || jsonb_build_object('nextDueAt',$1::bigint,'heartbeatDeadline',$1::bigint))::text WHERE id=$2", [at, id]);
}

try {
  runtime = await createProductionTestRuntime({ background: false });
  await scenario("Maximum accepted escaped header bytes survive encrypted storage and actual HTTP dispatch", async () => {
    const account = "escaped_headers"; await fund(account);
    const value = '"'.repeat(8191);
    await create(account, config("monitor", { check: { kind: "http", url: `${testRuntime().fixtures.httpUrl}/escaped-headers`, headers: { x: value }, contains: "TOMATOOK" } }));
    await ok(account, "/tick", "POST");
    const scheduled = await state(account);
    const job = scheduled.jobs.find(item => item.status === "pending" && item.role === "primary"); assert(job);
    await executeMessage(testRuntime().env, { kind: "check", accountId: account, jobId: job.id });
    const snapshot = await state(account);
    assert.equal(snapshot.monitors[0]!.state, "UP"); assert.equal(snapshot.usage, 1);
    assert.equal(testRuntime().fixtures.requestHeaders.get("escaped-headers")!.at(-1)!.x, value);
    await rejects(account, "/monitors", "POST", config("oversized", { check: { kind: "http", url: `${testRuntime().fixtures.httpUrl}/oversized-headers`, headers: { x: '"'.repeat(8192) } } }), 400);
    assert.equal((await state(account)).monitors.length, 1);
    await ok(account, "/monitors/monitor/pause", "POST", { revision: snapshot.monitors[0]!.revision });
  });
  await scenario("Maintenance fences live attempts and bulk revision checks roll back atomically", async () => {
    const account = "maintenance"; await fund(account);
    await create(account); await create(account, config("second"));
    const held = await claim(account, "monitor"); const observed = await result(held);
    const from = Date.now();
    const window = await ok<{ maintenance: { id: string } }>(account, "/maintenance", "POST", { monitorId: "monitor", revision: 1, startsAt: from, endsAt: from + 60000, reason: "Controlled fixture maintenance" });
    let snapshot = await state(account);
    assert.equal(snapshot.monitors.find(item => item.id === "monitor")!.state, "MAINTENANCE"); assert.equal(snapshot.reserved, 0);
    assert.equal((await ok<{ accepted: boolean }>(account, "/complete", "POST", { jobId: held.job.id, leaseToken: held.leaseToken, result: observed })).accepted, false);
    await rejects(account, "/maintenance", "POST", { monitorId: "monitor", revision: snapshot.monitors.find(item => item.id === "monitor")!.revision, startsAt: from, endsAt: from + 120000, reason: "Overlap" }, 409);
    const revisions = snapshot.monitors.map(item => ({ id: item.id, revision: item.revision }));
    await rejects(account, "/monitors/bulk", "POST", { action: "pause", monitors: [{ ...revisions[0]! }, { ...revisions[1]!, revision: 999 }] }, 409);
    assert.deepEqual((await state(account)).monitors.map(item => ({ id: item.id, paused: item.paused, revision: item.revision })), snapshot.monitors.map(item => ({ id: item.id, paused: item.paused, revision: item.revision })));
    await sleep(15); const to = Date.now();
    const coverageFrom = (await state(account)).coverage.find(segment => segment.state === "MAINTENANCE")!.startedAt;
    const report = await ok<AvailabilityReport>(account, `/reports?monitorId=monitor&from=${coverageFrom}&to=${to}`);
    assert.equal(report.durationsMs.MAINTENANCE, to - coverageFrom); assert.equal(report.excludedMs, to - coverageFrom); assert.equal(report.observedMs, 0);
    await ok(account, `/maintenance/${window.maintenance.id}`, "DELETE", { revision: (await state(account)).monitors.find(item => item.id === "monitor")!.revision });
    snapshot = await state(account); assert.equal(snapshot.monitors.find(item => item.id === "monitor")!.state, "UNKNOWN");
    await ok(account, "/monitors/bulk", "POST", { action: "pause", monitors: snapshot.monitors.map(item => ({ id: item.id, revision: item.revision })) });
    assert((await state(account)).monitors.every(item => item.paused)); assert.equal((await state(account)).usage, 0);
  });

  await scenario("CRUD revision fencing cancels reserved generation; all views redact headers and leases", async () => {
    const account = "crud"; await fund(account); const created = await create(account);
    assert.equal(created.monitor.name, "Private target name");
    const held = await claim(account); assert.equal((await state(account)).reserved, 1);
    await rejects(account, "/monitors/monitor", "PUT", { revision: 99, name: "Rejected" }, 409);
    const edited = await ok<{ monitor: MonitorView }>(account, "/monitors/monitor", "PUT", { revision: 1, name: "Renamed", headersMode: "keep" });
    assert.equal(edited.monitor.revision, 2); assert.equal(edited.monitor.name, "Renamed");
    assert.equal((await state(account)).reserved, 0);
    assert.equal((await ok<{ accepted: boolean }>(account, "/complete", "POST", { jobId: held.job.id, leaseToken: held.leaseToken, result: await result(held) })).accepted, false);
    const serialized = JSON.stringify(await state(account));
    assert(!serialized.includes("fixture-private-value")); assert(!serialized.includes("fixture-header-value")); assert(!serialized.includes("leaseToken")); assert(!serialized.includes("leaseUntil"));
    const monitor = (await ok<{ monitor: MonitorView }>(account, "/monitors/monitor")).monitor;
    assert(monitor.check.kind === "http"); assert.deepEqual(monitor.check.headerNames, ["authorization", "x-token"]); assert.equal(monitor.check.hasHeaders, true);
    await ok(account, "/monitors/monitor/pause", "POST", { revision: 2 });
    await rejects(account, "/monitors/monitor/resume", "POST", { revision: 2 }, 409);
    await ok(account, "/monitors/monitor/resume", "POST", { revision: 3 });
    await ok(account, "/monitors/monitor/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "monitor")!.revision }); // trusted internal action
  });

  await scenario("Header and webhook keep/replace/remove semantics are durable and secret-safe", async () => {
    const account = "secrets"; await fund(account);
    await create(account, config("monitor", { webhook: { url: testRuntime().fixtures.webhookUrl, secret: "fixture-webhook-secret" } }));
    await ok(account, "/monitors/monitor", "PUT", { revision: 1, check: { kind: "http", url: `${testRuntime().fixtures.httpUrl}/new` }, webhookMode: "keep" });
    let rows = await sql<{ data: string }>(account, "SELECT data FROM engine.monitors WHERE id=$1", ["monitor"]);
    for (const secret of ["fixture-private-value", "fixture-header-value", "fixture-webhook-secret"]) assert(!rows[0]!.data.includes(secret), "Monitor credentials must be encrypted at rest");
    const kept = await claim(account); await ok(account, "/complete", "POST", { jobId: kept.job.id, leaseToken: kept.leaseToken, result: await result(kept) });
    let received = testRuntime().fixtures.requestHeaders.get("new")!.at(-1)!;
    assert.equal(received.authorization, "Bearer fixture-private-value"); assert.equal(received["x-token"], "fixture-header-value");
    await testRuntime().restart();
    await ok(account, "/monitors/monitor", "PUT", { revision: 2, headersMode: "replace", check: { kind: "http", url: `${testRuntime().fixtures.httpUrl}/new`, headers: { "X-New": "fixture-new-secret" } }, webhookMode: "replace", webhook: { url: testRuntime().fixtures.webhookUrl, secret: "fixture-replaced-secret" } });
    rows = await sql<{ data: string }>(account, "SELECT data FROM engine.monitors WHERE id=$1", ["monitor"]);
    assert(!rows[0]!.data.includes("fixture-new-secret")); assert(!rows[0]!.data.includes("fixture-replaced-secret"));
    const replaced = await claim(account); await ok(account, "/complete", "POST", { jobId: replaced.job.id, leaseToken: replaced.leaseToken, result: await result(replaced) });
    received = testRuntime().fixtures.requestHeaders.get("new")!.at(-1)!;
    assert.equal(received["x-new"], "fixture-new-secret"); assert.equal(received.authorization, undefined); assert.equal(received["x-token"], undefined);
    await ok(account, "/monitors/monitor", "PUT", { revision: 3, headersMode: "remove", webhookMode: "remove" });
    const monitor = (await ok<{ monitor: MonitorView }>(account, "/monitors/monitor")).monitor;
    assert(monitor.check.kind === "http"); assert.equal(monitor.check.hasHeaders, false); assert.equal(monitor.webhook, undefined);
    const removed = await claim(account); await ok(account, "/complete", "POST", { jobId: removed.job.id, leaseToken: removed.leaseToken, result: await result(removed) });
    received = testRuntime().fixtures.requestHeaders.get("new")!.at(-1)!;
    assert.equal(received["x-new"], undefined); assert.equal(received.authorization, undefined);
    await ok(account, "/monitors/monitor/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "monitor")!.revision });
  });

  await scenario("Heartbeat rotation returns one token and immediately rejects the old token", async () => {
    const account = "rotation"; await fund(account); const first = await create(account, config("pulse", { check: { kind: "heartbeat" } })); assert(first.heartbeatToken);
    const second = await ok<{ monitor: MonitorView; heartbeatToken: string }>(account, "/monitors/pulse/heartbeat-token", "POST", { revision: 1 }); assert.notEqual(second.heartbeatToken, first.heartbeatToken);
    const old = await request(account, "/monitors/pulse/heartbeat", "POST", undefined, { Authorization: `Bearer ${first.heartbeatToken}`, "Idempotency-Key": "old" }); assert.equal(old.status, 401);
    const fresh = await request(account, "/monitors/pulse/heartbeat", "POST", undefined, { Authorization: `Bearer ${second.heartbeatToken}`, "Idempotency-Key": "new" }); assert.equal(fresh.status, 200);
    const serialized = JSON.stringify(await state(account)); assert(!serialized.includes(second.heartbeatToken)); assert(!serialized.includes("heartbeatTokenHash"));
    await rejects(account, "/monitors/pulse/heartbeat-token", "POST", { revision: 1 }, 409);
    await ok(account, "/monitors/pulse/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "pulse")!.revision });
  });

  await scenario("Deletion retains labeled history, closes coverage without recovery, prevents identifier reuse and rejects late jobs", async () => {
    const account = "deletion"; await fund(account); await create(account, config("monitor", { webhook: { url: "https://example.com/hook", secret: "fixture-webhook-secret" } }));
    const first = await claim(account);
    await ok(account, "/complete", "POST", { jobId: first.job.id, leaseToken: first.leaseToken, result: await result(first) });
    const due = Date.now();
    await sql(account, "UPDATE engine.monitors SET next_due=$1,data=jsonb_set(data::jsonb,'{nextDueAt}',to_jsonb($1::bigint))::text WHERE id=$2", [due, "monitor"]);
    const held = await claim(account);
    const tested = await ok<{ notifications: NotificationView[] }>(account, "/monitors/monitor/notification-test", "POST", { revision: 1 });
    const notification = (await ok<{ notification: NotificationRecord }>(account, "/notifications/claim", "POST", { eventId: tested.notifications[0]!.id })).notification;
    const incident = { id: "fixture-incident", monitorId: "monitor", openedAt: Date.now() - 1000, firstFailureAt: Date.now() - 2000, closedAt: null };
    await sql(account, "INSERT INTO engine.incidents(account_id,id,data) VALUES($1,$2,$3)", [account, incident.id, JSON.stringify(incident)]);
    await ok(account, "/status-page", "PUT", { revision: 0, slug: "deleted", title: "Public service", published: true, components: [{ monitorId: "monitor", label: "Public component" }] });
    await rejects(account, "/monitors/monitor", "DELETE", { revision: 9 }, 409);
    await ok(account, "/monitors/monitor", "DELETE", { revision: 1 });
    assert.equal((await ok<{ accepted: boolean }>(account, "/complete", "POST", { jobId: held.job.id, leaseToken: held.leaseToken, result: await result(held) })).accepted, false);
    assert.equal((await ok<{ accepted: boolean }>(account, "/notifications/complete", "POST", { eventId: notification.id, leaseToken: notification.leaseToken, success: true })).accepted, false);
    const snapshot = await state(account); assert.equal(snapshot.reserved, 0); assert.equal(snapshot.usage, 1); assert.equal(snapshot.monitors.length, 0);
    assert.equal(snapshot.observations[0]!.monitorName, "Private target name"); assert.equal(snapshot.notifications[0]!.status, "failed");
    assert(snapshot.coverage.every(segment => segment.endedAt !== null)); assert.equal(snapshot.incidents[0]!.closedAt, null); assert.equal(snapshot.incidents[0]!.monitorName, "Private target name");
    const page = await ok<PublicStatusView>(account, "/public-status"); assert.equal(page.components.length, 0); assert.equal(page.incidents.length, 0);
    await rejects(account, "/monitors", "POST", config(), 409);
  });

  await scenario("Import is bounded and atomic; secret-omission exports require replacement or removal", async () => {
    const source = "exporter"; await create(source, config("first", { webhook: { url: "https://example.com/hook", secret: "fixture-webhook-secret" } }));
    await ok(source, "/monitors/first/pause", "POST", { revision: (await state(source)).monitors.find(item => item.id === "first")!.revision });
    const exported = await ok<{ version: 1; monitors: Record<string, unknown>[]; secretOmissions: boolean }>(source, "/export"); assert.equal(exported.secretOmissions, true);
    assert.equal(exported.version, 1); assert.equal(exported.monitors[0]!.paused, true);
    assert(!JSON.stringify(exported).includes("fixture-webhook-secret")); assert(!JSON.stringify(exported).includes("fixture-private-value"));
    await rejects("importer", "/monitors/import", "POST", { version: 99, monitors: [config("unsupported")] }, 400); assert.equal((await state("importer")).monitors.length, 0);
    await rejects("importer", "/monitors/import", "POST", { monitors: [config("unversioned")] }, 400); assert.equal((await state("importer")).monitors.length, 0);
    await rejects("importer", "/monitors/import", "POST", { version: 1, monitors: [config("valid"), { ...config("invalid"), intervalMs: 1 }] }, 400); assert.equal((await state("importer")).monitors.length, 0);
    for (const paused of ["true", 1, null]) { await rejects("importer", "/monitors/import", "POST", { version: 1, monitors: [config("valid"), { ...config("invalid"), paused }] }, 400); assert.equal((await state("importer")).monitors.length, 0); }
    await rejects("importer", "/monitors/import", "POST", exported, 400); assert.equal((await state("importer")).monitors.length, 0);
    await rejects("importer", "/monitors/import", "POST", { version: 1, monitors: Array.from({ length: 101 }, (_, index) => config(`m${index}`)) }, 400);
    const imported = await ok<{ importedCount: number }>("importer", "/monitors/import", "POST", { version: 1, monitors: exported.monitors.map(monitor => ({ ...monitor, headersMode: "remove", webhookMode: "remove" })) }); assert.equal(imported.importedCount, 1);
    const paused = (await state("importer")).monitors[0]!; assert.equal(paused.paused, true); assert.equal(paused.state, "PAUSED"); assert.equal(paused.lastObservedAt, null);
    await ok("importer", "/tick", "POST"); const untouched = await state("importer"); assert.equal(untouched.jobs.length, 0); assert.equal(untouched.reserved, 0); assert.equal(untouched.usage, 0); assert.equal(untouched.notifications.length, 0);
    await ok("importer", "/monitors/import", "POST", { version: 1, monitors: [{ ...config("active", { paused: false }), state: "UP", lastObservedAt: Date.now(), incidentId: "foreign", balance: 100000 }] });
    const active = (await state("importer")).monitors.find(monitor => monitor.id === "active")!; assert.equal(active.state, "UNKNOWN"); assert.equal(active.lastObservedAt, null); assert.equal(active.incidentId, null); assert.equal((await state("importer")).balance, 0);
    await ok("importer", "/monitors/active/pause", "POST", { revision: (await state("importer")).monitors.find(item => item.id === "active")!.revision });
  });

  await scenario("Notification tests persist real intents, stop at ten failed attempts and manually retry stable event IDs", async () => {
    const account = "notifications"; await create(account, config("monitor", { webhook: { url: testRuntime().fixtures.webhookUrl, secret: "fixture-webhook-secret" } }));
    testRuntime().fixtures.webhookPlan(Array.from({ length: 10 }, () => "reject"));
    const tested = await ok<{ notifications: NotificationView[] }>(account, "/monitors/monitor/notification-test", "POST", { revision: 1 }); const id = tested.notifications[0]!.id;
    assert.equal(tested.notifications[0]!.type, "test"); assert.equal(tested.notifications[0]!.channel, "webhook");
    for (let attempt = 1; attempt <= 10; attempt++) {
      await makeDue(account, id);
      await executeMessage(testRuntime().env, { kind: "notification", accountId: account, eventId: id });
      const deliveries = await ok<{ notifications: NotificationView[] }>(account, "/notifications");
      assert.equal(deliveries.notifications[0]!.attempts, attempt);
    }
    let deliveries = await ok<{ notifications: NotificationView[] }>(account, "/notifications"); assert.equal(deliveries.notifications[0]!.status, "failed"); assert(deliveries.notifications[0]!.lastError);
    assert.equal(testRuntime().fixtures.receipts.filter(receipt => JSON.parse(receipt.body).id === id).length, 10, "Each persisted failure is a real signed HTTP attempt");
    assert(!JSON.stringify(deliveries).includes("fixture-webhook-secret")); assert(!JSON.stringify(deliveries).includes("leaseToken"));
    assert.equal((await ok<{ notification: null }>(account, "/notifications/claim", "POST", { eventId: id })).notification, null);
    const retried = await ok<{ notification: NotificationView }>(account, "/notifications/retry", "POST", { eventId: id }); assert.equal(retried.notification.id, id); assert.equal(retried.notification.status, "pending");
    testRuntime().fixtures.webhookPlan(["accept"]);
    await executeMessage(testRuntime().env, { kind: "notification", accountId: account, eventId: id });
    deliveries = await ok(account, "/notifications"); assert.equal(deliveries.notifications[0]!.status, "delivered"); assert.equal(deliveries.notifications[0]!.attempts, 11);
    assert(testRuntime().fixtures.acceptedWebhooks.has(id));
    await rejects(account, "/monitors", "POST", config("email", { email: { address: "fixture@example.com" } }), 503);
    await ok(account, "/monitors/monitor/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "monitor")!.revision });
  });

  await scenario("Public projection contains only selected labels and published updates, treats stale UP as UNKNOWN and respects unpublish", async () => {
    const account = "privacy"; await fund(account); await create(account); await create(account, config("hidden"));
    const held = await claim(account); await ok(account, "/complete", "POST", { jobId: held.job.id, leaseToken: held.leaseToken, result: await result(held) });
    const configured = await ok<{ page: PublicPageConfig }>(account, "/status-page", "PUT", { revision: 0, slug: "privacy", title: "Public title", published: true, components: [{ monitorId: "monitor", label: "Service" }] });
    await sql(account, "UPDATE engine.monitors SET data=(data::jsonb || jsonb_build_object('state','UP','lastObservedAt',$1::bigint))::text WHERE id=$2", [Date.now() - 1000000, "monitor"]);
    await sql(account, "INSERT INTO engine.incidents(account_id,id,data) VALUES($1,$2,$3)", [account, "private-owned-incident", JSON.stringify({ id: "private-owned-incident", monitorId: "monitor", openedAt: Date.now() - 2000, firstFailureAt: Date.now() - 3000, closedAt: null })]);
    await rejects(account, "/status-page/updates", "POST", { revision: configured.page.revision, incidentId: "foreign-incident", body: "Not ours" }, 404);
    const updated = await ok<{ page: PublicPageConfig; update: { id: string } }>(account, "/status-page/updates", "POST", { revision: configured.page.revision, incidentId: "private-owned-incident", body: "Plaintext <script> remains text" });
    let page = await ok<PublicStatusView>(account, "/public-status"); assert.deepEqual(page.components.map(component => component.label), ["Service"]); assert.equal(page.components[0]!.state, "UNKNOWN");
    assert.equal(page.incidents[0]!.updates[0]!.body, "Plaintext <script> remains text");
    const serialized = JSON.stringify(page); for (const secret of ["127.0.0.1", "example.com", "Private target name", "private-path", "monitorId", "private-owned-incident", "fixture-private-value", "hidden"]) assert(!serialized.includes(secret), secret);
    await rejects(account, "/status-page/updates", "DELETE", { revision: configured.page.revision, id: updated.update.id }, 409);
    const removed = await ok<{ page: PublicPageConfig }>(account, "/status-page/updates", "DELETE", { revision: updated.page.revision, id: updated.update.id }); page = await ok(account, "/public-status"); assert.equal(page.incidents[0]!.updates.length, 0);
    const unpublished = await ok<{ page: PublicPageConfig }>(account, "/status-page", "PUT", { ...removed.page, published: false }); await rejects(account, "/public-status", "GET", undefined, 404);
    await ok(account, "/status-page", "DELETE", { revision: unpublished.page.revision }); await rejects(account, "/public-status", "GET", undefined, 404);
    await ok(account, "/monitors/monitor/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "monitor")!.revision }); await ok(account, "/monitors/hidden/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "hidden")!.revision });
  });

  await scenario("History/incidents pagination bounds, credit grant metadata and safe audit persistence", async () => {
    const account = "metadata"; await fund(account); await create(account);
    await ok(account, "/audit", "POST", { actor: "fixture-user", action: "pilot:grant-reviewed", subject: "account" });
    const wallet = await ok<WalletView>(account, "/usage"); assert.equal(wallet.creditSource, "hosted-ledger"); assert.equal(wallet.grants[0]!.reason, "postgres-product-verification"); assert(wallet.grants[0]!.createdAt > 0); assert.equal(wallet.available, wallet.balance - wallet.reserved);
    await rejects(account, "/history?limit=101", "GET", undefined, 400); await rejects(account, "/incidents?limit=0", "GET", undefined, 400);
    const audit = await ok<{ entries: { actor: string; action: string }[]; cursor: string | null }>(account, "/audit?limit=1"); assert.equal(audit.entries.length, 1); assert(audit.cursor);
    const next = await ok<{ entries: unknown[] }>(account, `/audit?limit=1&cursor=${audit.cursor}`); assert.equal(next.entries.length, 1);
    const held = await claim(account); await ok(account, "/complete", "POST", { jobId: held.job.id, leaseToken: held.leaseToken, result: await result(held) });
    const filtered = await ok<{ observations: unknown[] }>(account, "/history?monitorId=not-selected"); assert.equal(filtered.observations.length, 0);
    await ok(account, "/monitors/monitor/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "monitor")!.revision });
  });
  await scenario("Stale outbound DOWN is UNKNOWN without closing incident; genuine overdue heartbeat DOWN remains authoritative", async () => {
    const outbound = "stale-down"; await create(outbound);
    await sql(outbound, "UPDATE engine.monitors SET data=(data::jsonb || jsonb_build_object('state','DOWN','lastObservedAt',$1::bigint,'incidentId',$2::text))::text WHERE id=$3", [Date.now() - 1000000, "open-stale-incident", "monitor"]);
    await sql(outbound, "INSERT INTO engine.incidents(account_id,id,data) VALUES($1,$2,$3)", [outbound, "open-stale-incident", JSON.stringify({ id: "open-stale-incident", monitorId: "monitor", openedAt: Date.now() - 1000000, firstFailureAt: Date.now() - 1000001, closedAt: null })]);
    const monitor = (await ok<{ monitor: MonitorView }>(outbound, "/monitors/monitor")).monitor;
    assert.equal(monitor.state, "DOWN"); assert.equal(monitor.effectiveState, "UNKNOWN"); assert.equal((await state(outbound)).incidents[0]!.closedAt, null);
    await ok(outbound, "/status-page", "PUT", { revision: 0, slug: "stale-down", title: "Service", published: true, components: [{ monitorId: "monitor", label: "Service" }] });
    assert.equal((await ok<PublicStatusView>(outbound, "/public-status")).components[0]!.state, "UNKNOWN");
    await ok(outbound, "/monitors/monitor/pause", "POST", { revision: (await state(outbound)).monitors.find(item => item.id === "monitor")!.revision });

    const heartbeat = "overdue-heartbeat"; await create(heartbeat, config("pulse", { check: { kind: "heartbeat" } }));
    const deadline = Date.now() - 50;
    await dueHeartbeat(heartbeat, "pulse", deadline);
    await ok(heartbeat, "/tick", "POST");
    const pulse = (await ok<{ monitor: MonitorView }>(heartbeat, "/monitors/pulse")).monitor;
    assert.equal(pulse.state, "DOWN"); assert.equal(pulse.effectiveState, "DOWN"); assert.equal(pulse.freshUntil, null);
    await ok(heartbeat, "/status-page", "PUT", { revision: 0, slug: "overdue-heartbeat", title: "Heartbeat", published: true, components: [{ monitorId: "pulse", label: "Pulse" }] });
    assert.equal((await ok<PublicStatusView>(heartbeat, "/public-status")).components[0]!.state, "DOWN");
    const expired = Date.now() - pulse.executionWindowMs - 100;
    await dueHeartbeat(heartbeat, "pulse", expired);
    await ok(heartbeat, "/tick", "POST");
    assert.equal((await ok<PublicStatusView>(heartbeat, "/public-status")).components[0]!.state, "DOWN"); assert.equal((await state(heartbeat)).incidents[0]!.closedAt, null);
    await ok(heartbeat, "/monitors/pulse/pause", "POST", { revision: (await state(heartbeat)).monitors.find(item => item.id === "pulse")!.revision });
  });
  await scenario("Detected heartbeat DOWN survives unfunded and duplicate pulses plus late repair; funded acceptance alone recovers", async () => {
    const account = "heartbeat-evidence";
    await ok(account, "/credits/initial", "PUT", { credits: 1 });
    const created = await create(account, config("pulse", { check: { kind: "heartbeat" } })); assert(created.heartbeatToken);
    const headers = { Authorization: `Bearer ${created.heartbeatToken}`, "Idempotency-Key": "first" };
    assert.equal((await request(account, "/monitors/pulse/heartbeat", "POST", undefined, headers)).status, 200);
    const deadline = Date.now() - 10;
    await dueHeartbeat(account, "pulse", deadline);
    await ok(account, "/tick", "POST");
    let snapshot = await state(account);
    assert.equal(snapshot.monitors[0]!.state, "DOWN");
    const from = snapshot.coverage.find(segment => segment.state === "DOWN")!.startedAt;
    await sleep(25); const to = Date.now();
    const route = `/reports?monitorId=pulse&from=${from}&to=${to}`;
    const original = await ok<AvailabilityReport>(account, route);
    assert.equal(original.durationsMs.DOWN, to - from); assert.equal(original.uptimeRatio, 0); assert.equal(original.coverageRatio, 1);
    const unfunded = await request(account, "/monitors/pulse/heartbeat", "POST", undefined, { ...headers, "Idempotency-Key": "unfunded" });
    assert.equal(unfunded.status, 402); assert.deepEqual(await unfunded.json(), { error: "insufficient_credits" });
    const duplicate = await request(account, "/monitors/pulse/heartbeat", "POST", undefined, headers);
    assert.deepEqual(await duplicate.json(), { accepted: false, duplicate: true, state: "DOWN" });
    const late = Date.now() - created.monitor.executionWindowMs - 100;
    await dueHeartbeat(account, "pulse", late);
    await ok(account, "/tick", "POST");
    snapshot = await state(account);
    assert.equal(snapshot.monitors[0]!.state, "DOWN"); assert.equal(snapshot.monitors[0]!.effectiveState, "DOWN");
    assert.equal(snapshot.incidents[0]!.closedAt, null);
    assert.equal(snapshot.balance, 0); assert.equal(snapshot.usage, 1); assert.equal(snapshot.reserved, 0); assert.equal(snapshot.missedSlots, 0);
    let wallet = await ok<WalletView>(account, "/usage"); assert.equal(wallet.heartbeatReceipts, 1); assert.equal(wallet.heartbeatCreditsUsed, 1);
    await ok(account, "/credits/recovery", "PUT", { credits: 1 });
    const recovered = await request(account, "/monitors/pulse/heartbeat", "POST", undefined, { ...headers, "Idempotency-Key": "recovery" });
    assert.deepEqual(await recovered.json(), { accepted: true, duplicate: false, state: "UP" });
    snapshot = await state(account); assert(snapshot.incidents[0]!.closedAt !== null); assert.equal(snapshot.usage, 2); assert.equal(snapshot.balance, 0);
    wallet = await ok<WalletView>(account, "/usage"); assert.equal(wallet.heartbeatReceipts, 2); assert.equal(wallet.heartbeatCreditsUsed, 2);
    await ok(account, "/monitors/pulse", "PUT", { revision: snapshot.monitors[0]!.revision, check: { kind: "http", url: "https://example.com" } });
    const edited = await ok<AvailabilityReport>(account, route);
    assert.deepEqual(edited.durationsMs, original.durationsMs); assert.equal(edited.observedMs, original.observedMs);
    assert.equal(edited.coverageRatio, original.coverageRatio); assert.equal(edited.uptimeRatio, original.uptimeRatio);
    await ok(account, "/monitors/pulse/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "pulse")!.revision });

    const transitioned = "heartbeat-transition";
    const unfundedMonitor = await create(transitioned, config("pulse", { check: { kind: "heartbeat" } })); assert(unfundedMonitor.heartbeatToken);
    const due = Date.now() - 10;
    await dueHeartbeat(transitioned, "pulse", due);
    await ok(transitioned, "/tick", "POST"); assert.equal((await state(transitioned)).monitors[0]!.state, "DOWN");
    await ok(transitioned, "/monitors/pulse/pause", "POST", { revision: (await state(transitioned)).monitors.find(item => item.id === "pulse")!.revision }); await ok(transitioned, "/monitors/pulse/resume", "POST", { revision: (await state(transitioned)).monitors.find(item => item.id === "pulse")!.revision });
    const refused = await request(transitioned, "/monitors/pulse/heartbeat", "POST", undefined, { Authorization: `Bearer ${unfundedMonitor.heartbeatToken}`, "Idempotency-Key": "blocked" });
    assert.equal(refused.status, 402);
    const overdue = Date.now() - 10;
    await dueHeartbeat(transitioned, "pulse", overdue);
    await ok(transitioned, "/tick", "POST");
    const unknown = await state(transitioned); assert.equal(unknown.monitors[0]!.state, "UNKNOWN"); assert.equal(unknown.incidents[0]!.closedAt, null);
    assert.equal(unknown.usage, 0); assert.equal((await ok<WalletView>(transitioned, "/usage")).heartbeatReceipts, 0);
    await ok(transitioned, "/monitors/pulse/pause", "POST", { revision: (await state(transitioned)).monitors.find(item => item.id === "pulse")!.revision });
  });
  await scenario("Historical stale outbound DOWN never gains heartbeat deadline coverage after protocol edits", async () => {
    const account = "outbound-report"; await fund(account);
    await create(account, config("monitor"));
    const primary = await claim(account);
    await ok(account, "/complete", "POST", { jobId: primary.job.id, leaseToken: primary.leaseToken, result: await result(primary, "failure") });
    await sleep(125);
    const pending = (await state(account)).jobs.find(job => job.role === "confirmation" && job.status === "pending"); assert(pending);
    const confirmation = (await ok<{ claim: ClaimedCheck | null }>(account, "/claim", "POST", { jobId: pending.id })).claim; assert(confirmation);
    await ok(account, "/complete", "POST", { jobId: confirmation.job.id, leaseToken: confirmation.leaseToken, result: await result(confirmation, "failure") });
    const down = await state(account); assert.equal(down.monitors[0]!.state, "DOWN");
    await sql(account, "UPDATE engine.freshness SET fresh_until=observed_at+5 WHERE monitor_id=$1", ["monitor"]);
    const from = down.coverage.find(segment => segment.state === "DOWN")!.startedAt + 10;
    await sleep(35); const to = Date.now();
    const route = `/reports?monitorId=monitor&from=${from}&to=${to}`;
    const original = await ok<AvailabilityReport>(account, route);
    assert.equal(original.durationsMs.UNKNOWN, to - from); assert.equal(original.durationsMs.DOWN, 0); assert.equal(original.coverageRatio, 0); assert.equal(original.uptimeRatio, null);
    const heartbeat = await ok<{ monitor: MonitorView }>(account, "/monitors/monitor", "PUT", { revision: down.monitors[0]!.revision, check: { kind: "heartbeat" } });
    const edited = await ok<AvailabilityReport>(account, route);
    assert.deepEqual(edited.durationsMs, original.durationsMs); assert.equal(edited.observedMs, original.observedMs);
    assert.equal(edited.coverageRatio, 0); assert.equal(edited.uptimeRatio, null);
    const due = Date.now() - 10;
    await dueHeartbeat(account, "monitor", due);
    await ok(account, "/tick", "POST"); assert.equal((await state(account)).monitors[0]!.state, "DOWN");
    const duringHeartbeat = await ok<AvailabilityReport>(account, route); assert.deepEqual(duringHeartbeat.durationsMs, original.durationsMs);
    await ok(account, "/monitors/monitor", "PUT", { revision: heartbeat.monitor.revision, check: { kind: "http", url: "https://example.com" } });
    assert.deepEqual((await ok<AvailabilityReport>(account, route)).durationsMs, original.durationsMs);
    await ok(account, "/monitors/monitor/pause", "POST", { revision: (await state(account)).monitors.find(item => item.id === "monitor")!.revision });
  });
  await scenario("Legacy unknown coverage remains conservative after restart and protocol edits", async () => {
    const account = "legacy-unknown"; await create(account, config("monitor", { paused: true }));
    const from = Date.now() - 10000, to = from + 1000;
    await sql(account, "INSERT INTO engine.coverage(account_id,monitor_id,started_at,ended_at,state,evidence_mode) VALUES($1,$2,$3,$4,$5,$6)", [account, "monitor", from, to, "DOWN", "legacy"]);
    await testRuntime().restart();
    const conservative = await ok<AvailabilityReport>(account, `/reports?monitorId=monitor&from=${from}&to=${to}`);
    assert.equal(conservative.durationsMs.DOWN, 0); assert.equal(conservative.durationsMs.UNKNOWN, 1000);
    assert.equal(conservative.coverageRatio, 0); assert.equal(conservative.uptimeRatio, null); assert.equal(conservative.legacyCoverageMs, 1000);
    await ok(account, "/monitors/monitor", "PUT", { revision: 1, check: { kind: "heartbeat" } });
    const edited = await ok<AvailabilityReport>(account, `/reports?monitorId=monitor&from=${from}&to=${to}`);
    assert.deepEqual(edited.durationsMs, conservative.durationsMs); assert.equal(edited.legacyCoverageMs, 1000);
  });
  await scenario("Persisted cumulative heartbeat usage survives token rotation, deletion, new pulses and another restart", async () => {
    const accounts = ["legacy-pulse-rotate", "legacy-pulse-delete"];
    for (const account of accounts) {
      await ok(account, "/credits/initial", "PUT", { credits: 3 });
      const created = await create(account, config("pulse", { check: { kind: "heartbeat" } })); assert(created.heartbeatToken);
      const accepted = await request(account, "/monitors/pulse/heartbeat", "POST", undefined, { Authorization: `Bearer ${created.heartbeatToken}`, "Idempotency-Key": "known-legacy-pulse" });
      assert.equal(accepted.status, 200); assert.equal((await accepted.json() as { accepted: boolean }).accepted, true);
      const before = await ok<WalletView>(account, "/usage"); assert.equal(before.usage, 1); assert.equal(before.heartbeatCreditsUsed, 1); assert.equal(before.heartbeatReceipts, 1);
    }
    const lost = "legacy-pulse-lost";
    await ok(lost, "/credits/initial", "PUT", { credits: 2 });
    const old = await create(lost, config("pulse", { check: { kind: "heartbeat" } })); assert(old.heartbeatToken);
    assert.equal((await request(lost, "/monitors/pulse/heartbeat", "POST", undefined, { Authorization: `Bearer ${old.heartbeatToken}`, "Idempotency-Key": "already-lost-pulse" })).status, 200);
    await ok(lost, "/monitors/pulse/heartbeat-token", "POST", { revision: 1 });
    await testRuntime().restart();
    for (const account of accounts) {
      const migrated = await ok<WalletView>(account, "/usage"); assert.equal(migrated.usage, 1); assert.equal(migrated.heartbeatCreditsUsed, 1); assert.equal(migrated.heartbeatReceipts, 1);
      let id: string, token: string;
      if (account === accounts[0]) {
        const rotated = await ok<{ heartbeatToken: string }>(account, "/monitors/pulse/heartbeat-token", "POST", { revision: 1 });
        id = "pulse"; token = rotated.heartbeatToken;
      } else {
        await ok(account, "/monitors/pulse", "DELETE", { revision: 1 });
        const created = await create(account, config("next", { check: { kind: "heartbeat" } })); assert(created.heartbeatToken);
        id = "next"; token = created.heartbeatToken;
      }
      const cleared = await ok<WalletView>(account, "/usage");
      assert.equal(cleared.usage, 1); assert.equal(cleared.heartbeatCreditsUsed, 1); assert.equal(cleared.heartbeatReceipts, 0); assert.equal(cleared.balance, 2);
      const headers = { Authorization: `Bearer ${token}`, "Idempotency-Key": "new-accepted-pulse" };
      const accepted = await request(account, `/monitors/${id}/heartbeat`, "POST", undefined, headers);
      assert.equal(accepted.status, 200); assert.equal((await accepted.json() as { accepted: boolean }).accepted, true);
      const duplicate = await request(account, `/monitors/${id}/heartbeat`, "POST", undefined, headers);
      assert.equal(duplicate.status, 200); assert.equal((await duplicate.json() as { duplicate: boolean }).duplicate, true);
      const after = await ok<WalletView>(account, "/usage");
      assert.equal(after.usage, 2); assert.equal(after.heartbeatCreditsUsed, 2); assert.equal(after.heartbeatReceipts, 1); assert.equal(after.balance, 1); assert.equal(after.reserved, 0);
    }
    const rotatedReceipts = await ok<WalletView>(lost, "/usage");
    assert.equal(rotatedReceipts.usage, 1); assert.equal(rotatedReceipts.balance, 1);
    assert.equal(rotatedReceipts.heartbeatCreditsUsed, 1); assert.equal(rotatedReceipts.heartbeatReceipts, 0);
    await testRuntime().restart();
    for (const account of accounts) {
      const retained = await ok<WalletView>(account, "/usage"); assert.equal(retained.heartbeatCreditsUsed, 2); assert.equal(retained.heartbeatReceipts, 1); assert.equal(retained.usage, 2);
    }
  });
  await scenario("Approved offline engine import restores actual protocols, secrets, reservations, cursors and archive bytes atomically", async () => {
    const source = testRuntime(), account = "offline_restore";
    const webhookSecret = randomBytes(32).toString("hex"), headerSecret = randomBytes(24).toString("hex");
    const owner = { email: "offline-owner@example.com", name: "Offline owner", password: randomBytes(24).toString("hex"), emailVerified: true };
    await source.env.identity.provision({ id: account, name: "Preserved identity account", owner });
    await fund(account);
    await create(account, config("monitor", { check: { kind: "http", url: `${source.fixtures.httpUrl}/offline-restored`, headers: { Authorization: `Bearer ${headerSecret}` }, contains: "TOMATOOK" }, webhook: { url: source.fixtures.webhookUrl, secret: webhookSecret } }));
    const pulse = await create(account, config("pulse", { check: { kind: "heartbeat" } })); assert(pulse.heartbeatToken);
    const first = await claim(account);
    await ok(account, "/complete", "POST", { jobId: first.job.id, leaseToken: first.leaseToken, result: await result(first) });
    assert.equal((await request(account, "/monitors/pulse/heartbeat", "POST", undefined, { Authorization: `Bearer ${pulse.heartbeatToken}`, "Idempotency-Key": "preserved-pulse" })).status, 200);
    await executeMessage(source.env, { kind: "archive", accountId: account });
    await sql(account, "UPDATE engine.monitors SET next_due=$1,data=jsonb_set(data::jsonb,'{nextDueAt}',to_jsonb($1::bigint))::text WHERE id=$2", [Date.now(), "monitor"]);
    const held = await claim(account);
    const tested = await ok<{ notifications: NotificationView[] }>(account, "/monitors/monitor/notification-test", "POST", { revision: 1 });
    const sending = await ok<{ notification: NotificationRecord }>(account, "/notifications/claim", "POST", { eventId: tested.notifications[0]!.id });
    assert(sending.notification.leaseToken);
    const before = await state(account); assert.equal(before.usage, 2); assert.equal(before.reserved, 1);
    const columns: Record<string, string[]> = {
      metadata: ["key", "value"], wallet: ["id", "balance", "reserved", "usage", "missed", "archive_sequence"],
      deposits: ["id", "credits"], monitors: ["id", "next_due", "paused", "data"],
      jobs: ["id", "monitor_id", "status", "expires_at", "scheduled_at", "data"],
      observations: ["id", "observed_at", "archived", "data", "cursor AS rowid"], incidents: ["id", "data", "cursor AS rowid"],
      notifications: ["id", "status", "next_due", "data", "cursor AS rowid"], pulses: ["monitor_id", "pulse_id", "received_at"],
      coverage: ["monitor_id", "started_at", "ended_at", "state", "evidence_mode", "cursor AS rowid"],
      outbox: ["id", "next_due", "message"], retired_monitors: ["id", "name", "deleted_at"], grants: ["id", "reason", "created_at"],
      audit: ["id", "data", "cursor AS rowid"], maintenance: ["id", "monitor_id", "starts_at", "ends_at", "data"],
      freshness: ["monitor_id", "observed_at", "fresh_until"],
    };
    const exported = await source.database.transaction(account, async tx => {
      const tables: Record<string, Record<string, unknown>[]> = {};
      const secrets = new AccountSecrets(source.env.DATA_KEY, account);
      for (const [table, fields] of Object.entries(columns)) {
        const rows = await tx.query<Record<string, unknown>>(`SELECT ${fields.join(",")} FROM engine.${table}`);
        for (const row of rows) {
          if (table === "monitors") { assert.equal(typeof row.data, "string"); row.data = JSON.stringify(secrets.decodeMonitor(String(row.data))); }
          if (table === "notifications") { assert.equal(typeof row.data, "string"); row.data = JSON.stringify(secrets.decodeNotification(String(row.data))); }
          if (table === "metadata" && row.key === "notification-defaults") row.value = JSON.stringify(secrets.decodeDefaults(String(row.value)));
        }
        tables[table] = rows;
      }
      const archives = await tx.query<{ id: string; payload: Buffer; created_at: number }>("SELECT id,payload,created_at FROM engine.archives ORDER BY id");
      assert(archives.length > 0);
      return { version: 1, kind: "tomato-engine-export", mode: "hosted", accounts: [{ accountId: account, tables, archives: archives.map(row => ({ id: row.id, payloadBase64: row.payload.toString("base64"), createdAt: row.created_at })) }] };
    });
    const target = await createProductionTestRuntime({ background: false, fixtures: source.fixtures });
    try {
      const preserved = await target.env.identity.provision({ id: account, name: "Preserved identity account", owner });
      const call = async <T>(endpoint: string, method = "GET", value?: unknown): Promise<T> => {
        const response = await target.internalFetch(account, endpoint, { method, headers: { "Content-Type": "application/json" }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
        assert(response.ok, await response.clone().text()); return await response.json() as T;
      };
      await assert.rejects(importLegacyEngine(target.database, exported, target.env.DATA_KEY, false), /empty_target_confirmation_required/);
      const missingCounter = structuredClone(exported);
      missingCounter.accounts[0]!.tables.metadata = missingCounter.accounts[0]!.tables.metadata!.filter(row => row.key !== "heartbeat-usage");
      await assert.rejects(importLegacyEngine(target.database, missingCounter, target.env.DATA_KEY, true), /provable_cumulative_heartbeat_usage_required/);
      await target.database.transaction(account, async tx => {
        for (const table of Object.keys(columns)) assert.equal((await tx.query(`SELECT 1 FROM engine.${table} LIMIT 1`)).length, 0, "An unprovable cumulative counter rejects the import without guessing or leaving partial rows");
      });
      const imported = await importLegacyEngine(target.database, exported, target.env.DATA_KEY, true);
      assert.equal(imported.accounts, 1); assert.equal(imported.archives, exported.accounts[0]!.archives.length);
      const restored = await call<EngineSnapshot>("/state");
      assert.equal(restored.usage, before.usage); assert.equal(restored.balance, before.balance); assert.equal(restored.reserved, before.reserved);
      assert.deepEqual(restored.observations, before.observations); assert.deepEqual(restored.coverage, before.coverage);
      const history = await call<{ observations: unknown[]; cursor: string | null }>("/history?limit=1");
      assert.equal(history.observations.length, 1);
      await target.database.transaction(account, async tx => {
        const importedRows = await tx.query<{ id: string; rowid: number }>("SELECT id,cursor AS rowid FROM engine.observations ORDER BY cursor");
        assert.deepEqual(importedRows, exported.accounts[0]!.tables.observations!.map(row => ({ id: row.id, rowid: row.rowid })).sort((a, b) => Number(a.rowid) - Number(b.rowid)));
        const chunks = await tx.query<{ id: string; payload: Buffer }>("SELECT id,payload FROM engine.archives ORDER BY id");
        assert.deepEqual(chunks.map(row => ({ id: row.id, payloadBase64: row.payload.toString("base64") })), exported.accounts[0]!.archives.map(row => ({ id: row.id, payloadBase64: row.payloadBase64 })));
        const monitors = await tx.query<{ data: string }>("SELECT data FROM engine.monitors");
        assert(monitors.every(row => !row.data.includes(headerSecret) && !row.data.includes(webhookSecret)));
      });
      const stale = await call<{ accepted: boolean }>("/complete", "POST", { jobId: held.job.id, leaseToken: held.leaseToken, result: await result(held) });
      assert.equal(stale.accepted, false, "Legacy execution tokens cannot own restored attempts");
      await executeMessage(target.env, { kind: "check", accountId: account, jobId: held.job.id });
      const completed = await call<EngineSnapshot>("/state");
      assert.equal(completed.usage, 3); assert.equal(completed.reserved, 0); assert.equal(completed.balance, before.balance - 1);
      assert.equal(source.fixtures.requestHeaders.get("offline-restored")!.at(-1)!.authorization, `Bearer ${headerSecret}`);
      const duplicate = await target.internalFetch(account, "/monitors/pulse/heartbeat", { method: "POST", headers: { Authorization: `Bearer ${pulse.heartbeatToken}`, "Idempotency-Key": "preserved-pulse" } });
      const duplicateBody: unknown = await duplicate.json();
      assert(duplicateBody && typeof duplicateBody === "object" && "duplicate" in duplicateBody && duplicateBody.duplicate === true);
      assert.equal((await call<EngineSnapshot>("/state")).usage, 3);
      source.fixtures.webhookPlan(["accept"]);
      await executeMessage(target.env, { kind: "notification", accountId: account, eventId: sending.notification.id });
      const receipt = source.fixtures.receipts.find(item => JSON.parse(item.body).id === sending.notification.id); assert(receipt);
      assert.equal(receipt.headers["idempotency-key"], sending.notification.id);
      assert.equal(receipt.headers["x-tomato-signature"], createHmac("sha256", webhookSecret).update(`${receipt.headers["x-tomato-timestamp"]}.${receipt.body}`).digest("hex"));
      const delivered = await call<EngineSnapshot>("/state"); assert.equal(delivered.notifications.find(item => item.id === sending.notification.id)!.status, "delivered");
      await assert.rejects(importLegacyEngine(target.database, exported, target.env.DATA_KEY, true), /engine_import_target_not_empty/);
      assert.equal((await call<EngineSnapshot>("/state")).usage, delivered.usage);
      const ownerRows = await target.database.query<{ id: string }>("SELECT id FROM public.auth_user WHERE id=$1", [preserved.owner.id]); assert.equal(ownerRows.length, 1);
      const rollbackAccounts = ["rollback_a", "rollback_b"];
      for (const id of rollbackAccounts) await target.env.identity.provision({ id, name: id, owner: { ...owner, email: `${id}@example.com` } });
      const cloneAccount = (id: string) => {
        const tables = structuredClone(exported.accounts[0]!.tables);
        tables.metadata = tables.metadata!.map(row => row.key === "account" ? { ...row, value: id } : row);
        return { accountId: id, tables, archives: [] };
      };
      const valid = cloneAccount(rollbackAccounts[0]!), invalid = cloneAccount(rollbackAccounts[1]!); invalid.tables.wallet = [];
      await assert.rejects(importLegacyEngine(target.database, { ...exported, accounts: [valid, invalid] }, target.env.DATA_KEY, true), /complete_wallet_required/);
      for (const id of rollbackAccounts) await target.database.transaction(id, async tx => {
        for (const table of Object.keys(columns)) assert.equal((await tx.query(`SELECT 1 FROM engine.${table} LIMIT 1`)).length, 0, "A later account failure rolls back every earlier imported row");
      });
      await target.restart();
      const afterRestart = await call<EngineSnapshot>("/state"); assert.equal(afterRestart.usage, 3); assert.equal(afterRestart.reserved, 0);
      await executeMessage(target.env, { kind: "check", accountId: account, jobId: held.job.id });
      assert.equal((await call<EngineSnapshot>("/state")).usage, 3);
    } finally { await target.close(); }
  });
  console.log(`PASS product engine verification: ${passed} real Node/PostgreSQL scenarios`);
} catch (error) { console.error(error); process.exitCode = 1; }
finally { await runtime?.close(); }
