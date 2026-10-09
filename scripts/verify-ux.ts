import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { NativeClient, htmlCsrf } from "./local-client.ts";
import { createProductionTestRuntime, type ProductionTestRuntime } from "./production-test-runtime.ts";
import type { AvailabilityReport, DeliveryView, DisplayMonitor, MaintenanceWindow } from "../src/product-types.ts";

const password = randomBytes(24).toString("hex");
let service: ProductionTestRuntime | undefined;
try {
  service = await createProductionTestRuntime();
  const provision = await service.fetch("/api/operator/accounts", { method: "POST", headers: { Authorization: `Bearer ${service.token}`, "Content-Type": "application/json" }, body: JSON.stringify({ id: "ux", name: "Native UX", owner: { email: "ux-owner@example.test", name: "UX fixture", password, emailVerified: true }, testingCredits: 10000 }) });
  assert.equal(provision.status, 201);
  const client = new NativeClient(service.baseUrl);
  await client.login("ux-owner@example.test", password);
  const base = "/app/accounts/ux", api = "/api/accounts/ux";
  const form = (values: Record<string, string>): URLSearchParams => new URLSearchParams(values);
  async function json<T>(route: string): Promise<T> { return JSON.parse((await client.request(route, { expected: 200 })).text) as T; }
  async function submit(route: string, values: Record<string, string>, expected = 303) {
    const page = await client.request(route === `${base}/new-monitor` ? route : base, { expected: 200 });
    return client.request(route, { form: form({ csrfToken: htmlCsrf(page.text), ...values }), expected });
  }
  async function monitor(id: string): Promise<DisplayMonitor> { return (await json<{ monitor: DisplayMonitor }>(`${api}/monitors/${id}`)).monitor; }
  async function until<T>(read: () => Promise<T>, done: (value: T) => boolean): Promise<T> {
    const deadline = Date.now() + 30000;
    while (true) {
      const value = await read();
      if (done(value)) return value;
      if (Date.now() >= deadline) throw new Error("The real local runtime did not produce the expected evidence within 30 seconds.");
      await sleep(150);
    }
  }
  const dashboard = await client.request(base, { expected: 200 });
  assert.equal(dashboard.response.headers.get("Referrer-Policy"), "strict-origin");
  assert.equal(dashboard.response.headers.get("Cache-Control"), "no-store");
  const quick = await submit(`${base}/new-monitor`, { kind: "http", url: `${service.fixtures.httpUrl}/first-native` });
  const location = quick.response.headers.get("Location")!;
  const id = location.split("/").at(-1)!;
  let first = await monitor(id);
  assert.equal(first.intervalMs, 60000); assert.equal(first.timeoutMs, 5000);
  assert.equal(first.check.kind, "http");
  const initialReport = await json<AvailabilityReport>(`${api}/reports?monitorId=${id}`);
  const preciseTo = Math.min(initialReport.to, initialReport.from + 1);
  assert(preciseTo > initialReport.from, "Fresh retained report must contain a real nonempty window");
  const precisePage = await client.request(`${base}/reports?monitorId=${id}&from=${initialReport.from}&to=${preciseTo}`, { expected: 200 });
  const reportBounds = (html: string): { from: string; to: string } => {
    const from = html.match(/<input\b[^>]*name="from"[^>]*value="([^"]+)"/)?.[1];
    const to = html.match(/<input\b[^>]*name="to"[^>]*value="([^"]+)"/)?.[1];
    assert(from && to, "Rendered native report form must retain both bounds");
    return { from, to };
  };
  const renderedBounds = reportBounds(precisePage.text);
  assert.equal(Date.parse(`${renderedBounds.from}Z`), initialReport.from, "Native report From must not discard retained milliseconds");
  assert.equal(Date.parse(`${renderedBounds.to}Z`), preciseTo, "Native report To must preserve the actual sub-second window");
  const unchangedRange = new URLSearchParams({ monitorId: id, ...renderedBounds });
  const unchangedPage = await client.request(`${base}/reports?${unchangedRange}`, { expected: 200 });
  assert.deepEqual(reportBounds(unchangedPage.text), renderedBounds, "Unchanged native submission must preserve the same displayed window");
  console.log("PASS native report resubmission preserves an actual one-millisecond fresh-monitor window");
  first = await until(() => monitor(id), value => value.effectiveState === "UP" && value.lastObservedAt !== null);
  assert(service.fixtures.hits.get("first-native"));
  console.log("PASS URL-only native creation generates identity/defaults and obtains actual controlled HTTP evidence");

  const cadenceBefore = first.nextDueAt, observedBefore = first.lastObservedAt!, hitsBefore = service.fixtures.hits.get("first-native")!;
  const usageBefore = await json<{ usage: number }>(`${api}/usage`);
  await submit(`${base}/monitors/${id}/check-now`, { revision: String(first.revision) });
  first = await until(() => monitor(id), value => value.lastObservedAt !== null && value.lastObservedAt > observedBefore);
  assert.equal(first.effectiveState, "UP"); assert.equal(first.nextDueAt, cadenceBefore);
  const usageAfter = await json<{ usage: number }>(`${api}/usage`);
  assert.equal(usageAfter.usage - usageBefore.usage, 1);
  assert.equal(service.fixtures.hits.get("first-native")! - hitsBefore, 1);
  console.log("PASS native Check now queues exactly one observed primary and one credit without shifting ordinary cadence");

  const secret = randomBytes(24).toString("hex");
  const settings = await client.request(`${base}/settings`, { expected: 200 });
  const defaults = await json<{ defaults: { revision: number } }>(`${api}/notification-defaults`);
  await client.request(`${base}/settings/notification-defaults`, { form: form({ csrfToken: htmlCsrf(settings.text), revision: String(defaults.defaults.revision), webhookMode: "replace", webhookUrl: service.fixtures.webhookUrl, webhookSecret: secret, emailMode: "remove" }), expected: 303 });
  const alertCreate = await submit(`${base}/new-monitor`, { kind: "http", url: `${service.fixtures.httpUrl}/alerts-native`, useNotificationDefaults: "true" });
  const alertId = alertCreate.response.headers.get("Location")!.split("/").at(-1)!;
  let alertMonitor = await monitor(alertId);
  assert.equal(alertMonitor.webhook?.url, service.fixtures.webhookUrl);
  const detail = await client.request(`${base}/monitors/${alertId}`, { expected: 200 });
  assert(!detail.text.includes(secret));
  await client.request(`${base}/monitors/${alertId}/notification-test`, { form: form({ csrfToken: htmlCsrf(detail.text), revision: String(alertMonitor.revision) }), expected: 303 });
  const deliveryResult = await until(() => json<{ notifications: DeliveryView[] }>(`${api}/notifications`), value => value.notifications.some(delivery => delivery.monitorId === alertId && delivery.type === "test" && delivery.status === "delivered"));
  assert(deliveryResult.notifications.some(delivery => delivery.channel === "webhook" && delivery.status === "delivered"));
  assert(service.fixtures.receipts.length > 0);
  console.log("PASS opt-in workspace defaults copy a real destination; explicit local webhook test produces delivery evidence without revealing the stored secret");

  first = await monitor(id); alertMonitor = await monitor(alertId);
  const bulkPage = await client.request(base, { expected: 200 });
  const pause = form({ csrfToken: htmlCsrf(bulkPage.text), action: "pause", [`revision_${id}`]: String(first.revision), [`revision_${alertId}`]: String(alertMonitor.revision) });
  pause.append("monitorId", id); pause.append("monitorId", alertId);
  await client.request(`${base}/monitors/bulk`, { form: pause, expected: 303 });
  assert((await monitor(id)).paused); assert((await monitor(alertId)).paused);
  const resumeStale = new URLSearchParams(pause); resumeStale.set("action", "resume");
  await client.request(`${base}/monitors/bulk`, { form: resumeStale, expected: 409 });
  assert((await monitor(id)).paused); assert((await monitor(alertId)).paused);
  resumeStale.set(`revision_${id}`, String((await monitor(id)).revision)); resumeStale.set(`revision_${alertId}`, String((await monitor(alertId)).revision));
  await client.request(`${base}/monitors/bulk`, { form: resumeStale, expected: 303 });
  assert(!(await monitor(id)).paused); assert(!(await monitor(alertId)).paused);
  console.log("PASS native repeated-checkbox bulk pause/resume is revision-fenced and rejects a stale batch without partial mutation");

  const maintenanceRevision = (await monitor(id)).revision;
  const maintenanceInput = { monitorId: id, revision: String(maintenanceRevision), startsAt: new Date(Date.now() - 1000).toISOString().slice(0, 19), endsAt: new Date(Date.now() + 3600000).toISOString().slice(0, 19), reason: "Controlled local maintenance" };
  await submit(`${base}/maintenance`, { ...maintenanceInput, revision: String(maintenanceRevision + 1) }, 409);
  assert.equal((await json<{ maintenance: MaintenanceWindow[] }>(`${api}/maintenance`)).maintenance.length, 0);
  assert.equal((await monitor(id)).revision, maintenanceRevision);
  await submit(`${base}/maintenance`, maintenanceInput);
  const windows = await json<{ maintenance: MaintenanceWindow[] }>(`${api}/maintenance`);
  const window = windows.maintenance.find(value => value.monitorId === id && value.status === "active")!;
  assert(window);
  assert.equal((await monitor(id)).effectiveState, "MAINTENANCE");
  await sleep(50);
  const report = await json<AvailabilityReport>(`${api}/reports?monitorId=${id}&from=${Date.now() - 60000}&to=${Date.now()}`);
  assert(report.durationsMs.MAINTENANCE > 0, "Real maintenance time must be represented separately from uptime");
  const reportPage = await client.request(`${base}/reports?monitorId=${id}`, { expected: 200 });
  assert(reportPage.text.includes('method="get"')); assert(reportPage.text.includes('name="from"')); assert(reportPage.text.includes('name="to"'));
  const cancelRevision = (await monitor(id)).revision;
  await submit(`${base}/maintenance/${window.id}/cancel`, { revision: String(cancelRevision - 1) }, 409);
  assert.equal((await monitor(id)).effectiveState, "MAINTENANCE", "Stale native cancellation must preserve real maintenance");
  await submit(`${base}/maintenance/${window.id}/cancel`, { revision: String(cancelRevision) });
  assert.notEqual((await monitor(id)).effectiveState, "MAINTENANCE");
  console.log("PASS native maintenance and cancellation expose truthful MAINTENANCE state and actual report data");

  const rejected = await submit(`${base}/new-monitor`, { kind: "http", id: "bad-config", name: "Preserved operator name", url: `${service.fixtures.httpUrl}/bad-config`, headersMode: "replace", headers: JSON.stringify({ Host: secret }) }, 400);
  assert(rejected.text.includes('value="Preserved operator name"'));
  assert(!rejected.text.includes(secret), "Invalid secret-bearing headers must not be redisplayed");
  const invalidValue = await submit(`${base}/new-monitor`, { kind: "http", id: "bad-header-value", name: "Safe header error", url: `${service.fixtures.httpUrl}/bad-header-value`, headersMode: "replace", headers: JSON.stringify({ Authorization: `${secret}\u0001` }) }, 400);
  assert(!invalidValue.text.includes(secret), "Rejected header values must not redisplay secret-bearing failed input");
  const statusPage = await client.request(`${base}/status-page`, { expected: 200 });
  const beforePublication = await json<{ revision: number }>(`${api}/status-page`);
  const publicationInput = { csrfToken: htmlCsrf(statusPage.text), revision: String(beforePublication.revision), slug: "local-ux-status", title: "Controlled service", componentId: id, [`componentLabel_${id}`]: "Service", published: "on" };
  await client.request(`${base}/status-page`, { form: form(publicationInput), expected: 303 });
  const configuredPublication = await json<{ page: { revision: number } }>(`${api}/status-page`);
  await client.request(`${base}/status-page`, { form: form({ ...publicationInput, title: "Stale native publication" }), expected: 409 });
  assert.deepEqual(await json(`${api}/status-page`), configuredPublication, "Stale native publication must preserve configured public components");
  const anonymous = new NativeClient(service.baseUrl);
  const publicPage = await anonymous.request("/status/local-ux-status", { expected: 200 });
  assert(!publicPage.text.includes(service.fixtures.httpUrl)); assert(!publicPage.text.includes(secret));
  await submit(`${base}/status-page/unpublish`, { revision: String(configuredPublication.page.revision - 1) }, 409);
  await anonymous.request("/status/local-ux-status", { expected: 200 });
  await submit(`${base}/status-page/unpublish`, { revision: String(configuredPublication.page.revision) });
  await anonymous.request("/status/local-ux-status", { expected: 404 });
  console.log("PASS no-JavaScript error recovery preserves nonsecret input; native publication remains explicitly opted-in and private-data-free");
} finally { await service?.close(); }
