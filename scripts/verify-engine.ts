import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import type { ProductionTestRuntime } from "./production-test-runtime.ts";
import { createProductionTestRuntime } from "./production-test-runtime.ts";
import { setTimeout as sleep } from "node:timers/promises";
import { gunzipSync, gzipSync } from "node:zlib";
import { executeMessage } from "../src/worker.ts";
import { runProbe } from "../src/probes.ts";
import { policy } from "../src/validation.ts";
import type { Check, ClaimedCheck, EngineSnapshot, MonitorInput, MonitorRecord, MonitorView, ProbeResult, StoredObservation } from "../src/types.ts";
import type { Fixtures } from "./fixtures.ts";

let token: string;
const webhookSecret = randomBytes(24).toString("hex");
const deadlineMs = 20_000;
const suiteDeadline = Date.now() + 300_000;
let runtime: ProductionTestRuntime | undefined;
let fixtures: Fixtures | undefined;
let passed = 0;

async function eventually<T>(label: string, observe: () => Promise<T>, accepts: (value: T) => boolean, timeout = deadlineMs): Promise<T> {
  const deadline = Math.min(Date.now() + timeout, suiteDeadline);
  let last: T | undefined;
  while (Date.now() < deadline) {
    let timer: NodeJS.Timeout | undefined;
    try {
      const observationDeadline = Promise.withResolvers<never>();
      timer = setTimeout(() => observationDeadline.reject(new Error(`${label}: observation exceeded hard deadline`)), Math.max(1, deadline - Date.now()));
      last = await Promise.race([observe(), observationDeadline.promise]);
    } finally { clearTimeout(timer); }
    if (accepts(last)) return last;
    await sleep(75);
  }
  throw new Error(`${label}: hard deadline exceeded; last=${JSON.stringify(last)}`);
}
function testRuntime(): ProductionTestRuntime { assert(runtime, "Runtime is missing"); return runtime; }
function fx(): Fixtures { assert(fixtures, "Fixtures are missing"); return fixtures; }

async function api(account: string, suffix: string, method = "GET", body?: unknown, authorization = `Bearer ${token}`): Promise<{ status: number; data: unknown }> {
  const response = await testRuntime().fetch(`/v1/accounts/${account}/${suffix}`, {
    method, headers: { Authorization: authorization, "Content-Type": "application/json" }, ...(body === undefined ? (method === "POST" ? { body: "{}" } : {}) : { body: JSON.stringify(body) }),
  });
  const data: unknown = await response.json();
  if (response.status >= 400) assert(data && typeof data === "object" && "error" in data, "API errors require a JSON error field");
  return { status: response.status, data };
}
async function ok(account: string, suffix: string, method = "GET", body?: unknown): Promise<unknown> {
  const result = await api(account, suffix, method, body);
  assert.equal(result.status, 200, `${method} ${account}/${suffix}: ${JSON.stringify(result)}`);
  return result.data;
}
async function state(account: string): Promise<EngineSnapshot> { return await ok(account, "state") as EngineSnapshot; }
async function fund(account: string, credits = 100): Promise<void> { await ok(account, "credits/initial", "PUT", { credits }); }
async function create(account: string, input: MonitorInput): Promise<{ monitor: MonitorView; heartbeatToken?: string }> {
  const result = await api(account, "monitors", "POST", input);
  assert.equal(result.status, 201, `Creating ${account}/${input.id}: ${JSON.stringify(result)}`);
  return result.data as { monitor: MonitorView; heartbeatToken?: string };
}
function input(id: string, check: Check, overrides: Partial<MonitorInput> = {}): MonitorInput {
  return { id, check, intervalMs: 60_000, timeoutMs: 500, confirmationDelayMs: 1_000, executionWindowMs: 5_000, ...overrides };
}
async function tick(account: string): Promise<void> { await ok(account, "tick", "POST"); }
async function pause(account: string, id = "monitor"): Promise<void> {
  await ok(account, `monitors/${id}/pause`, "POST", { revision: monitor(await state(account), id).revision });
}
async function resume(account: string, id = "monitor"): Promise<void> {
  await ok(account, `monitors/${id}/resume`, "POST", { revision: monitor(await state(account), id).revision });
}
async function internal<T>(account: string, endpoint: string, body?: unknown): Promise<T> {
  const response = await testRuntime().internalFetch(account, endpoint, {
    method: body === undefined ? "GET" : "POST", headers: { "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  assert(response.ok, `Engine ${endpoint}: HTTP${response.status} ${await response.clone().text()}`);
  return await response.json() as T;
}
async function scenario(name: string, run: () => Promise<void>): Promise<void> {
  await run(); passed++; console.log(`PASS ${name}`);
}
function monitor(snapshot: EngineSnapshot, id = "monitor"): MonitorView {
  const record = snapshot.monitors.find(item => item.id === id); assert(record, `Missing monitor ${id}`); return record;
}
function primaryObservations(snapshot: EngineSnapshot): StoredObservation[] {
  return snapshot.observations.filter(observation => snapshot.jobs.find(job => job.id === observation.id)?.role === "primary");
}
function assertCredits(snapshot: EngineSnapshot, credits: number, pulses = 0): void {
  const completed = snapshot.jobs.filter(job => job.role === "primary" && job.status === "done" && snapshot.observations.some(observation => observation.id === job.id && observation.result.outcome !== "unknown")).length;
  assert.equal(snapshot.usage, completed + pulses, "Every target observation is charged once, confirmations/unknowns are free");
  assert.equal(snapshot.balance + snapshot.usage, credits, "Conservation of deposited credits");
  assert(snapshot.reserved >= 0 && snapshot.reserved <= snapshot.balance);
}
async function stableState(account: string, desired: MonitorView["state"]): Promise<EngineSnapshot> {
  return eventually(`${account} reaches ${desired}`, () => state(account), value => monitor(value).state === desired);
}
async function protocolCase(kind: string, mode: "up" | "down" | "stall", check: Check, fixtureName: string,
  expectedOutcome: ProbeResult["outcome"] = mode === "up" ? "success" : "failure"): Promise<void> {
  const account = `${kind}_${mode}`;
  fx().set(fixtureName, mode);
  const previousHits = fx().hits.get(fixtureName) ?? 0;
  await fund(account);
  await create(account, input("monitor", check));
  const result = expectedOutcome === "unknown"
    ? await eventually(`${account} records missing resolver coverage`, () => state(account), value => value.observations.some(item => item.result.outcome === "unknown"))
    : await stableState(account, expectedOutcome === "success" ? "UP" : "DOWN");
  const observations = primaryObservations(result);
  assert.equal(observations.length, 1, "One primary slot expected");
  assert.equal(observations[0]?.result.outcome, expectedOutcome);
  assert((fx().hits.get(fixtureName) ?? 0) - previousHits >= (expectedOutcome === "failure" ? 2 : 1), "Real endpoint must receive every required physical attempt");
  if (mode === "stall") {
    assert((observations[0]?.result.latencyMs ?? 0) >= 350, "Stalled fixture must exercise actual timeout deadline");
    assert((observations[0]?.result.latencyMs ?? Infinity) < 3_000, "Timeout must remain bounded");
  }
  assertCredits(result, 100);
  assert.equal(result.usage, expectedOutcome === "unknown" ? 0 : 1);
  if (expectedOutcome === "unknown") {
    assert.equal(monitor(result).state, "UNKNOWN"); assert.equal(result.reserved, 0); assert.equal(result.incidents.length, 0);
  } else if (expectedOutcome === "failure") {
    assert.equal(result.incidents.length, 1);
    assert(result.jobs.some(job => job.role === "confirmation" && job.status === "done"));
  }
  await pause(account);
}

async function protocols(): Promise<void> {
  for (const mode of ["up", "down", "stall"] as const) {
    const name = `http_${mode}`;
    await scenario(`HTTP ${mode}`, () => protocolCase("http", mode, { kind: "http", url: `${fx().httpUrl}/${name}`, contains: "TOMATOOK" }, name));
    const secureName = `https_${mode}`;
    await scenario(`HTTPS ${mode} with isolated CA`, () => protocolCase("https", mode, { kind: "http", url: `${fx().httpsUrl}/${secureName}`, contains: "TOMATOOK" }, secureName));
    const dnsName = `dns-${mode}.example.com`;
    await scenario(`DNS wire ${mode}${mode === "stall" ? " remains UNKNOWN" : ""}`, () =>
      protocolCase("dns", mode, { kind: "dns", name: dnsName, recordType: "A", expected: ["127.0.0.1"] }, dnsName, mode === "stall" ? "unknown" : mode === "up" ? "success" : "failure"));
    const wsName = `websocket_${mode}`;
    await scenario(`WebSocket ${mode}`, () => protocolCase("websocket", mode, { kind: "websocket", url: `${fx().websocketUrl}/${wsName}`, send: "HELLO", expect: "TOMATOOK" }, wsName));
    await scenario(`TCP ${mode}`, () => protocolCase("tcp", mode, { kind: "tcp", hostname: "127.0.0.1", port: fx().tcpPort, send: "HELLO", expect: "TOMATOOK" }, "tcp"));
    await scenario(`TLS ${mode} with explicit CA`, () => protocolCase("tls", mode, { kind: "tls", hostname: "127.0.0.1", port: fx().tlsPort, send: "HELLO", expect: "TOMATOOK" }, "tls"));
  }
  const dnsRecords: { recordType: "AAAA" | "MX" | "TXT" | "NS" | "CNAME"; expected: string[] }[] = [
    { recordType: "AAAA", expected: ["::1"] },
    { recordType: "MX", expected: ["10 mail.fixture.test"] },
    { recordType: "TXT", expected: ["TOMATOOK"] },
    { recordType: "NS", expected: ["ns.fixture.test"] },
    { recordType: "CNAME", expected: ["alias.fixture.test"] },
  ];
  for (const { recordType, expected } of dnsRecords) {
    const name = `dns-${recordType.toLowerCase()}.example.com`;
    await scenario(`DNS wire ${recordType} answers`, () => protocolCase(`dns_${recordType.toLowerCase()}`, "up", { kind: "dns", name, recordType, expected }, name));
  }
  const privateRecord = "private-record.example.com";
  await scenario("DNS private-address records are assertions, not private network connections", () =>
    protocolCase("dns_private", "up", { kind: "dns", name: privateRecord, recordType: "A", expected: ["10.20.30.40"] }, privateRecord));
  for (const [kind, check] of [
    ["https", { kind: "http", url: `${fx().invalidHttpsUrl}/invalid_certificate` }],
    ["tls", { kind: "tls", hostname: "127.0.0.1", port: fx().invalidTlsPort }],
  ] as const) {
    await scenario(`${kind.toUpperCase()} rejects a trusted certificate for the wrong identity`, async () => {
      const account = `${kind}_invalid_identity`;
      await fund(account); await create(account, input("monitor", check));
      const snapshot = await eventually("Invalid identity yields a durable observation", () => state(account), value => value.observations.length > 0);
      const result = primaryObservations(snapshot)[0]?.result; assert(result);
      assert.notEqual(result.outcome, "success", "A trusted issuer must not bypass hostname validation");
      assert.notEqual(monitor(snapshot).state, "UP");
      if (result.outcome === "unknown") {
        assert.equal(snapshot.usage, 0); assert.equal(snapshot.balance, 100); assert.equal(snapshot.reserved, 0);
        assert.equal(snapshot.incidents.length, 0);
      } else {
        const down = await stableState(account, "DOWN");
        assert.equal(down.usage, 1); assert.equal(down.incidents.length, 1);
      }
      await pause(account);
    });
  }
  await scenario("Resolver infrastructure failure stays UNKNOWN and does not consume credits", async () => {
    const account = "resolver_impaired"; const name = "resolver-error.example.com";
    await fund(account); await create(account, input("monitor", { kind: "dns", name, recordType: "A" }));
    const snapshot = await eventually("Resolver failure observation is durably accepted", () => state(account), value => value.observations.some(item => item.result.outcome === "unknown"));
    assert.equal(monitor(snapshot).state, "UNKNOWN"); assert.equal(snapshot.usage, 0); assert.equal(snapshot.balance, 100); assert.equal(snapshot.reserved, 0);
    assert.equal(snapshot.incidents.length, 0);
    assert.equal(primaryObservations(snapshot)[0]?.result.outcome, "unknown");
    await pause(account);
  });
}

async function protocolBoundaries(): Promise<void> {
  const boundary = async (name: string, check: Check, outcome: ProbeResult["outcome"], code: string,
    fixtureName: string, physicalRequests: number): Promise<EngineSnapshot> => {
    const account = `boundary_${name}`;
    const before = fx().hits.get(fixtureName) ?? 0;
    await fund(account);
    await create(account, input("monitor", check, { confirmationDelayMs: 100 }));
    const snapshot = outcome === "unknown"
      ? await eventually(`${account} accepts a resolver observation`, () => state(account), value => value.observations.length > 0)
      : await stableState(account, outcome === "success" ? "UP" : "DOWN");
    const primary = primaryObservations(snapshot);
    assert.equal(primary.length, 1, "Exactly one scheduled primary is accepted");
    assert.equal(snapshot.observations.length, outcome === "failure" ? 2 : 1, "Only a target failure needs a free confirmation");
    for (const observation of snapshot.observations) {
      assert.equal(observation.result.outcome, outcome);
      assert.equal(observation.result.code, code);
      assert(observation.result.latencyMs < 2_000, "Protocol boundary handling completes within a bounded deadline");
    }
    assert.equal(monitor(snapshot).state, outcome === "unknown" ? "UNKNOWN" : outcome === "success" ? "UP" : "DOWN");
    assert.equal(snapshot.incidents.length, outcome === "failure" ? 1 : 0);
    if (outcome === "failure") {
      assert.equal(snapshot.incidents[0]?.closedAt, null);
      assert(snapshot.jobs.some(job => job.role === "confirmation" && job.status === "done"));
    }
    assertCredits(snapshot, 100);
    assert.equal(snapshot.usage, outcome === "unknown" ? 0 : 1);
    assert.equal(snapshot.balance, outcome === "unknown" ? 100 : 99);
    assert.equal(snapshot.reserved, 0);
    assert.equal((fx().hits.get(fixtureName) ?? 0) - before, physicalRequests, "Count real physical endpoint contacts, not queue deliveries");
    await pause(account);
    return snapshot;
  };

  await scenario("HTTP explicitly allowed non-2xx status succeeds and is charged once", async () => {
    const name = "boundary_custom_status";
    fx().httpSequence(name, [{ status: 418, body: "TOMATOOK" }]);
    const snapshot = await boundary("custom_status", { kind: "http", url: `${fx().httpUrl}/${name}`, status: [418], contains: "TOMATOOK" },
      "success", "http_ok", name, 1);
    assert.equal(primaryObservations(snapshot)[0]?.result.evidence?.status, 418);
    assert.equal(primaryObservations(snapshot)[0]?.result.evidence?.bytes, 8);
  });

  await scenario("HTTP cross-origin redirect contacts a second origin without forwarding credentials", async () => {
    const source = "boundary_redirect_source", target = "boundary_redirect_target";
    assert.notEqual(new URL(fx().httpUrl).origin, new URL(fx().secondHttpUrl).origin);
    fx().httpSequence(source, [{ status: 302, headers: { Location: `${fx().secondHttpUrl}/${target}` } }]);
    const targetBefore = fx().hits.get(target) ?? 0;
    await boundary("cross_origin", {
      kind: "http", url: `${fx().httpUrl}/${source}`, contains: "TOMATOOK",
      headers: { Authorization: "Bearer fixture-only", Cookie: "fixture=private", "X-Probe-Secret": "fixture-only" },
    }, "success", "http_ok", source, 1);
    assert.equal((fx().hits.get(target) ?? 0) - targetBefore, 1);
    const sent = fx().requestHeaders.get(source)?.at(-1), redirected = fx().requestHeaders.get(target)?.at(-1);
    assert(sent && redirected);
    assert.equal(sent.authorization, "Bearer fixture-only");
    assert.equal(sent.cookie, "fixture=private");
    assert.equal(sent["x-probe-secret"], "fixture-only");
    assert.equal(redirected.authorization, undefined);
    assert.equal(redirected.cookie, undefined);
    assert.equal(redirected["x-probe-secret"], undefined);
    assert.equal(redirected.host, new URL(fx().secondHttpUrl).host);
  });

  await scenario("HTTP redirect loop stops at the configured hop limit with one charged incident", async () => {
    const name = "boundary_redirect_loop";
    fx().httpSequence(name, [{ status: 302, headers: { Location: `/${name}` } }]);
    await boundary("redirect_loop", { kind: "http", url: `${fx().httpUrl}/${name}`, maxRedirects: 2 },
      "failure", "redirect_limit", name, 6);
  });

  await scenario("HTTP compressed body is capped by decoded bytes, not its small wire size", async () => {
    const name = "boundary_compressed_body", decoded = "TOMATOOK" + "x".repeat(1_024);
    const compressed = gzipSync(decoded);
    assert(compressed.byteLength < 64 && Buffer.byteLength(decoded) > 64);
    fx().httpSequence(name, [{
      headers: { "Content-Encoding": "gzip", "Content-Length": String(compressed.byteLength) }, body: compressed,
    }]);
    await boundary("compressed_body", { kind: "http", url: `${fx().httpUrl}/${name}`, contains: "TOMATOOK", maxBodyBytes: 64 },
      "failure", "response_too_large", name, 2);
  });

  await scenario("DNS malformed wire response is UNKNOWN with no charge or incident", async () => {
    const name = "boundary-malformed.example.com";
    fx().dnsResponse(name, "malformed");
    await boundary("dns_malformed", { kind: "dns", name, recordType: "A", expected: ["127.0.0.1"] },
      "unknown", "resolver_invalid_response", name, 1);
  });

  await scenario("DNS response transaction mismatch stays UNKNOWN and free", async () => {
    const name = "boundary-mismatched.example.com";
    fx().dnsResponse(name, "mismatched");
    await boundary("dns_mismatched", { kind: "dns", name, recordType: "A", expected: ["127.0.0.1"] },
      "unknown", "resolver_invalid_response", name, 1);
  });

  await scenario("WebSocket exact message mismatch opens one charged incident", async () => {
    const name = "boundary_websocket_mismatch";
    fx().websocketMessage(name, "TOMATOBAD");
    await boundary("websocket_mismatch", { kind: "websocket", url: `${fx().websocketUrl}/${name}`, send: "HELLO", expect: "TOMATOOK" },
      "failure", "websocket_message", name, 2);
  });

  await scenario("WebSocket extended-length frame exceeding message cap fails promptly", async () => {
    const name = "boundary_websocket_size";
    fx().websocketMessage(name, "TOMATOOK" + "x".repeat(120));
    await boundary("websocket_size", { kind: "websocket", url: `${fx().websocketUrl}/${name}`, send: "HELLO", expect: "TOMATOOK", maxMessageBytes: 8 },
      "failure", "response_too_large", name, 2);
  });

  await scenario("TCP banner split across delayed packets succeeds at the exact cumulative cap", async () => {
    fx().set("tcp", "up"); fx().streamBanner("tcp", ["TOMA", "TOOK"], 40);
    const before = fx().streamWrites.get("tcp") ?? 0;
    try {
      const snapshot = await boundary("tcp_split", { kind: "tcp", hostname: "127.0.0.1", port: fx().tcpPort, send: "HELLO", expect: "TOMATOOK", maxResponseBytes: 8 },
        "success", "tcp_ok", "tcp", 1);
      assert.equal(primaryObservations(snapshot)[0]?.result.evidence?.bytes, 8);
      assert.equal((fx().streamWrites.get("tcp") ?? 0) - before, 2, "The server physically writes two separate banner chunks");
    } finally { fx().streamBanner("tcp", []); }
  });

  await scenario("TLS split banner exceeding cumulative cap fails with a free confirmation", async () => {
    fx().set("tls", "up"); fx().streamBanner("tls", ["TOMA", "TOOK_TOO_LARGE"], 40);
    const before = fx().streamWrites.get("tls") ?? 0;
    try {
      await boundary("tls_oversized", { kind: "tls", hostname: "127.0.0.1", port: fx().tlsPort, send: "HELLO", expect: "TOMATOOK", maxResponseBytes: 8 },
        "failure", "response_too_large", "tls", 2);
      assert.equal((fx().streamWrites.get("tls") ?? 0) - before, 4, "Primary and confirmation both receive the cumulative overflow");
    } finally { fx().streamBanner("tls", []); }
  });
}

async function security(): Promise<void> {
  await scenario("API auth, deposits, validation, tenant isolation and redaction", async () => {
    assert.equal((await api("auth", "state", "GET", undefined, "")).status, 401);
    assert.equal((await api("auth", "state", "GET", undefined, "Bearer incorrect")).status, 401);
    await fund("tenant_a", 37); await fund("tenant_a", 37); await fund("tenant_b", 19);
    assert.equal((await state("tenant_a")).balance, 37); assert.equal((await state("tenant_b")).balance, 19);
    assert.equal((await state("tenant_b")).monitors.length, 0);
    const changedDeposit = await api("tenant_a", "credits/initial", "PUT", { credits: 38 });
    assert(changedDeposit.status >= 400 && changedDeposit.status < 500);
    for (const credits of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      const result = await api("tenant_a", `credits/invalid_${String(credits).replace(/[^A-Za-z0-9_-]/g, "_")}`, "PUT", { credits });
      assert(result.status >= 400 && result.status < 500);
    }
    for (const invalid of [input("bad/id", { kind: "heartbeat" }), input("bad_interval", { kind: "heartbeat" }, { intervalMs: 0 }), input("bad_port", { kind: "tcp", hostname: "127.0.0.1", port: 0 }), { ...input("bad_kind", { kind: "heartbeat" }), check: { kind: "not_a_protocol" } }]) {
      const result = await api("tenant_a", "monitors", "POST", invalid); assert(result.status >= 400 && result.status < 500);
    }
    await create("tenant_a", input("heartbeat", { kind: "heartbeat" }, { webhook: { url: fx().webhookUrl, secret: webhookSecret } }));
    const serialized = JSON.stringify(await state("tenant_a"));
    assert(!serialized.includes(webhookSecret)); assert(!serialized.includes("heartbeatTokenHash"));
    assert.equal((await state("tenant_b")).monitors.length, 0);
    await pause("tenant_a", "heartbeat");
  });
  await scenario("Unsafe addresses and unsafe HTTP redirects fail closed", async () => {
    const cases: Check[] = [
      { kind: "http", url: "http://169.254.169.254/latest/meta-data/" },
      { kind: "tcp", hostname: "10.0.0.1", port: 80 },
      { kind: "tls", hostname: "192.168.1.1", port: 443 },
      { kind: "websocket", url: "ws://172.16.0.1/" },
      { kind: "http", url: `${fx().httpUrl}/redirect-private` },
    ];
    for (const [index, check] of cases.entries()) {
      const account = `unsafe_${index}`; await fund(account);
      const result = await api(account, "monitors", "POST", input("monitor", check));
      if (result.status >= 400 && result.status < 500) continue;
      assert.equal(result.status, 201);
      const snapshot = await stableState(account, "DOWN");
      assert(snapshot.observations.every(observation => observation.result.outcome === "failure"));
      await pause(account);
    }
    assert((fx().hits.get("redirect-private") ?? 0) >= 1, "Redirect test must reach its controlled origin");
  });
  await scenario("A DNS-blocked destination is unexecuted, UNKNOWN and uncharged", async () => {
    const account = "blocked_preflight"; const fixtureName = "preflight_private";
    await fund(account);
    await create(account, input("monitor", { kind: "http", url: `http://private-record.example.com:${new URL(fx().httpUrl).port}/${fixtureName}` }));
    const snapshot = await eventually("Blocked preflight is durably accepted", () => state(account), value => value.observations.some(item => item.result.code === "blocked_destination"));
    assert.equal(primaryObservations(snapshot)[0]?.result.outcome, "unknown");
    assert.equal(monitor(snapshot).state, "UNKNOWN"); assert.equal(snapshot.usage, 0); assert.equal(snapshot.balance, 100); assert.equal(snapshot.reserved, 0);
    assert.equal(snapshot.incidents.length, 0); assert.equal(fx().hits.get(fixtureName) ?? 0, 0);
    await pause(account);
  });
}

async function heartbeat(): Promise<void> {
  await scenario("Heartbeat ingress deduplication, overdue incident and recovery", async () => {
    const account = "heartbeat"; await fund(account);
    const created = await create(account, input("monitor", { kind: "heartbeat", graceMs: 1 }, { intervalMs: 1_000, webhook: { url: fx().webhookUrl, secret: webhookSecret } }));
    assert(created.heartbeatToken);
    const pulse = async (key: string, bearer = created.heartbeatToken!): Promise<number> => {
      const response = await testRuntime().fetch(`/heartbeat/${account}/monitor`, { method: "POST", headers: { Authorization: `Bearer ${bearer}`, "Idempotency-Key": key } });
      await response.text(); return response.status;
    };
    assert.equal(await pulse("first", "invalid"), 401);
    const crossTenant = await testRuntime().fetch("/heartbeat/tenant_a/heartbeat", { method: "POST", headers: { Authorization: `Bearer ${created.heartbeatToken}`, "Idempotency-Key": "cross_tenant" } });
    assert(crossTenant.status >= 400 && crossTenant.status < 500);
    await crossTenant.text();
    assert.equal((await state("tenant_a")).usage, 0, "Heartbeat credentials cannot cross tenant boundaries");
    assert.equal(await pulse("first"), 200); assert.equal(await pulse("first"), 200);
    let snapshot = await state(account); assert.equal(snapshot.usage, 1); assert.equal(snapshot.balance, 99); assert.equal(monitor(snapshot).state, "UP");
    await stableState(account, "DOWN"); snapshot = await state(account); assert.equal(snapshot.usage, 1); assert.equal(snapshot.incidents.length, 1);
    assert.equal(await pulse("second"), 200); snapshot = await stableState(account, "UP");
    assert.equal(snapshot.usage, 2); assert.equal(snapshot.balance, 98); assert(snapshot.incidents[0]?.closedAt);
    await pause(account);
  });
}

interface NotificationBody { id: string; monitorId: string; incidentId: string; type: "down" | "recovery"; occurredAt: number }
function verifyReceipt(receipt: Fixtures["receipts"][number]): NotificationBody {
  const body = JSON.parse(receipt.body) as NotificationBody;
  assert.deepEqual(Object.keys(body).sort(), ["id", "incidentId", "monitorId", "occurredAt", "type"].sort());
  assert.equal(receipt.headers["idempotency-key"], body.id);
  const timestamp = receipt.headers["x-tomato-timestamp"]; assert.equal(typeof timestamp, "string");
  assert.equal(receipt.headers["x-tomato-signature"], createHmac("sha256", webhookSecret).update(`${timestamp}.${receipt.body}`).digest("hex"));
  assert.equal(receipt.headers["content-type"], "application/json");
  assert(Number.isFinite(body.occurredAt)); return body;
}
async function incidentsAndReplay(): Promise<void> {
  await scenario("PostgreSQL outbox incident, signed local webhook, recovery and duplicate deliveries", async () => {
    const account = "lifecycle"; fx().set("lifecycle", "up"); await fund(account);
    await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/lifecycle`, contains: "TOMATOOK" }, { intervalMs: 1_000, webhook: { url: fx().webhookUrl, secret: webhookSecret } }));
    await stableState(account, "UP"); fx().set("lifecycle", "down");
    const down = await stableState(account, "DOWN");
    const incident = down.incidents.find(item => item.closedAt === null); assert(incident);
    await eventually("Down webhook reaches real local sink", async () => { await tick(account); return fx().receipts.filter(receipt => (JSON.parse(receipt.body) as NotificationBody).incidentId === incident.id); }, receipts => receipts.some(receipt => verifyReceipt(receipt).type === "down"));
    fx().set("lifecycle", "up"); const recovered = await stableState(account, "UP");
    assert(recovered.incidents.find(item => item.id === incident.id)?.closedAt);
    await eventually("Recovery webhook reaches real local sink", async () => { await tick(account); return fx().receipts.filter(receipt => (JSON.parse(receipt.body) as NotificationBody).incidentId === incident.id); }, receipts => receipts.some(receipt => verifyReceipt(receipt).type === "recovery"));
    await pause(account); const before = await state(account);
    const completed = before.jobs.filter(job => job.status === "done"); assert(completed.length > 0);
    for (const job of completed) await executeMessage(testRuntime().env, { kind: "check", accountId: account, jobId: job.id });
    for (const notification of before.notifications) await executeMessage(testRuntime().env, { kind: "notification", accountId: account, eventId: notification.id });
    for (const job of completed) {
      const observation = before.observations.find(item => item.id === job.id); assert(observation);
      const replay = await internal<{ accepted: boolean }>(account, "/complete", { jobId: job.id, leaseToken: "finished-lease", result: observation.result });
      assert.equal(replay.accepted, false);
    }
    await sleep(1_500); const after = await state(account);
    assert.equal(after.balance, before.balance); assert.equal(after.usage, before.usage); assert.equal(after.reserved, before.reserved);
    assert.deepEqual(after.incidents, before.incidents); assert.equal(after.observations.length, before.observations.length); assertCredits(after, 100);
    for (const type of ["down", "recovery"] as const) assert.equal(after.notifications.filter(item => item.incidentId === incident.id && item.type === type).length, 1, "Exactly one durable notification intent per transition");
  });
}

async function consumer(enabled: boolean): Promise<void> {
  if (enabled) testRuntime().startConsumer(); else await testRuntime().stopConsumer();
}
async function claimFirst(account: string): Promise<ClaimedCheck> {
  const snapshot = await state(account); const pending = snapshot.jobs.find(job => job.status === "pending"); assert(pending, "Scheduler must persist a real pending job");
  const response = await internal<{ claim: ClaimedCheck | null }>(account, "/claim", { jobId: pending.id }); assert(response.claim); return response.claim;
}
function realResult(snapshot: EngineSnapshot, outcome: ProbeResult["outcome"]): ProbeResult {
  const observation = snapshot.observations.find(item => item.result.outcome === outcome); assert(observation, `Missing real ${outcome} evidence`); return observation.result;
}
async function adversarialScheduling(): Promise<void> {
  await scenario("Pause/resume cancels generations and rejects stale/reordered incident results", async () => {
    const evidence = await state("http_up");
    await consumer(false);
    try {
      const account = "generations"; await fund(account);
      await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/generations` }, { intervalMs: 1_000 }));
      await tick(account); const first = await claimFirst(account);
      await pause(account); const paused = await state(account); assert.equal(monitor(paused).state, "PAUSED"); assert.equal(paused.usage, 0); assert.equal(paused.reserved, 0);
      const rejected = await internal<{ accepted: boolean }>(account, "/complete", { jobId: first.job.id, leaseToken: first.leaseToken, result: realResult(evidence, "success") }); assert.equal(rejected.accepted, false);
      await resume(account); const resumed = await state(account); assert.equal(monitor(resumed).state, "UNKNOWN"); assert(monitor(resumed).revision > first.job.revision);
    } finally { await consumer(true); }
    await stableState("generations", "UP");
    fx().set("generations", "down"); const newer = await stableState("generations", "DOWN");
    const incident = newer.incidents.find(item => item.closedAt === null); assert(incident);
    const stale = newer.jobs.find(job => job.status === "cancelled"); assert(stale);
    const replay = await internal<{ accepted: boolean }>("generations", "/complete", { jobId: stale.id, leaseToken: "stale", result: realResult(evidence, "success") }); assert.equal(replay.accepted, false);
    const after = await state("generations"); assert.equal(monitor(after).state, "DOWN"); assert.equal(after.incidents.find(item => item.id === incident.id)?.closedAt, null);
    const oldUp = after.observations.find(item => item.result.outcome === "success"); assert(oldUp);
    const oldJob = after.jobs.find(item => item.id === oldUp.id); assert(oldJob);
    const reordered = await internal<{ accepted: boolean }>("generations", "/complete", { jobId: oldJob.id, leaseToken: "finished", result: oldUp.result }); assert.equal(reordered.accepted, false);
    assert.equal((await state("generations")).incidents.find(item => item.id === incident.id)?.closedAt, null);
    await pause("generations"); assertCredits(await state("generations"), 100);
  });
  await scenario("Missed PostgreSQL outbox jobs become UNKNOWN and release credits without charge", async () => {
    const account = "missed";
    await fund(account); await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/missed` }, { intervalMs: 3_500, executionWindowMs: 3_000 }));
    await stableState(account, "UP");
    await consumer(false);
    try {
      await eventually("The real scheduler persists an unconsumed slot", () => state(account), value => value.jobs.some(job => job.status === "pending"));
      const before = await state(account); const hits = fx().hits.get("missed") ?? 0;
      assert.equal(monitor(before).state, "UP", "Missing coverage must replace an actually observed healthy state");
      const { job } = await claimFirst(account);
      assert.equal((await state(account)).reserved, 1);
      await sleep(Math.max(0, job.expiresAt - Date.now()) + 150); await tick(account);
      const after = await state(account);
      assert(after.jobs.some(item => item.id === job.id && item.status === "missed"));
      assert.equal(monitor(after).state, "UNKNOWN"); assert.equal(after.usage, before.usage); assert.equal(after.balance, before.balance); assert.equal(after.reserved, 0);
      assert.deepEqual(after.observations, before.observations); assert(after.missedSlots > before.missedSlots);
      assert(after.coverage.some(segment => segment.state === "UP" && segment.endedAt !== null));
      assert(after.coverage.some(segment => segment.state === "UNKNOWN" && segment.endedAt === null && segment.startedAt >= job.scheduledAt));
      assert.equal(fx().hits.get("missed"), hits, "Claimed but unexecuted work must not contact the target");
      await pause(account); assertCredits(await state(account), 100);
    } finally { await consumer(true); }
    const paused = await state(account); await sleep(1_500);
    assert.equal((await state(account)).usage, paused.usage);
  });
}

async function observeClaim(claim: ClaimedCheck): Promise<ProbeResult> {
  assert(claim.check.kind !== "heartbeat");
  return runProbe(claim.check, claim.timeoutMs, policy(testRuntime().env));
}
async function deliverClaim(account: string, claim: ClaimedCheck, result: ProbeResult): Promise<boolean> {
  const response = await internal<{ accepted: boolean }>(account, "/complete", { jobId: claim.job.id, leaseToken: claim.leaseToken, result });
  return response.accepted;
}
async function pendingClaim(account: string, role: "primary" | "confirmation" = "primary", rootJobId?: string): Promise<ClaimedCheck> {
  const snapshot = await eventually(`${account} has due ${role} work`, () => state(account), value =>
    value.jobs.some(job => job.role === role && job.status === "pending" && job.scheduledAt <= Date.now() && (rootJobId === undefined || job.rootJobId === rootJobId)));
  const job = snapshot.jobs.find(job => job.role === role && job.status === "pending" && job.scheduledAt <= Date.now() && (rootJobId === undefined || job.rootJobId === rootJobId)); assert(job);
  const response = await internal<{ claim: ClaimedCheck | null }>(account, "/claim", { jobId: job.id }); assert(response.claim);
  return response.claim;
}
async function rephaseSchedule(account: string, at: number, unpause = false): Promise<void> {
  // Change only persisted scheduling; real time, leases, results and billing remain intact.
  await testRuntime().database.transaction(account, async tx => {
    const rows = await tx.query<{ data: string }>("SELECT data FROM engine.monitors WHERE id=$1", ["monitor"]);
    assert(rows[0]); const monitor = JSON.parse(rows[0].data) as MonitorRecord;
    monitor.nextDueAt = at;
    if (unpause) { monitor.paused = false; monitor.revision++; }
    await tx.query("UPDATE engine.monitors SET next_due=$1,paused=$2,data=$3 WHERE id=$4", [at, monitor.paused ? 1 : 0, JSON.stringify(monitor), "monitor"]);
  });
  await tick(account);
}
async function runtimeAdversarial(): Promise<void> {
  const owned = new Set<string>();
  const errors: Error[] = [];
  const cases: [string, () => Promise<void>][] = [
    ["A live older-slot success cannot close a newer confirmed incident", async () => {
      const account = "live_old_slot"; owned.add(account); await consumer(false); await fund(account);
      await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/${account}`, contains: "TOMATOOK" }, { confirmationDelayMs: 100, executionWindowMs: 15000 }));
      const older = await pendingClaim(account); const oldResult = await observeClaim(older); assert.equal(oldResult.outcome, "success");
      await rephaseSchedule(account, Date.now() + 150); fx().set(account, "down");
      const newer = await pendingClaim(account); const newerResult = await observeClaim(newer); assert.equal(newerResult.outcome, "failure");
      assert.equal(await deliverClaim(account, newer, newerResult), true);
      const confirmation = await pendingClaim(account, "confirmation", newer.job.id);
      assert.equal(await deliverClaim(account, confirmation, await observeClaim(confirmation)), true);
      const down = await state(account); assert.equal(monitor(down).state, "DOWN"); assert(down.incidents[0]);
      assert.equal(await deliverClaim(account, older, oldResult), true, "A live old receipt is accepted for history and usage");
      const after = await state(account);
      assert.equal(monitor(after).state, "DOWN"); assert.deepEqual(after.incidents, down.incidents); assert.deepEqual(after.coverage, down.coverage);
      assert.equal(after.usage, 2); assert.equal(after.balance, 98); assert.equal(after.reserved, 0);
      assert.equal(await deliverClaim(account, older, oldResult), false); assert.equal((await state(account)).usage, 2);
    }],
    ["A newer-slot primary observed before a confirmation cannot regress its newer DOWN evidence", async () => {
      const account = "live_observation_order"; owned.add(account); await consumer(false); await fund(account); fx().set(account, "down");
      await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/${account}`, contains: "TOMATOOK" }, { confirmationDelayMs: 100, executionWindowMs: 15000 }));
      const first = await pendingClaim(account); assert.equal(await deliverClaim(account, first, await observeClaim(first)), true);
      await rephaseSchedule(account, Date.now() + 150); fx().set(account, "up");
      const newer = await pendingClaim(account); const staleSuccess = await observeClaim(newer); assert.equal(staleSuccess.outcome, "success");
      await sleep(25); fx().set(account, "down");
      const confirmation = await pendingClaim(account, "confirmation", first.job.id); const failure = await observeClaim(confirmation);
      assert.equal(failure.outcome, "failure"); assert(staleSuccess.finishedAt < failure.finishedAt);
      assert.equal(await deliverClaim(account, confirmation, failure), true);
      const down = await state(account); assert.equal(monitor(down).state, "DOWN");
      assert.equal(await deliverClaim(account, newer, staleSuccess), true);
      const after = await state(account);
      assert.equal(monitor(after).state, "DOWN", "Observation time, not late submission, determines recovery evidence");
      assert.equal(monitor(after).candidateJobId, null); assert.deepEqual(after.incidents, down.incidents); assert.deepEqual(after.coverage, down.coverage);
      assert.equal(after.usage, 2); assert.equal(after.reserved, 0);
    }],
    ["Discarding an obsolete contradictory confirmation does not orphan newer failure confirmation", async () => {
      const account = "live_confirmation_order"; owned.add(account); await consumer(false); await fund(account); fx().set(account, "down");
      await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/${account}`, contains: "TOMATOOK" }, { confirmationDelayMs: 100, executionWindowMs: 15000 }));
      const first = await pendingClaim(account); assert.equal(await deliverClaim(account, first, await observeClaim(first)), true);
      fx().set(account, "up"); const confirmation = await pendingClaim(account, "confirmation", first.job.id);
      const staleSuccess = await observeClaim(confirmation); assert.equal(staleSuccess.outcome, "success");
      await rephaseSchedule(account, Date.now() + 150); fx().set(account, "down");
      const newer = await pendingClaim(account); const failure = await observeClaim(newer); assert.equal(failure.outcome, "failure");
      assert(staleSuccess.finishedAt < failure.finishedAt); assert.equal(await deliverClaim(account, newer, failure), true);
      assert.equal(await deliverClaim(account, confirmation, staleSuccess), true);
      const pending = await state(account);
      assert.equal(monitor(pending).state, "SUSPECT"); assert.equal(monitor(pending).candidateJobId, newer.job.id);
      assert(pending.jobs.some(job => job.role === "confirmation" && job.rootJobId === newer.job.id && job.status === "pending"));
      await consumer(true); const down = await stableState(account, "DOWN");
      assert.equal(down.usage, 2, "Replacement confirmation cannot require another paid primary slot");
      assert.equal(down.incidents.length, 1);
    }],
    ["An expired completion is rejected without destroying a still-fresh execution's lease takeover", async () => {
      const account = "lease_takeover"; owned.add(account); await consumer(false); await fund(account);
      await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/${account}`, contains: "TOMATOOK" }, { timeoutMs: 100, executionWindowMs: 15000 }));
      const first = await pendingClaim(account); const held = await observeClaim(first); assert.equal(held.outcome, "success");
      await sleep(Math.max(0, first.job.leaseUntil - Date.now()) + 100); assert(Date.now() < first.job.expiresAt);
      assert.equal(await deliverClaim(account, first, held), false);
      const response = await internal<{ claim: ClaimedCheck | null }>(account, "/claim", { jobId: first.job.id });
      assert(response.claim, "Lease expiry must permit takeover before the job's execution deadline");
      const second = response.claim; assert.notEqual(second.leaseToken, first.leaseToken);
      const reserved = await state(account); assert.equal(reserved.reserved, 1); assert.equal(reserved.usage, 0);
      assert.equal(await deliverClaim(account, first, held), false);
      assert.equal(await deliverClaim(account, second, await observeClaim(second)), true);
      const after = await state(account); assert.equal(after.usage, 1); assert.equal(after.balance, 99); assert.equal(after.reserved, 0); assert.equal(after.missedSlots, 0);
      assert.equal(fx().hits.get(account), 2, "Two physical attempts still consume only one logical credit");
    }],
    ["Concurrent outbound claims and heartbeat spend cannot overdraw the last credit", async () => {
      const account = "credit_contention"; owned.add(account); await consumer(false); await fund(account, 1);
      for (const id of ["first", "second"]) await create(account, input(id, { kind: "http", url: `${fx().httpUrl}/${account}_${id}`, contains: "TOMATOOK" }));
      const heartbeat = await create(account, input("pulse", { kind: "heartbeat" })); assert(heartbeat.heartbeatToken);
      const snapshot = await eventually("Two physical slots are durably scheduled", () => state(account), value => value.jobs.filter(job => job.role === "primary" && job.status === "pending").length === 2);
      const claims = await Promise.all(snapshot.jobs.map(job => internal<{ claim: ClaimedCheck | null }>(account, "/claim", { jobId: job.id })));
      const winners = claims.flatMap(value => value.claim ? [value.claim] : []); assert.equal(winners.length, 1); assert(winners[0]);
      let current = await state(account); assert.equal(current.balance, 1); assert.equal(current.reserved, 1); assert.equal(current.usage, 0);
      const pulse = async (): Promise<number> => {
        const response = await testRuntime().fetch(`/heartbeat/${account}/pulse`, { method: "POST", headers: { Authorization: `Bearer ${heartbeat.heartbeatToken}`, "Idempotency-Key": "competing" } });
        await response.text(); return response.status;
      };
      assert.equal(await pulse(), 402);
      assert.equal(await deliverClaim(account, winners[0], await observeClaim(winners[0])), true);
      current = await state(account); assert.equal(current.balance, 0); assert.equal(current.usage, 1); assert.equal(current.reserved, 0);
      assert.equal((fx().hits.get(`${account}_first`) ?? 0) + (fx().hits.get(`${account}_second`) ?? 0), 1);
      assert.equal(await pulse(), 402); await ok(account, "credits/refill", "PUT", { credits: 1 });
      assert.equal(await pulse(), 200, "Failed ingestion cannot consume the pulse's idempotency key"); assert.equal(await pulse(), 200);
      current = await state(account); assert.equal(current.balance, 0); assert.equal(current.usage, 2); assert.equal(current.reserved, 0);
      assert.equal(await deliverClaim(account, winners[0], current.observations.find(item => item.id === winners[0]!.job.id)!.result), false);
      await pause(account, "pulse"); assert.equal(await pulse(), 409); assert.equal((await state(account)).usage, 2);
    }],
    ["Same-slot incidents across accounts have distinct external webhook idempotency identities", async () => {
      const accounts = ["collision_a", "collision_b"]; await consumer(false);
      for (const account of accounts) {
        owned.add(account); await fund(account); fx().set(account, "down");
        await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/${account}` }, { confirmationDelayMs: 100, webhook: { url: fx().webhookUrl, secret: webhookSecret } }));
        await pause(account);
      }
      const at = Date.now() + 500;
      for (const account of accounts) await rephaseSchedule(account, at, true);
      await consumer(true);
      const snapshots = await Promise.all(accounts.map(account => eventually(`${account} delivers down intent`, () => state(account), value => value.notifications.some(item => item.type === "down" && item.status === "delivered"))));
      const notifications = snapshots.map(snapshot => { const item = snapshot.notifications.find(item => item.type === "down"); assert(item); return item; });
      assert.equal(snapshots[0]?.observations.find(item => item.scheduledAt === at)?.scheduledAt, at);
      assert.equal(snapshots[1]?.observations.find(item => item.scheduledAt === at)?.scheduledAt, at);
      assert.notEqual(notifications[0]?.id, notifications[1]?.id, "Account identity is part of the recipient's deduplication scope");
      for (const notification of notifications) {
        const effect = fx().acceptedWebhooks.get(notification.id); assert(effect); assert.equal(verifyReceipt(fx().receipts.find(receipt => receipt.body === effect.body)!).id, notification.id);
      }
    }],
    ["Webhook rejection and accepted-response loss retry transport without duplicate logical effects or charges", async () => {
      const account = "webhook_retries"; owned.add(account); fx().set(account, "down"); fx().webhookPlan(["reject", "lose-response", "accept"]); await fund(account);
      await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/${account}` }, { confirmationDelayMs: 100, webhook: { url: fx().webhookUrl, secret: webhookSecret } }));
      const first = await eventually("First rejected delivery is persisted for retry", () => state(account), value => value.notifications.some(item => item.attempts === 1 && item.status === "pending"));
      const event = first.notifications[0]; assert(event); assert.equal(fx().acceptedWebhooks.has(event.id), false);
      for (let i = 0; i < 4; i++) await executeMessage(testRuntime().env, { kind: "notification", accountId: account, eventId: event.id });
      const delivered = await eventually("Lost-response retry eventually commits delivery", () => state(account), value => value.notifications.some(item => item.id === event.id && item.status === "delivered"));
      assert.equal(delivered.notifications.find(item => item.id === event.id)?.attempts, 3);
      const receipts = fx().receipts.filter(receipt => (JSON.parse(receipt.body) as NotificationBody).id === event.id);
      assert.equal(receipts.length, 3); for (const receipt of receipts) assert.equal(verifyReceipt(receipt).id, event.id);
      assert(receipts[0]); const effect = fx().acceptedWebhooks.get(event.id); assert(effect); assert.equal(effect.body, receipts[0].body);
      assert.equal(delivered.usage, 1); assert.equal(delivered.balance, 99); assert.equal(delivered.notifications.length, 1);
      for (let i = 0; i < 4; i++) await executeMessage(testRuntime().env, { kind: "notification", accountId: account, eventId: event.id });
      await sleep(1500); assert.equal(fx().receipts.filter(receipt => (JSON.parse(receipt.body) as NotificationBody).id === event.id).length, 3);
      assert.deepEqual(fx().acceptedWebhooks.get(event.id), effect); assert.equal((await state(account)).usage, 1);
    }],
    ["Pending archive restart and duplicate envelopes preserve one exact PostgreSQL observation set", async () => {
      const account = "archive_replay"; owned.add(account); await consumer(false); await fund(account);
      await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/${account}`, contains: "TOMATOOK" }));
      const claim = await pendingClaim(account); const result = await observeClaim(claim); assert.equal(await deliverClaim(account, claim, result), true);
      const before = await state(account); const batch = await internal<{ batch: { id: string; observations: StoredObservation[] } | null }>(account, "/archive/claim", {}); assert(batch.batch);
      await testRuntime().restart();
      const restored = await internal<typeof batch>(account, "/archive/claim", {}); assert.deepEqual(restored, batch);
      for (let i = 0; i < 4; i++) await executeMessage(testRuntime().env, { kind: "archive", accountId: account });
      await consumer(true);
      const stored = await eventually("Outbox execution commits the restored immutable archive", () => archives(account), rows => rows.some(row => row.id === batch.batch!.id));
      const contents = stored.find(row => row.id === batch.batch!.id)!.payload;
      const decoded = JSON.parse(gunzipSync(contents).toString("utf8")) as { accountId: string; observations: StoredObservation[] };
      assert.equal(decoded.accountId, account); assert.deepEqual(decoded.observations, before.observations);
      for (let i = 0; i < 4; i++) await executeMessage(testRuntime().env, { kind: "archive", accountId: account });
      const replayed = await archives(account);
      assert.deepEqual(replayed.map(row => row.id), [batch.batch.id]);
      assert.deepEqual(replayed[0]!.payload, contents);
      assert.equal((await state(account)).usage, 1);
    }],
  ];
  for (const [name, run] of cases) {
    try { await scenario(name, run); }
    catch (error) { errors.push(error instanceof Error ? error : new Error(String(error))); console.error(`FAIL ${name}: ${String(error)}`); }
    finally {
      await consumer(false);
      for (const account of owned) for (const monitor of (await state(account)).monitors) if (!monitor.paused) await pause(account, monitor.id);
      fx().webhookPlan([]); await consumer(true);
    }
  }
  if (errors.length) throw new AggregateError(errors, `${errors.length} adversarial runtime scenarios failed`);
}

async function archives(account: string): Promise<{ id: string; payload: Buffer }[]> {
  return testRuntime().database.transaction(account, tx => tx.query<{ id: string; payload: Buffer }>("SELECT id,payload FROM engine.archives ORDER BY id"));
}
async function archiveAndRestart(): Promise<void> {
  await scenario("Archives claim at most 100 real observations, retain exact bytes and prune only expired scoped chunks", async () => {
    const account = "archive_bounds"; await consumer(false);
    try {
      await fund(account, 200); await create(account, input("monitor", { kind: "http", url: `${fx().httpUrl}/archive-bounds`, contains: "TOMATOOK" }));
      const ids: string[] = [];
      for (let index = 0; index < 105; index++) {
        if (index) { await sleep(2); await rephaseSchedule(account, Date.now()); }
        const claim = await pendingClaim(account);
        assert.equal(await deliverClaim(account, claim, await observeClaim(claim)), true); ids.push(claim.job.id);
      }
      await pause(account);
      const first = await internal<{ batch: { id: string; observations: StoredObservation[] } }>(account, "/archive/claim", {});
      assert.equal(first.batch.observations.length, 100);
      await testRuntime().restart();
      assert.deepEqual(await internal(account, "/archive/claim", {}), first);
      await executeMessage(testRuntime().env, { kind: "archive", accountId: account });
      const second = await internal<{ batch: { id: string; observations: StoredObservation[] } }>(account, "/archive/claim", {});
      assert.equal(second.batch.observations.length, 5);
      await executeMessage(testRuntime().env, { kind: "archive", accountId: account });
      assert.equal((await internal<{ batch: null }>(account, "/archive/claim", {})).batch, null);
      const rows = await archives(account); assert.equal(rows.length, 2);
      const archivedIds: string[] = [];
      for (const row of rows) {
        const decoded: unknown = JSON.parse(gunzipSync(row.payload).toString("utf8"));
        assert(decoded && typeof decoded === "object" && "accountId" in decoded && decoded.accountId === account && "observations" in decoded && Array.isArray(decoded.observations));
        for (const observation of decoded.observations) {
          assert(observation && typeof observation === "object" && "id" in observation && typeof observation.id === "string");
          archivedIds.push(observation.id);
        }
      }
      assert.deepEqual(archivedIds.sort(), ids.sort()); assert.equal((await state(account)).usage, 105);
      const foreign = await archives("http_up");
      const bytes = rows[0]!.payload;
      await testRuntime().database.transaction(account, async tx => {
        await tx.query("INSERT INTO engine.archives(account_id,id,payload,created_at) VALUES($1,$2,$3,$4)", [account, "expired-retention-fixture", bytes, Date.now() - 31 * 86400000]);
        await tx.query("INSERT INTO engine.archives(account_id,id,payload,created_at) VALUES($1,$2,$3,$4)", [account, "retained-fixture", bytes, Date.now()]);
      });
      await tick(account);
      const retained = await archives(account);
      assert(!retained.some(row => row.id === "expired-retention-fixture")); assert(retained.some(row => row.id === "retained-fixture"));
      for (const row of rows) assert.deepEqual(retained.find(item => item.id === row.id)?.payload, row.payload);
      assert.deepEqual(await archives("http_up"), foreign);
    } finally { await consumer(true); }
  });
  await scenario("PostgreSQL compressed archives contain matching recorded protocol evidence", async () => {
    const expected = (await state("http_up")).observations[0]; assert(expected);
    await executeMessage(testRuntime().env, { kind: "archive", accountId: "http_up" });
    const rows = await archives("http_up");
    assert(rows.length > 0);
    const observations = rows.flatMap(row => {
      const archived = JSON.parse(gunzipSync(row.payload).toString("utf8")) as { version: number; accountId: string; observations: StoredObservation[] };
      assert.equal(archived.version, 1); assert.equal(archived.accountId, "http_up");
      return archived.observations;
    });
    assert(observations.some(record => record.id === expected.id && record.monitorId === expected.monitorId && JSON.stringify(record.result) === JSON.stringify(expected.result)));
    await testRuntime().database.transaction("tenant_b", async tx => {
      assert.equal((await tx.query("SELECT id FROM engine.archives WHERE account_id=$1", ["http_up"])).length, 0, "FORCE RLS excludes another account's archive bytes");
    });
  });
  await scenario("Restarting the Node runtime preserves PostgreSQL tenants, ledger, incidents and archive bytes", async () => {
    const accounts = ["lifecycle", "heartbeat", "tenant_a", "tenant_b", "generations", "missed"];
    const before = await Promise.all(accounts.map(state));
    const beforeArchives = await archives("http_up");
    await testRuntime().restart();
    for (const [index, account] of accounts.entries()) {
      const after = await state(account); const previous = before[index]; assert(previous);
      assert.equal(after.balance, previous.balance); assert.equal(after.usage, previous.usage); assert.equal(after.reserved, previous.reserved);
      assert.deepEqual(after.monitors, previous.monitors); assert.deepEqual(after.incidents, previous.incidents); assert.deepEqual(after.observations, previous.observations);
    }
    await fund("tenant_a", 37); assert.equal((await state("tenant_a")).balance, 37, "Deposit idempotency survives runtime restart");
    assert.deepEqual(await archives("http_up"), beforeArchives);
  });
}

async function modeBoundary(): Promise<void> {
  await scenario("Self-host executes and counts without deposits while hosted mode enforces its empty ledger", async () => {
    const local = await createProductionTestRuntime({ background: false, runtime: { mode: "self-host" } });
    try {
      const account = "self_host";
      const call = async <T>(endpoint: string, method = "GET", value?: unknown): Promise<T> => {
        const response = await local.internalFetch(account, endpoint, { method, headers: { "Content-Type": "application/json" }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
        assert(response.ok, await response.clone().text()); return await response.json() as T;
      };
      await call("/monitors", "POST", input("outbound", { kind: "http", url: `${local.fixtures.httpUrl}/unmetered`, contains: "TOMATOOK" }));
      const pulse = await call<{ heartbeatToken: string }>("/monitors", "POST", input("pulse", { kind: "heartbeat" }));
      await call("/tick", "POST");
      const scheduled = await call<EngineSnapshot>("/state");
      const job = scheduled.jobs.find(item => item.role === "primary" && item.status === "pending"); assert(job);
      await executeMessage(local.env, { kind: "check", accountId: account, jobId: job.id });
      const response = await local.internalFetch(account, "/monitors/pulse/heartbeat", { method: "POST", headers: { Authorization: `Bearer ${pulse.heartbeatToken}`, "Idempotency-Key": "unmetered-pulse" } });
      assert.equal(response.status, 200);
      const snapshot = await call<EngineSnapshot>("/state");
      assert.equal(snapshot.usage, 2); assert.equal(snapshot.balance, 0); assert.equal(snapshot.reserved, 0);
      assert.equal(snapshot.mode, "self-host"); assert.equal(snapshot.creditEnforced, false);
      assert.equal(snapshot.observations.length, 1); assert.equal(local.fixtures.hits.get("unmetered"), 1);
      const duplicate = await local.internalFetch(account, "/monitors/pulse/heartbeat", { method: "POST", headers: { Authorization: `Bearer ${pulse.heartbeatToken}`, "Idempotency-Key": "unmetered-pulse" } });
      const duplicateBody: unknown = await duplicate.json();
      assert(duplicateBody && typeof duplicateBody === "object" && "duplicate" in duplicateBody && duplicateBody.duplicate === true);
      await executeMessage(local.env, { kind: "check", accountId: account, jobId: job.id });
      assert.equal((await call<EngineSnapshot>("/state")).usage, 2);
      await call("/monitors", "POST", input("blocked", { kind: "http", url: "http://private-record.example.com/never-executed" }));
      await call("/tick", "POST");
      const blocked = (await call<EngineSnapshot>("/state")).jobs.find(item => item.monitorId === "blocked" && item.status === "pending"); assert(blocked);
      await executeMessage(local.env, { kind: "check", accountId: account, jobId: blocked.id });
      const unknown = await call<EngineSnapshot>("/state");
      assert.equal(unknown.usage, 2); assert.equal(unknown.observations.find(item => item.id === blocked.id)?.result.outcome, "unknown");
      await local.restart();
      const restored = await call<EngineSnapshot>("/state");
      assert.equal(restored.usage, 2); assert.equal(restored.balance, 0);
      local.env.MODE = "hosted";
      try {
        const mismatched = await local.internalFetch(account, "/state");
        assert.equal(mismatched.status, 409, "An existing account cannot silently cross charging policies");
      } finally { local.env.MODE = "self-host"; }
    } finally { await local.close(); }
    await consumer(false);
    try {
      const account = "hosted_empty";
      await create(account, input("outbound", { kind: "http", url: `${fx().httpUrl}/hosted-empty` }));
      const pulse = await create(account, input("pulse", { kind: "heartbeat" })); assert(pulse.heartbeatToken);
      await tick(account);
      const scheduled = await state(account); assert.equal(scheduled.mode, "hosted"); assert.equal(scheduled.creditEnforced, true);
      for (const job of scheduled.jobs) await executeMessage(testRuntime().env, { kind: "check", accountId: account, jobId: job.id });
      const response = await testRuntime().fetch(`/heartbeat/${account}/pulse`, { method: "POST", headers: { Authorization: `Bearer ${pulse.heartbeatToken}`, "Idempotency-Key": "empty" } });
      assert.equal(response.status, 402); assert.equal((await state(account)).usage, 0); assert.equal(fx().hits.get("hosted-empty") ?? 0, 0);
      await pause(account, "outbound"); await pause(account, "pulse");
    } finally { await consumer(true); }
  });
}

async function main(): Promise<void> {
  runtime = await createProductionTestRuntime();
  fixtures = runtime.fixtures;
  token = runtime.token;
  const suite = process.env.TOMATO_VERIFY_SUITE;
  if (suite === "runtime") await runtimeAdversarial();
  else if (suite === "protocol") await protocolBoundaries();
  else {
    if (suite !== undefined) throw new Error(`Unknown TOMATO_VERIFY_SUITE: ${suite}`);
    await security(); await protocols(); await protocolBoundaries(); await heartbeat(); await incidentsAndReplay(); await adversarialScheduling(); await runtimeAdversarial(); await archiveAndRestart(); await modeBoundary();
  }
  console.log(`PASS engine verification: ${passed} scenarios; real Node/PostgreSQL/outbox, authenticated isolated prober and protocol fixtures`);
}
try { await main(); }
catch (error) { console.error(`FAIL engine verification: ${error instanceof Error ? error.stack : String(error)}`); process.exitCode = 1; }
finally {
  try { await runtime?.close(); }
  catch (error) { console.error(`FAIL cleanup: ${String(error)}`); process.exitCode = 1; }
}
