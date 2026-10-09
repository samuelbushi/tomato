import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { createProductionTestRuntime, type ProductionTestRuntime } from "./production-test-runtime.ts";
import type { Fixtures } from "./fixtures.ts";
import worker from "../src/worker.ts";
import type { Env } from "../src/runtime-types.ts";
import type { Principal } from "../src/product-types.ts";
import type { MonitorView } from "../src/types.ts";
import { verifyOperatorCredits } from "./verify-operator-credits.ts";

const password = randomBytes(24).toString("hex");
const headerSecret = randomBytes(24).toString("hex");
const webhookSecret = randomBytes(24).toString("hex");
let runtime: ProductionTestRuntime | undefined;
let fixtures: Fixtures | undefined;
let passed = 0;
interface Client { cookies: Map<string, string>; csrf: string }
const owner: Client = { cookies: new Map(), csrf: "" };
const viewer: Client = { cookies: new Map(), csrf: "" };
const editor: Client = { cookies: new Map(), csrf: "" };
const anonymous: Client = { cookies: new Map(), csrf: "" };
let origin: string;
try {
  runtime = await createProductionTestRuntime();
  fixtures = runtime.fixtures;
  origin = runtime.baseUrl;
  const operator = runtime.token;
  async function request(client: Client, route: string, method = "GET", value?: unknown, options: { status?: number; origin?: string; csrf?: string; bearer?: string; form?: boolean } = {}) {
    const headers: Record<string, string> = {};
    if (client.cookies.size) headers.Cookie = [...client.cookies].map(([key, cookie]) => `${key}=${cookie}`).join("; ");
    if (options.bearer) headers.Authorization = `Bearer ${options.bearer}`;
    let payload: string | undefined;
    if (method !== "GET") {
      headers.Origin = options.origin ?? origin;
      headers["X-CSRF-Token"] = options.csrf ?? client.csrf;
      if (value !== undefined) { headers["Content-Type"] = options.form ? "application/x-www-form-urlencoded" : "application/json"; payload = options.form ? new URLSearchParams(value as Record<string, string>).toString() : JSON.stringify(value); }
    }
    const response = await runtime!.fetch(`${origin}${route}`, { method, headers, ...(payload === undefined ? {} : { body: payload }), redirect: "manual" });
    if (options.status !== undefined) assert.equal(response.status, options.status, "Unexpected client response status");
    for (const entry of response.headers.getSetCookie()) {
      const first = entry.split(";", 1)[0]!;
      const split = first.indexOf("="); const name = first.slice(0, split), cookieValue = first.slice(split + 1);
      if (cookieValue) client.cookies.set(name, cookieValue); else client.cookies.delete(name);
    }
    const text = await response.text();
    let data: Record<string, unknown> = {};
    if (response.headers.get("Content-Type")?.includes("application/json")) data = JSON.parse(text) as Record<string, unknown>;
    return { response, text, data };
  }
  async function scenario(label: string, fn: () => Promise<void>): Promise<void> { await fn(); passed++; console.log(`PASS ${label}`); }
  async function login(client: Client, email: string): Promise<void> {
    const preflight = await request(client, "/api/auth/login", "GET", undefined, { status: 200 });
    client.csrf = String(preflight.data.csrfToken);
    await request(client, "/api/auth/login", "POST", { email, password, csrfToken: client.csrf }, { status: 200 });
    client.csrf = String((await request(client, "/api/session", "GET", undefined, { status: 200 })).data.csrfToken);
    assert(client.cookies.has("tomato-session"));
  }
  await scenario("public homepage works without identity or auth configuration and preserves HTTP semantics", async () => {
    const publicFetch = (url: string, init?: RequestInit) => worker.fetch(new Request(url, init), {} as Env);
      const response = await publicFetch("https://tomato.local/", { redirect: "manual" });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("Set-Cookie"), null);
      assert(response.headers.get("Content-Security-Policy")?.includes("frame-ancestors 'none'"));
      const text = await response.text();
      const withCredentials = await publicFetch("https://tomato.local/", { headers: { Cookie: "__Host-tomato-session=unavailable", Authorization: "Bearer unavailable" }, redirect: "manual" });
      assert.equal(withCredentials.status, 200);
      assert.equal(withCredentials.headers.get("Set-Cookie"), null);
      assert.equal(await withCredentials.text(), text);
      const head = await publicFetch("https://tomato.local/", { method: "HEAD", redirect: "manual" });
      assert.equal(head.status, 200);
      assert.equal(await head.text(), "");
      for (const header of ["Content-Type", "Cache-Control", "Content-Security-Policy", "Referrer-Policy"]) assert.equal(head.headers.get(header), response.headers.get(header));
      for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
        const unsupported = await publicFetch("https://tomato.local/", { method, redirect: "manual" });
        assert.equal(unsupported.status, 405);
        assert.equal(unsupported.headers.get("Allow"), "GET, HEAD");
        assert.equal(unsupported.headers.get("Set-Cookie"), null);
      }
      const insecure = await publicFetch("http://tomato.local/?from=home", { redirect: "manual" });
      assert.equal(insecure.status, 308);
      assert.equal(insecure.headers.get("Location"), "https://tomato.local/?from=home");
      assert.equal(insecure.headers.get("Set-Cookie"), null);
  });
  await scenario("hosted operator provisioning validates credit admission before creating identities and never grants implicitly", async () => {
    await verifyOperatorCredits(runtime!);
  });
  await scenario("protected provisioning creates actual account and auditable testing grants", async () => {
    await request(anonymous, "/api/operator/accounts", "POST", { id: "alpha", name: "Alpha", owner: { email: "alice@example.test", name: "Alice fixture", password, emailVerified: true }, testingCredits: 10000 }, { status: 201, bearer: operator });
    await request(anonymous, "/api/operator/accounts", "POST", { id: "beta", name: "Beta", owner: { email: "bob@example.test", name: "Bob fixture", password, emailVerified: true }, testingCredits: 10000 }, { status: 201, bearer: operator });
    await request(anonymous, "/api/operator/accounts", "POST", { id: "forged", name: "Forged", owner: { email: "forger@example.test", name: "Unauthorized fixture", password, emailVerified: true } }, { status: 401 });
    await login(owner, "alice@example.test");
    const usage = await request(owner, "/api/accounts/alpha/usage", "GET", undefined, { status: 200 });
    assert.equal(usage.data.creditSource, "hosted-ledger"); assert.equal(usage.data.balance, 10000); assert.equal((usage.data.grants as unknown[]).length, 1);
    await request(owner, "/api/operator/accounts/alpha/credits/forged", "PUT", { credits: 1000000 }, { status: 401 });
  });
  await scenario("session API, SSR login redirects and cookie security headers are genuine", async () => {
    const session = await request(owner, "/api/session", "GET", undefined, { status: 200 });
    assert.equal((session.data.actor as Principal["actor"]).username, "alice@example.test");
    const app = await request(owner, "/app/accounts/alpha", "GET", undefined, { status: 200 });
    assert.equal(app.response.headers.get("Cache-Control"), "no-store"); assert(app.response.headers.get("Content-Security-Policy")?.includes("frame-ancestors 'none'"));
    const denied = await request(anonymous, "/app/accounts/alpha", "GET", undefined, { status: 303 }); assert.equal(denied.response.headers.get("Location"), "/login");
    await request(anonymous, "/api/accounts/alpha/state", "GET", undefined, { status: 401 });
    await request(owner, "/api/accounts/beta/state", "GET", undefined, { status: 404 });
  });
  await scenario("homepage stays public with a real session while console and login retain private boundaries", async () => {
    const home = await request(anonymous, "/", "GET", undefined, { status: 200 });
    const signedIn = await request(owner, "/", "GET", undefined, { status: 200 });
    assert.equal(signedIn.text, home.text);
    assert.equal(signedIn.response.headers.get("Set-Cookie"), null);
    const denied = await request(anonymous, "/app", "GET", undefined, { status: 303 });
    assert.equal(denied.response.headers.get("Location"), "/login");
    const loginPage = await request(anonymous, "/login", "GET", undefined, { status: 200 });
    assert.equal(loginPage.response.headers.get("Cache-Control"), "no-store");
    assert(loginPage.response.headers.get("Set-Cookie"));
    const selected = await request(owner, "/app", "GET", undefined, { status: 303 });
    assert.equal(selected.response.headers.get("Location"), "/app/accounts/alpha");
    const workspace = await request(owner, selected.response.headers.get("Location")!, "GET", undefined, { status: 200 });
    assert.equal(workspace.response.headers.get("Cache-Control"), "no-store");
  });
  await scenario("HTML login redirects forward and persist genuine server session cookies", async () => {
    const browserClient: Client = { cookies: new Map(), csrf: "" };
    const loginPage = await request(browserClient, "/login", "GET", undefined, { status: 200 });
    const token = loginPage.text.match(/name="csrfToken"\s+value="([^"]+)"/);
    assert(token, "Actual HTML login must provide its anonymous CSRF credential");
    browserClient.csrf = token[1]!;
    const anonymousCookieNames = [...browserClient.cookies.keys()];
    const submitted = await request(browserClient, "/login", "POST", { email: "alice@example.test", password, csrfToken: browserClient.csrf }, { status: 303, form: true });
    assert.equal(submitted.response.headers.get("Location"), "/app");
    assert(anonymousCookieNames.every(name => !browserClient.cookies.has(name)), "Actual HTML login must clear anonymous cookies independently of its new session cookie");
    const selected = await request(browserClient, "/app", "GET", undefined, { status: 303 });
    assert.equal(selected.response.headers.get("Location"), "/app/accounts/alpha");
    await request(browserClient, "/app/accounts/alpha/new-monitor", "GET", undefined, { status: 200 });
    const session = await request(browserClient, "/api/session", "GET", undefined, { status: 200 });
    browserClient.csrf = String(session.data.csrfToken);
    await request(browserClient, "/api/auth/logout", "POST", {}, { status: 200 });
    await request(browserClient, "/app/accounts/alpha/new-monitor", "GET", undefined, { status: 303 });
  });
  let revision = 0;
  await scenario("same-origin JSON monitor CRUD enforces CSRF, redacts values and fences revisions", async () => {
    const input = { id: "http", name: "Private API", check: { kind: "http", url: `${fixtures!.httpUrl}/product-client`, headers: { Authorization: headerSecret }, contains: "TOMATOOK" }, intervalMs: 60000, timeoutMs: 500, executionWindowMs: 5000, webhook: { url: fixtures!.webhookUrl, secret: webhookSecret } };
    await request(owner, "/api/accounts/alpha/monitors", "POST", input, { status: 403, origin: "https://foreign.invalid" });
    await request(owner, "/api/accounts/alpha/monitors", "POST", input, { status: 403, origin: "null" });
    await request(owner, "/api/accounts/alpha/monitors", "POST", input, { status: 403, csrf: "wrong" });
    const created = await request(owner, "/api/accounts/alpha/monitors", "POST", input, { status: 201 });
    const monitor = created.data.monitor as MonitorView; revision = monitor.revision;
    assert(!created.text.includes(headerSecret)); assert(!created.text.includes(webhookSecret));
    const snapshot = await request(owner, "/api/accounts/alpha/state", "GET", undefined, { status: 200 });
    assert(!snapshot.text.includes(headerSecret)); assert(!snapshot.text.includes(webhookSecret)); assert(!snapshot.text.includes("leaseToken"));
    const persisted = await runtime!.database.transaction("alpha", tx => tx.query<{ data: string }>("SELECT data FROM engine.monitors WHERE account_id=$1 AND id=$2", ["alpha", "http"]));
    assert.equal(persisted.length, 1);
    assert(!persisted[0]!.data.includes(headerSecret)); assert(!persisted[0]!.data.includes(webhookSecret));
    const observedDeadline = Date.now() + 15000;
    while (!(fixtures!.requestHeaders.get("product-client") ?? []).some(headers => headers.authorization === headerSecret)) {
      assert(Date.now() < observedDeadline, "The real prober must send the original decrypted HTTP credential to the controlled recipient");
      await sleep(100);
    }
    const updated = await request(owner, "/api/accounts/alpha/monitors/http", "PUT", { ...input, revision, name: "Renamed", headersMode: "keep", webhookMode: "keep", check: { kind: "http", url: `${fixtures!.httpUrl}/product-client`, contains: "TOMATOOK" } }, { status: 200 });
    revision = (updated.data.monitor as MonitorView).revision;
    await request(owner, "/api/accounts/alpha/monitors/http", "PUT", { ...input, revision: revision - 1 }, { status: 409 });
    await request(owner, "/api/accounts/alpha/monitors/http", "GET", undefined, { status: 200 });
  });
  await scenario("SSR forms produce actual mutations and 303 rather than pretend UI changes", async () => {
    const created = await request(owner, "/app/accounts/alpha/new-monitor", "POST", { csrfToken: owner.csrf, id: "form-dns", name: "DNS by form", kind: "dns", dnsName: "dns-up.example.com", recordType: "A", expected: "127.0.0.1", intervalSeconds: "60", timeoutSeconds: "0.5", confirmationDelaySeconds: "1", executionWindowSeconds: "5" }, { status: 303, form: true });
    assert.equal(created.response.headers.get("Location"), "/app/accounts/alpha/monitors/form-dns");
    const monitor = await request(owner, "/api/accounts/alpha/monitors/form-dns", "GET", undefined, { status: 200 }); assert.equal((monitor.data.monitor as MonitorView).name, "DNS by form");
    const editor = await request(owner, "/app/accounts/alpha/monitors/http/edit", "GET", undefined, { status: 200 }); assert(!editor.text.includes(headerSecret)); assert(!editor.text.includes(webhookSecret));
  });
  await scenario("real invite link acceptance establishes viewer; role and account boundaries govern writes", async () => {
    const invitation = await request(owner, "/api/accounts/alpha/invitations", "POST", { username: "carol@example.test", role: "viewer" }, { status: 201 });
    const token = String(invitation.data.invitationToken);
    await request(anonymous, "/api/operator/accounts", "POST", { id: "viewer-fixture", name: "Viewer fixture identity", owner: { email: "carol@example.test", name: "Carol fixture", password, emailVerified: true }, testingCredits: 1 }, { status: 201, bearer: operator });
    await login(viewer, "carol@example.test");
    const preview = await request(viewer, `/invite/${token}`, "GET", undefined, { status: 200 });
    const csrfMatch = preview.text.match(/name="csrfToken"\s+value="([^"]+)"/); assert(csrfMatch, "Invite form requires an actual CSRF field"); viewer.csrf = csrfMatch[1]!;
    await request(viewer, `/invite/${token}`, "POST", { csrfToken: viewer.csrf }, { status: 403, form: true, origin: "https://foreign.invalid" });
    await request(viewer, `/invite/${token}`, "POST", { csrfToken: viewer.csrf }, { status: 403, form: true, origin: "null" });
    await request(viewer, `/invite/${token}`, "POST", { csrfToken: viewer.csrf }, { status: 303, form: true });
    const session = await request(viewer, "/api/session", "GET", undefined, { status: 200 }); viewer.csrf = String(session.data.csrfToken);
    await request(viewer, "/api/accounts/alpha/monitors", "GET", undefined, { status: 200 });
    await request(viewer, "/api/accounts/alpha/monitors/http/pause", "POST", { revision }, { status: 403 });
    await request(viewer, "/api/accounts/alpha/invitations", "POST", { username: "mallory@example.test", role: "owner" }, { status: 403 });
    await request(viewer, "/api/accounts/beta/state", "GET", undefined, { status: 404 });
  });
  await scenario("served owner, editor and viewer HTML exposes only authorized team and publication controls", async () => {
    const invited = await request(owner, "/api/accounts/alpha/invitations", "POST", { username: "dana@example.test", role: "editor" }, { status: 201 });
    const token = String(invited.data.invitationToken);
    await request(anonymous, "/api/operator/accounts", "POST", { id: "editor-fixture", name: "Editor fixture identity", owner: { email: "dana@example.test", name: "Dana fixture", password, emailVerified: true }, testingCredits: 1 }, { status: 201, bearer: operator });
    await login(editor, "dana@example.test");
    const preview = await request(editor, `/invite/${token}`, "GET", undefined, { status: 200 });
    const csrf = preview.text.match(/name="csrfToken"\s+value="([^"]+)"/); assert(csrf); editor.csrf = csrf[1]!;
    await request(editor, `/invite/${token}`, "POST", { csrfToken: editor.csrf }, { status: 303, form: true });
    const session = await request(editor, "/api/session", "GET", undefined, { status: 200 }); editor.csrf = String(session.data.csrfToken);
    for (const [client, isOwner] of [[owner, true], [editor, false], [viewer, false]] as const) {
      const page = await request(client, "/app/accounts/alpha/status-page", "GET", undefined, { status: 200 });
      const actions = [...page.text.matchAll(/<form\b[^>]*\baction="([^"]+)"/g)].map(match => match[1]);
      assert.equal(actions.includes("/app/accounts/alpha/status-page"), isOwner);
    }
    await request(owner, "/app/accounts/alpha/team", "GET", undefined, { status: 200 });
    await request(viewer, "/app/accounts/alpha/team", "GET", undefined, { status: 403 });
    await request(editor, "/app/accounts/alpha/team", "GET", undefined, { status: 403 });
    await request(editor, "/api/accounts/alpha/status-page", "PUT", { revision: 0, slug: "editor-forbidden", title: "Forbidden", published: true, components: [] }, { status: 403 });
    await request(owner, "/api/public/status/editor-forbidden", "GET", undefined, { status: 404 });
  });
  await scenario("scoped API keys work without cookies but never escalate to team/owner actions", async () => {
    const created = await request(owner, "/api/accounts/alpha/api-keys", "POST", { name: "Read automation", scope: "read", expiresInDays: 1 }, { status: 201 });
    const token = String(created.data.apiKey);
    await request(anonymous, "/api/accounts/alpha/state", "GET", undefined, { status: 200, bearer: token });
    await request(anonymous, "/api/accounts/alpha/monitors/http/pause", "POST", { revision }, { status: 403, bearer: token });
    await request(anonymous, "/api/accounts/alpha/invitations", "POST", { username: "mallory@example.test", role: "owner" }, { status: 403, bearer: token });
    const list = await request(owner, "/api/accounts/alpha/api-keys", "GET", undefined, { status: 200 }); assert(!list.text.includes(token));
    const key = created.data.key;
    assert(key && typeof key === "object" && "id" in key && typeof key.id === "string");
    const id = key.id;
    await request(owner, `/api/accounts/alpha/api-keys/${id}`, "DELETE", undefined, { status: 200 });
    await request(anonymous, "/api/accounts/alpha/state", "GET", undefined, { status: 401, bearer: token });
  });
  await scenario("heartbeat one-time secret rotation invalidates old token and preserves receipt dedupe", async () => {
    const created = await request(owner, "/api/accounts/alpha/monitors", "POST", { id: "pulse", name: "Nightly backup", check: { kind: "heartbeat", graceMs: 0 }, intervalMs: 60000 }, { status: 201 });
    const token = String(created.data.heartbeatToken);
    const monitor = created.data.monitor as MonitorView;
    const instructions = await request(owner, "/api/accounts/alpha/monitors/pulse/heartbeat-instructions", "GET", undefined, { status: 200 }); assert(!instructions.text.includes(token));
    const rotated = await request(owner, "/api/accounts/alpha/monitors/pulse/heartbeat-token", "POST", { revision: monitor.revision }, { status: 200 });
    const next = String(rotated.data.heartbeatToken); assert.notEqual(next, token);
    const rejected = await runtime!.fetch(`${origin}/heartbeat/alpha/pulse`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Idempotency-Key": "old" } }); assert.equal(rejected.status, 401);
    for (const duplicate of [false, true]) {
      const receipt = await runtime!.fetch(`${origin}/heartbeat/alpha/pulse`, { method: "POST", headers: { Authorization: `Bearer ${next}`, "Idempotency-Key": "current" } });
      assert.equal(receipt.status, 200);
      const data: unknown = await receipt.json();
      assert(data && typeof data === "object" && "duplicate" in data);
      assert.equal(data.duplicate, duplicate);
    }
  });
  await scenario("explicit webhook test is durable and actually delivered through real native queue transport", async () => {
    const before = fixtures!.receipts.length;
    const monitor = (await request(owner, "/api/accounts/alpha/monitors/http", "GET", undefined, { status: 200 })).data.monitor as MonitorView;
    await request(owner, "/api/accounts/alpha/monitors/http/notification-test", "POST", { revision: monitor.revision }, { status: 200 });
    const deadline = Date.now() + 15000;
    let delivered = false;
    while (Date.now() < deadline) {
      const records = await request(owner, "/api/accounts/alpha/notifications", "GET", undefined, { status: 200 });
      delivered = (records.data.notifications as { type: string; status: string }[]).some(item => item.type === "test" && item.status === "delivered");
      if (delivered) break; await sleep(100);
    }
    assert(delivered, "Native queue must persist actual successful recipient response"); assert(fixtures!.receipts.length > before);
    const receipt = fixtures!.receipts.find(item => {
      const data: unknown = JSON.parse(item.body);
      return data && typeof data === "object" && "type" in data && data.type === "test";
    });
    assert(receipt);
    const timestamp = receipt.headers["x-tomato-timestamp"];
    assert.equal(typeof timestamp, "string");
    assert.equal(receipt.headers["x-tomato-signature"], createHmac("sha256", webhookSecret).update(`${timestamp}.${receipt.body}`).digest("hex"), "Actual webhook signing must use the decrypted persisted credential");
    const persisted = await runtime!.database.transaction("alpha", tx => tx.query<{ data: string }>("SELECT data FROM engine.notifications WHERE account_id=$1", ["alpha"]));
    assert(persisted.length > 0);
    assert(persisted.every(row => !row.data.includes(webhookSecret)), "Notification credentials must remain absent from plaintext PostgreSQL records");
  });
  await scenario("unconfigured email is explicit failure and cannot claim delivery", async () => {
    await request(owner, "/api/accounts/alpha/monitors", "POST", { id: "email", name: "Email monitor", check: { kind: "heartbeat" }, intervalMs: 60000, email: { address: "test@example.invalid" } }, { status: 503 });
    await request(owner, "/app/accounts/alpha/settings", "GET", undefined, { status: 200 });
  });
  await scenario("opt-in public status never leaks targets/secrets and unpublish takes effect immediately", async () => {
    await request(anonymous, "/api/public/status/alpha-status", "GET", undefined, { status: 404 });
    await request(viewer, "/api/accounts/alpha/status-page", "PUT", { revision: 0, slug: "alpha-status", title: "Alpha", published: true, components: [{ monitorId: "http", label: "API" }] }, { status: 403 });
    fixtures!.set("public-incident", "down");
    const target = new URL(fixtures!.httpUrl); target.pathname = "/public-incident";
    await request(owner, "/api/accounts/alpha/monitors", "POST", { id: "public-incident", name: "Private incident target", check: { kind: "http", url: target.href }, intervalMs: 1000, confirmationDelayMs: 100 }, { status: 201 });
    const deadline = Date.now() + 15000; let incidentMonitor: MonitorView | undefined;
    while (Date.now() < deadline) { const current = await request(owner, "/api/accounts/alpha/monitors/public-incident", "GET", undefined, { status: 200 }); incidentMonitor = current.data.monitor as MonitorView; if (incidentMonitor.state === "DOWN" && incidentMonitor.incidentId) break; await sleep(100); }
    assert(incidentMonitor?.state === "DOWN" && incidentMonitor.incidentId, "Public updates require an actual native confirmed incident");
    const unpublished = (await request(owner, "/api/accounts/alpha/status-page", "GET", undefined, { status: 200 })).data as { revision: number };
    const configuration = { revision: unpublished.revision, slug: "alpha-status", title: "Alpha status", published: true, components: [{ monitorId: "http", label: "API" }, { monitorId: "public-incident", label: "Incident service" }] };
    await request(owner, "/api/accounts/alpha/status-page", "PUT", configuration, { status: 200 });
    const configured = (await request(owner, "/api/accounts/alpha/status-page", "GET", undefined, { status: 200 })).data.page as { revision: number };
    await request(owner, "/api/accounts/alpha/status-page", "PUT", { ...configuration, title: "Stale publication" }, { status: 409 });
    assert.deepEqual((await request(owner, "/api/accounts/alpha/status-page", "GET", undefined, { status: 200 })).data.page, configured, "Stale publication must preserve page and components");
    const page = await request(anonymous, "/api/public/status/alpha-status", "GET", undefined, { status: 200 });
    assert(!page.text.includes(fixtures!.httpUrl)); assert(!page.text.includes(headerSecret)); assert(!page.text.includes(webhookSecret)); assert(!page.text.includes("monitorId")); assert(!page.text.includes("webhook"));
    const html = await request(anonymous, "/status/alpha-status", "GET", undefined, { status: 200 }); assert(html.text.includes("Alpha status"));
    const body = "Published customer-safe incident update";
    await request(owner, "/app/accounts/alpha/status-page/updates", "POST", { csrfToken: owner.csrf, revision: String(configured.revision), incidentId: incidentMonitor.incidentId, body }, { status: 303, form: true });
    assert((await request(anonymous, "/api/public/status/alpha-status", "GET", undefined, { status: 200 })).text.includes(body));
    assert((await request(anonymous, "/status/alpha-status", "GET", undefined, { status: 200 })).text.includes(body));
    const management = await request(owner, "/app/accounts/alpha/status-page", "GET", undefined, { status: 200 });
    const removal = management.text.match(/<form\b[^>]*\baction="\/app\/accounts\/alpha\/status-page\/updates\/remove"[^>]*>([\s\S]*?)<\/form>/); assert(removal);
    const updateId = removal[1]!.match(/name="updateId"\s+value="([^"]+)"/), csrf = removal[1]!.match(/name="csrfToken"\s+value="([^"]+)"/), revision = removal[1]!.match(/name="revision"\s+value="([^"]+)"/); assert(updateId && csrf && revision, "Native remove form must disclose its real update identifier, revision and CSRF");
    await request(owner, "/app/accounts/alpha/status-page/updates/remove", "POST", { csrfToken: csrf[1], updateId: updateId[1], revision: String(Number(revision[1]) - 1) }, { status: 409, form: true });
    assert((await request(anonymous, "/api/public/status/alpha-status", "GET", undefined, { status: 200 })).text.includes(body), "Stale native removal must preserve the public update");
    await request(owner, "/app/accounts/alpha/status-page/updates/remove", "POST", { csrfToken: csrf[1], updateId: updateId[1], revision: revision[1] }, { status: 303, form: true });
    assert(!(await request(anonymous, "/api/public/status/alpha-status", "GET", undefined, { status: 200 })).text.includes(body)); assert(!(await request(anonymous, "/status/alpha-status", "GET", undefined, { status: 200 })).text.includes(body));
    const afterRemoval = (await request(owner, "/api/accounts/alpha/status-page", "GET", undefined, { status: 200 })).data.page as { revision: number };
    const second = await request(owner, "/api/accounts/alpha/status-page/updates", "POST", { revision: afterRemoval.revision, incidentId: incidentMonitor.incidentId, body }, { status: 201 });
    const update = second.data.update as { id: string };
    const withUpdate = (await request(owner, "/api/accounts/alpha/status-page", "GET", undefined, { status: 200 })).data.page as { revision: number };
    await request(owner, `/api/accounts/alpha/status-page/updates/${update.id}`, "DELETE", { revision: withUpdate.revision }, { status: 200 });
    assert(!(await request(anonymous, "/api/public/status/alpha-status", "GET", undefined, { status: 200 })).text.includes(body));
    await request(owner, "/api/accounts/alpha/monitors/public-incident/pause", "POST", { revision: incidentMonitor.revision }, { status: 200 });
    const beforeUnpublish = (await request(owner, "/api/accounts/alpha/status-page", "GET", undefined, { status: 200 })).data.page as { revision: number };
    await request(owner, "/api/accounts/alpha/status-page", "DELETE", { revision: beforeUnpublish.revision }, { status: 200 });
    await request(anonymous, "/api/public/status/alpha-status", "GET", undefined, { status: 404 });
  });
  await scenario("real export omission safety and atomic import rejection are exposed through management API", async () => {
    const exported = await request(owner, "/api/accounts/alpha/export", "GET", undefined, { status: 200 });
    assert(!exported.text.includes(headerSecret)); assert(!exported.text.includes(webhookSecret)); assert.equal(exported.data.secretOmissions, true);
    await request(owner, "/api/accounts/alpha/monitors/import", "POST", { version: 99, monitors: [{ id: "import-version", name: "Unsupported", check: { kind: "heartbeat" }, intervalMs: 60000 }] }, { status: 400 });
    await request(owner, "/api/accounts/alpha/monitors/import-version", "GET", undefined, { status: 404 });
    await request(owner, "/api/accounts/alpha/monitors/import", "POST", { version: 1, monitors: [{ id: "import-good", name: "Imported", check: { kind: "heartbeat" }, intervalMs: 60000 }, { id: "import-bad", name: "Bad", check: { kind: "invented" }, intervalMs: 60000 }] }, { status: 400 });
    await request(owner, "/api/accounts/alpha/monitors/import-good", "GET", undefined, { status: 404 });
    const imported = await request(owner, "/app/accounts/alpha/monitors/import", "POST", { csrfToken: owner.csrf, configuration: JSON.stringify({ version: 1, monitors: [{ id: "import-pulse", name: "Imported backup", check: { kind: "heartbeat" }, intervalMs: 60000, paused: true }] }) }, { status: 200, form: true });
    const importedToken = imported.text.match(/<pre\b[^>]*\bdata-secret[^>]*>([a-f0-9-]{72})<\/pre>/);
    assert(importedToken, "Real import response must disclose its newly generated heartbeat credential once");
    const paused = await runtime!.fetch(`${origin}/heartbeat/alpha/import-pulse`, { method: "POST", headers: { Authorization: `Bearer ${importedToken[1]}`, "Idempotency-Key": "import-proof" } }); assert.equal(paused.status, 409);
    await request(owner, "/api/accounts/alpha/monitors/import-pulse/resume", "POST", { revision: 1 }, { status: 200 });
    const accepted = await runtime!.fetch(`${origin}/heartbeat/alpha/import-pulse`, { method: "POST", headers: { Authorization: `Bearer ${importedToken[1]}`, "Idempotency-Key": "import-proof" } });
    assert.equal(accepted.status, 200, "Imported one-time heartbeat instructions must actually authenticate ingestion");
  });
  await scenario("funded paused imports do not execute, reserve, charge or notify; explicit resume produces real first observations", async () => {
    const client: Client = { cookies: new Map(), csrf: "" };
    await request(anonymous, "/api/operator/accounts", "POST", { id: "paused-import", name: "Paused import proof", owner: { email: "paused-owner@example.test", name: "Paused owner fixture", password, emailVerified: true }, testingCredits: 100 }, { status: 201, bearer: operator });
    await login(client, "paused-owner@example.test");
    const target = new URL(fixtures!.httpUrl); target.pathname = "/paused-import-outbound";
    await request(client, "/api/accounts/paused-import/monitors/import", "POST", { version: 1, monitors: [{ id: "outbound", check: { kind: "http", url: target.href }, paused: true, state: "UP", lastObservedAt: Date.now() }] }, { status: 400 });
    await request(client, "/api/accounts/paused-import/monitors/outbound", "GET", undefined, { status: 404 });
    const imported = await request(client, "/api/accounts/paused-import/monitors/import", "POST", { version: 1, monitors: [{ id: "outbound", name: "Paused HTTP", check: { kind: "http", url: target.href, contains: "TOMATOOK" }, intervalMs: 1000, paused: true, webhook: { url: fixtures!.webhookUrl, secret: webhookSecret } }, { id: "heartbeat", name: "Paused heartbeat", check: { kind: "heartbeat" }, intervalMs: 1000, paused: true }] }, { status: 201 });
    const importedRows = imported.data.monitors as { monitor: MonitorView; heartbeatToken?: string }[];
    assert(importedRows.every(row => row.monitor.state === "PAUSED" && row.monitor.lastObservedAt === null && row.monitor.incidentId === null));
    const heartbeat = importedRows.find(row => row.monitor.id === "heartbeat"); assert(heartbeat?.heartbeatToken);
    const pulse = await runtime!.fetch(`${origin}/heartbeat/paused-import/heartbeat`, { method: "POST", headers: { Authorization: `Bearer ${heartbeat.heartbeatToken}`, "Idempotency-Key": "paused-pulse" } }); assert.equal(pulse.status, 409);
    await request(anonymous, "/v1/accounts/paused-import/tick", "POST", {}, { status: 200, bearer: operator });
    await sleep(1200);
    const before = await request(client, "/api/accounts/paused-import/state", "GET", undefined, { status: 200 });
    assert.equal(before.data.balance, 100); assert.equal(before.data.usage, 0); assert.equal(before.data.reserved, 0); assert.equal((before.data.jobs as unknown[]).length, 0); assert.equal((before.data.notifications as unknown[]).length, 0); assert.equal((before.data.observations as unknown[]).length, 0);
    assert.equal(fixtures!.hits.get("paused-import-outbound") ?? 0, 0);
    await request(client, "/api/accounts/paused-import/monitors/outbound/resume", "POST", { revision: 1 }, { status: 200 });
    const deadline = Date.now() + 15000; let observed: MonitorView | undefined;
    while (Date.now() < deadline) { const current = await request(client, "/api/accounts/paused-import/monitors/outbound", "GET", undefined, { status: 200 }); observed = current.data.monitor as MonitorView; if (observed.state === "UP" && observed.lastObservedAt !== null) break; await sleep(100); }
    assert(observed?.state === "UP" && observed.lastObservedAt !== null, "Actual native queue must create the first observation only after resume"); assert((fixtures!.hits.get("paused-import-outbound") ?? 0) > 0);
    await request(client, "/api/accounts/paused-import/monitors/outbound/pause", "POST", { revision: observed.revision }, { status: 200 });
    await request(client, "/api/accounts/paused-import/monitors/heartbeat/resume", "POST", { revision: 1 }, { status: 200 });
    const accepted = await runtime!.fetch(`${origin}/heartbeat/paused-import/heartbeat`, { method: "POST", headers: { Authorization: `Bearer ${heartbeat.heartbeatToken}`, "Idempotency-Key": "paused-pulse" } }); assert.equal(accepted.status, 200);
    const actual = await request(client, "/api/accounts/paused-import/monitors/heartbeat", "GET", undefined, { status: 200 }); assert.equal((actual.data.monitor as MonitorView).state, "UP");
    await request(client, "/api/accounts/paused-import/monitors/heartbeat/pause", "POST", { revision: 2 }, { status: 200 });
  });
  await scenario("audits contain real consequential events and revoked sessions fail immediately", async () => {
    const audit = await request(owner, "/api/accounts/alpha/audit", "GET", undefined, { status: 200 });
    assert((audit.data.entries as { action: string }[]).some(entry => entry.action === "monitor.create")); assert(!audit.text.includes(password)); assert(!audit.text.includes(headerSecret));
    const sessions = await request(owner, "/api/auth/sessions", "GET", undefined, { status: 200 }); assert((sessions.data.sessions as unknown[]).length >= 1);
    await request(owner, "/api/auth/logout", "POST", {}, { status: 200 });
    await request(owner, "/api/session", "GET", undefined, { status: 401 });
  });
  console.log(`PASS application verification: ${passed} scenarios; actual SSR/JSON clients + Node/PostgreSQL/outbox`);
} finally { await runtime?.close(); }
