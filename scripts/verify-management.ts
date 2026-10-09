import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { createProductionTestRuntime, type ProductionTestRuntime } from "./production-test-runtime.ts";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Fixtures } from "./fixtures.ts";
import { runMcpSmoke } from "./verify-mcp.ts";
import type { ApiKeyView, AuditView, AvailabilityReport, MaintenanceWindow, SessionView } from "../src/product-types.ts";
import type { MonitorView, EngineSnapshot, Incident, NotificationView } from "../src/types.ts";

const password = randomBytes(24).toString("hex");
const hookSecret = randomBytes(24).toString("hex");
let origin: string;
const accountId = "alpha";
let runtime: ProductionTestRuntime | undefined;
let fixtures: Fixtures | undefined;
let operator: string;
let endpoint: URL;
let passed = 0;
let rpcId = 0;
interface NativeClient { cookies: Map<string, string>; csrf: string }
interface AgentClient { client: Client; transport: StreamableHTTPClientTransport; key: string; view: ApiKeyView }
const native = (): NativeClient => ({ cookies: new Map(), csrf: "" });
const anonymous = native(), owner = native(), viewer = native(), editor = native();
const agents: AgentClient[] = [];

async function request(client: NativeClient, route: string, method = "GET", value?: unknown, status = 200, bearer?: string, form = false) {
  const headers: Record<string, string> = {};
  if (client.cookies.size) headers.Cookie = [...client.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (method !== "GET") { headers.Origin = origin; headers["X-CSRF-Token"] = client.csrf; }
  const payload = value === undefined ? undefined : form ? new URLSearchParams(value as Record<string, string>).toString() : JSON.stringify(value);
  if (payload !== undefined) headers["Content-Type"] = form ? "application/x-www-form-urlencoded" : "application/json";
  const response = await runtime!.fetch(`${origin}${route}`, { method, headers, redirect: "manual", ...(payload === undefined ? {} : { body: payload }) });
  for (const cookie of response.headers.getSetCookie()) {
    const first = cookie.split(";", 1)[0]!, split = first.indexOf("="), name = first.slice(0, split), value = first.slice(split + 1);
    if (value) client.cookies.set(name, value); else client.cookies.delete(name);
  }
  const text = await response.text();
  assert.equal(response.status, status, `${method} ${route}: unexpected status ${response.status}`);
  return { response, text, data: response.headers.get("Content-Type")?.includes("application/json") ? JSON.parse(text) as Record<string, unknown> : {} };
}
async function login(client: NativeClient, email: string, value = password): Promise<void> {
  client.csrf = String((await request(client, "/api/auth/login")).data.csrfToken);
  await request(client, "/api/auth/login", "POST", { email, password: value, csrfToken: client.csrf });
  client.csrf = String((await request(client, "/api/session")).data.csrfToken);
  assert(client.cookies.has("tomato-session"));
}
async function invite(client: NativeClient, username: string, role: "viewer" | "editor"): Promise<void> {
  const result = await request(owner, `/api/accounts/${accountId}/invitations`, "POST", { username, role }, 201);
  await request(anonymous, "/api/operator/accounts", "POST", { id: `fixture-${role}`, name: `${role} fixture identity`, owner: { email: username, name: `${role} fixture`, password, emailVerified: true }, testingCredits: 1 }, 201, operator);
  await login(client, username);
  const route = `/invite/${result.data.invitationToken}`;
  const preview = await request(client, route);
  const csrf = preview.text.match(/name="csrfToken"\s+value="([^"]+)"/); assert(csrf);
  client.csrf = csrf[1]!;
  await request(client, route, "POST", { csrfToken: client.csrf }, 303, undefined, true);
  client.csrf = String((await request(client, "/api/session")).data.csrfToken);
}
async function issue(client: NativeClient, scope: "read" | "write" | "manage", name: string, account = accountId): Promise<{ key: ApiKeyView; apiKey: string }> {
  const result = await request(client, `/api/accounts/${account}/api-keys`, "POST", { name, scope, expiresInDays: 90 }, 201);
  return result.data as unknown as { key: ApiKeyView; apiKey: string };
}
async function connect(issued: { key: ApiKeyView; apiKey: string }): Promise<AgentClient> {
  const client = new Client({ name: "tomato-management-acceptance", version: "0.1.0" }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(endpoint, { requestInit: { headers: { Authorization: `Bearer ${issued.apiKey}` }, credentials: "omit", redirect: "error" } });
  const agent = { client, transport, key: issued.apiKey, view: issued.key }; agents.push(agent);
  await client.connect(transport, { timeout: 15000 });
  assert.equal(transport.protocolVersion, "2025-11-25"); assert(transport.sessionId);
  return agent;
}
async function tool<T = Record<string, unknown>>(agent: AgentClient, name: string, args: Record<string, unknown> = {}, expectedStatus?: number, account = accountId): Promise<T> {
  const result = await agent.client.callTool({ name: `tomato.${name}`, arguments: { accountId: account, ...args } }, undefined, { timeout: 15000 });
  const data = result.structuredContent as Record<string, unknown> | undefined;
  assert(data, `${name} must return structured consumer data`);
  if (expectedStatus === undefined) assert.notEqual(result.isError, true, `${name}: ${String(data.error ?? "tool failed")}`);
  else { assert.equal(result.isError, true, `${name} must reject`); assert.equal(data.status, expectedStatus, `${name} rejection status`); }
  return data as T;
}
async function globalTool<T = Record<string, unknown>>(agent: AgentClient, name: string, expectedStatus?: number): Promise<T> {
  const result = await agent.client.callTool({ name: `tomato.${name}`, arguments: {} }, undefined, { timeout: 15000 });
  assert(result.structuredContent);
  if (expectedStatus === undefined) assert.notEqual(result.isError, true);
  else { assert.equal(result.isError, true); assert.equal((result.structuredContent as Record<string, unknown>).status, expectedStatus); }
  return result.structuredContent as T;
}
async function monitor(agent: AgentClient, id: string, account = accountId): Promise<MonitorView> { return (await tool<{ monitor: MonitorView }>(agent, "monitor.get", { monitorId: id }, undefined, account)).monitor; }
async function tick(account = accountId): Promise<void> { await request(anonymous, `/v1/accounts/${account}/tick`, "POST", {}, 200, operator); }
async function pulse(account: string, id: string, token: string, receipt: string, status = 200): Promise<Record<string, unknown>> {
  const response = await runtime!.fetch(`${origin}/heartbeat/${account}/${id}`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Idempotency-Key": receipt } });
  assert.equal(response.status, status, "Heartbeat ingestion status"); return await response.json() as Record<string, unknown>;
}
async function eventually<T>(label: string, read: () => Promise<T>, accepts: (value: T) => boolean, timeout = 20000): Promise<T> {
  const deadline = Date.now() + timeout;
  while (true) { const value = await read(); if (accepts(value)) return value; assert(Date.now() < deadline, label); await sleep(500); }
}
async function scenario(label: string, run: () => Promise<void>): Promise<void> { await run(); passed++; console.log(`PASS ${label}`); }
async function rpc(key: string, method: string, params: Record<string, unknown> = {}, session?: string, notification = false): Promise<Response> {
  return fetch(endpoint, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...(session ? { "MCP-Session-Id": session, "MCP-Protocol-Version": "2025-11-25" } : {}) }, body: JSON.stringify({ jsonrpc: "2.0", ...(notification ? {} : { id: ++rpcId }), method, params }) });
}

try {
  runtime = await createProductionTestRuntime();
  fixtures = runtime.fixtures;
  origin = runtime.baseUrl;
  operator = runtime.token;
  endpoint = new URL("/mcp", origin);

  await scenario("native provisioning, invitation acceptance and one-time scoped credentials are real", async () => {
    await request(anonymous, "/api/operator/accounts", "POST", { id: accountId, name: "Alpha", owner: { email: "alice@example.test", name: "Alice fixture", password, emailVerified: true }, testingCredits: 10000 }, 201, operator);
    await request(anonymous, "/api/operator/accounts", "POST", { id: "beta", name: "Beta", owner: { email: "bob@example.test", name: "Bob fixture", password, emailVerified: true }, testingCredits: 100 }, 201, operator);
    await login(owner, "alice@example.test"); await invite(viewer, "carol@example.test", "viewer"); await invite(editor, "dana@example.test", "editor");
    await request(viewer, `/api/accounts/${accountId}/api-keys`, "POST", { name: "viewer-write", scope: "write" }, 403);
  });
  const ownerRead = await connect(await issue(owner, "read", "owner-read"));
  const ownerWrite = await connect(await issue(owner, "write", "owner-write"));
  const ownerManage = await connect(await issue(owner, "manage", "owner-manage"));
  await connect(await issue(editor, "read", "editor-read"));
  const editorWrite = await connect(await issue(editor, "write", "editor-write"));
  const editorManage = await connect(await issue(editor, "manage", "editor-manage"));
  const viewerRead = await connect(await issue(viewer, "read", "viewer-read"));
  const viewerManage = await connect(await issue(viewer, "manage", "viewer-manage"));

  await scenario("installed SDK interoperates through genuine remote HTTP and spawned stdio", async () => {
    const evidence = await runMcpSmoke(endpoint, ownerManage.key, ownerRead.key);
    assert(evidence.http.sessionCreated && evidence.http.readSucceeded && evidence.stdio.readSucceeded);
    await request(owner, `/api/accounts/${accountId}/monitors/stdio-scope-denied`, "GET", undefined, 404);
  });
  await scenario("all valid owner/editor/viewer scope combinations execute reads and enforce both ceilings", async () => {
    for (const agent of agents) {
      const workspaces = await globalTool<{ accounts: { id: string }[] }>(agent, "workspaces.list"); assert.deepEqual(workspaces.accounts.map(item => item.id), [accountId]);
      const workspace = await tool<{ account: { role: string; id: string } }>(agent, "workspace.get"); assert.equal(workspace.account.id, accountId);
      await tool(agent, "workspace.get", {}, 404, "beta");
      await tool(agent, "monitors.list"); await tool(agent, "members.list"); await tool(agent, "usage.get");
      if (agent.view.scope === "read") await tool(agent, "monitor.create", { id: `forbidden-${agent.view.id}`, check: { kind: "heartbeat" }, paused: true }, 403);
      if (agent.view.scope !== "manage") await tool(agent, "key.create", { name: "cannot-delegate", scope: "read" }, 403);
      if (workspace.account.role !== "owner") await tool(agent, "workspace.rename", { name: "Unauthorized rename" }, 403);
    }
    await tool(viewerManage, "monitor.create", { id: "viewer-forbidden", check: { kind: "heartbeat" }, paused: true }, 403);
    await tool(editorManage, "notification_defaults.set", { revision: 0 }, 403);
    const renamed = await tool<{ account: { name: string } }>(ownerManage, "workspace.rename", { name: "  Managed Alpha  " }); assert.equal(renamed.account.name, "Managed Alpha");
    await tool(ownerManage, "workspace.rename", { name: "   " }, 400);
    const capabilities = await globalTool<{ payments: boolean; commercialSignup: boolean }>(ownerRead, "capabilities.get"); assert.equal(capabilities.payments, false); assert.equal(capabilities.commercialSignup, false);
  });
  await scenario("source scope/expiry, exact delegation boundary, self-revocation and secret omission hold", async () => {
    const delegated = await tool<{ key: ApiKeyView; apiKey: string }>(ownerManage, "key.create", { name: "exact-ceiling", scope: "manage", expiresAt: ownerManage.view.expiresAt });
    assert.equal(delegated.key.expiresAt, ownerManage.view.expiresAt);
    await tool(ownerManage, "key.create", { name: "too-long", scope: "read", expiresAt: ownerManage.view.expiresAt + 1 }, 403);
    await tool(ownerManage, "key.create", { name: "invalid-days", scope: "read", expiresInDays: 91 }, 400);
    const shortIssued = await tool<{ key: ApiKeyView; apiKey: string }>(ownerManage, "key.create", { name: "short-source", scope: "manage", expiresAt: Date.now() + 300000 });
    const shortSource = await connect(shortIssued);
    const minimalChild = await tool<{ key: ApiKeyView; apiKey: string }>(shortSource, "key.create", { name: "minimal-name-scope", scope: "read" });
    assert.equal(minimalChild.key.expiresAt, shortSource.view.expiresAt, "Omitted expiry must cap the default at source expiry");
    const boundedSession = await runtime!.database.query<{ expires_at: number }>("SELECT expires_at FROM identity.mcp_sessions WHERE id=$1", [shortSource.transport.sessionId!]); assert.equal(boundedSession[0]!.expires_at, shortSource.view.expiresAt);
    await tool(viewerManage, "key.create", { name: "viewer-write", scope: "write", expiresAt: viewerManage.view.expiresAt }, 403);
    const viewerChild = await tool<{ key: ApiKeyView; apiKey: string }>(viewerManage, "key.create", { name: "own-security", scope: "manage", expiresAt: viewerManage.view.expiresAt });
    await tool(viewerManage, "key.revoke", { keyId: viewerChild.key.id });
    const child = await connect(delegated);
    const keys = await tool<{ keys: ApiKeyView[] }>(ownerManage, "keys.list"); assert(keys.keys.some(key => key.id === child.view.id)); assert(!JSON.stringify(keys).includes(child.key));
    await tool(child, "key.revoke", { keyId: child.view.id });
    await request(anonymous, `/api/accounts/${accountId}/workspace`, "GET", undefined, 401, child.key);
    await tool(ownerManage, "key.revoke", { keyId: editorManage.view.id }, 404);
    const principal = (await request(owner, "/api/session")).data;
    const actor = principal.actor;
    assert(actor && typeof actor === "object" && "id" in actor && typeof actor.id === "string");
    // This deliberately crosses only the trusted internal delegation boundary; it does not replace the public SDK smoke.
    const stub = runtime!.env.identity;
    for (const source of [ownerRead, ownerWrite]) {
      const response = await stub.fetch(new Request("https://identity.internal/api-keys/create", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actorId: actor.id, accountId, name: "internal-escalation", sourceKeyId: source.view.id, scope: "manage", expiresAt: source.view.expiresAt }) })); assert.equal(response.status, 403);
      const narrowed = await stub.fetch(new Request("https://identity.internal/api-keys/create", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actorId: actor.id, accountId, name: "internal-valid-read", sourceKeyId: source.view.id, scope: "read", expiresAt: source.view.expiresAt }) })); assert.equal(narrowed.status, 200);
    }
    const wrongUser = await stub.fetch(new Request("https://identity.internal/api-keys/create", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actorId: actor.id, accountId, name: "other-user-source", sourceKeyId: viewerManage.view.id, scope: "read", expiresAt: viewerManage.view.expiresAt }) })); assert.equal(wrongUser.status, 401);
    const betaOwner = native(); await login(betaOwner, "bob@example.test");
    const betaSession = (await request(betaOwner, "/api/session")).data, betaActor = betaSession.actor;
    assert(betaActor && typeof betaActor === "object" && "id" in betaActor && typeof betaActor.id === "string");
    const wrongAccount = await stub.fetch(new Request("https://identity.internal/api-keys/create", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actorId: betaActor.id, accountId: "beta", name: "other-account-source", sourceKeyId: ownerManage.view.id, scope: "read", expiresAt: ownerManage.view.expiresAt }) })); assert.equal(wrongAccount.status, 401);
    const expired = await tool<{ key: ApiKeyView; apiKey: string }>(ownerManage, "key.create", { name: "expired-source", scope: "manage", expiresAt: Date.now() + 1000 });
    await runtime!.database.query("UPDATE identity.api_keys SET expires_at=$1 WHERE id=$2", [Date.now() - 1, expired.key.id]);
    await request(anonymous, `/api/accounts/${accountId}/workspace`, "GET", undefined, 401, expired.apiKey);
    const rejected = await stub.fetch(new Request("https://identity.internal/api-keys/create", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actorId: actor.id, accountId, name: "expired-delegation", sourceKeyId: expired.key.id, scope: "read", expiresAt: Date.now() + 500 }) })); assert.equal(rejected.status, 401);
  });
  await scenario("revoking a delegated parent invalidates its child and grandchild but not unrelated keys", async () => {
    const parent = await connect(await issue(owner, "manage", "cascade-parent"));
    const childIssued = await tool<{ key: ApiKeyView; apiKey: string }>(parent, "key.create", { name: "cascade-child", scope: "manage", expiresAt: Date.now() + 300000 });
    assert.equal(childIssued.key.parentKeyId, parent.view.id);
    const child = await connect(childIssued);
    const grandchildIssued = await tool<{ key: ApiKeyView; apiKey: string }>(child, "key.create", { name: "cascade-grandchild", scope: "read" });
    assert.equal(grandchildIssued.key.parentKeyId, child.view.id); assert.equal(grandchildIssued.key.expiresAt, child.view.expiresAt);
    const grandchild = await connect(grandchildIssued);
    for (const agent of [parent, child, grandchild]) {
      const workspaces = await globalTool<{ accounts: { id: string }[] }>(agent, "workspaces.list"); assert.deepEqual(workspaces.accounts.map(value => value.id), [accountId]);
    }
    await tool(child, "key.create", { name: "chain-too-long", scope: "read", expiresAt: child.view.expiresAt + 1 }, 403);
    await tool(grandchild, "key.create", { name: "chain-scope-escalation", scope: "manage" }, 403);
    await tool(ownerManage, "key.revoke", { keyId: parent.view.id });
    for (const revoked of [parent, child, grandchild]) {
      await assert.rejects(revoked.client.callTool({ name: "tomato.workspaces.list", arguments: {} }, undefined, { timeout: 15000 }), error => error instanceof StreamableHTTPError && error.code === 401, "The actual SDK must see revoked cascade credentials as HTTP401");
      await request(anonymous, `/api/accounts/${accountId}/workspace`, "GET", undefined, 401, revoked.key);
    }
    const sibling = await globalTool<{ accounts: { id: string }[] }>(ownerRead, "workspaces.list"); assert.deepEqual(sibling.accounts.map(value => value.id), [accountId]);
    const surviving = await tool<{ keys: ApiKeyView[] }>(ownerManage, "keys.list"); assert(surviving.keys.some(value => value.id === ownerRead.view.id));
    assert(!surviving.keys.some(value => [parent.view.id, child.view.id, grandchild.view.id].includes(value.id)), "Revoked descendants cannot remain active in the key list");
  });
  await scenario("legacy sessions bind bearer IDs, require initialized, persist TTL and delete genuinely", async () => {
    const initialized = await rpc(ownerManage.key, "initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "legacy-acceptance", version: "1" } }); assert.equal(initialized.status, 200);
    const id = initialized.headers.get("MCP-Session-Id"); assert(id);
    assert.equal((await rpc(ownerManage.key, "tools/list", {}, id)).status, 409);
    assert.equal((await rpc(ownerManage.key, "notifications/initialized", {}, id, true)).status, 202);
    assert.equal((await rpc(ownerRead.key, "tools/list", {}, id)).status, 404);
    assert.equal((await rpc(ownerManage.key, "tools/list", {}, id)).status, 200);
    const unknown = await rpc(ownerManage.key, "tools/call", { name: "tomato.not_real", arguments: {} }, id); assert.equal(unknown.status, 400);
    const unknownBody: unknown = await unknown.json(); assert(unknownBody && typeof unknownBody === "object" && "error" in unknownBody);
    const unknownError = unknownBody.error; assert(unknownError && typeof unknownError === "object" && "code" in unknownError); assert.equal(unknownError.code, -32602);
    const rows = await runtime!.database.query<{ expires_at: number; initialized: boolean; auth_binding: string }>("SELECT expires_at,initialized,auth_binding FROM identity.mcp_sessions WHERE id=$1", [id]);
    assert.equal(rows[0]!.auth_binding, ownerManage.view.id); assert.equal(rows[0]!.initialized, true); assert(rows[0]!.expires_at <= Date.now() + 3600000);
    await runtime!.database.query("UPDATE identity.mcp_sessions SET expires_at=$1 WHERE id=$2", [Date.now() - 1, id]);
    assert.equal((await rpc(ownerManage.key, "ping", {}, id)).status, 404);
    const second = await rpc(ownerManage.key, "initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "delete-acceptance", version: "1" } }); const secondId = second.headers.get("MCP-Session-Id"); assert(secondId);
    const deleted = await fetch(endpoint, { method: "DELETE", headers: { Authorization: `Bearer ${ownerManage.key}`, "MCP-Protocol-Version": "2025-11-25", "MCP-Session-Id": secondId } }); assert.equal(deleted.status, 204);
    assert.equal((await rpc(ownerManage.key, "ping", {}, secondId)).status, 404);
  });

  await scenario("URL-only defaults and all six check families have real usable DTOs", async () => {
    const quick = await tool<{ monitor: MonitorView }>(editorWrite, "monitor.create", { check: { kind: "http", url: `${fixtures!.httpUrl}/quick-defaults` }, paused: true });
    assert(quick.monitor.id); assert.equal(quick.monitor.name, "127.0.0.1"); assert.equal(quick.monitor.intervalMs, 60000); assert.equal(quick.monitor.timeoutMs, 5000);
    await tool(editorWrite, "monitor.delete", { monitorId: quick.monitor.id, revision: quick.monitor.revision });
    const checks = [
      { id: "family-http", check: { kind: "http", url: `${fixtures!.httpUrl}/family-http` } },
      { id: "family-dns", check: { kind: "dns", name: "dns-up.example.com", recordType: "A", expected: ["127.0.0.1"] } },
      { id: "family-websocket", check: { kind: "websocket", url: fixtures!.websocketUrl } },
      { id: "family-tcp", check: { kind: "tcp", hostname: "127.0.0.1", port: fixtures!.tcpPort } },
      { id: "family-tls", check: { kind: "tls", hostname: "127.0.0.1", port: fixtures!.tlsPort } },
      { id: "family-heartbeat", check: { kind: "heartbeat" } },
    ];
    for (const config of checks) { const created = await tool<{ monitor: MonitorView; heartbeatToken?: string }>(editorWrite, "monitor.create", { ...config, paused: true }); assert.equal(created.monitor.check.kind, config.check.kind); assert.equal(created.monitor.state, "PAUSED"); if (config.check.kind === "heartbeat") assert(created.heartbeatToken); }
    const edited = await tool<{ monitor: MonitorView }>(editorWrite, "monitor.update", { monitorId: "family-http", revision: 1, name: "Revision-fenced edit", headersMode: "replace", check: { kind: "http", url: `${fixtures!.httpUrl}/family-http`, headers: { Authorization: hookSecret } } });
    assert.equal(edited.monitor.revision, 2); assert(!JSON.stringify(edited).includes(hookSecret));
    await tool(editorWrite, "monitor.update", { monitorId: "family-http", revision: 1, name: "stale" }, 409);
    await tool(editorWrite, "monitor.update", { monitorId: "family-http", revision: 2, headersMode: "remove" });
    const exported = await tool<{ version: number; monitors: unknown[] }>(ownerRead, "monitors.export"); assert.equal(exported.version, 1); assert(exported.monitors.length >= 6); assert(!JSON.stringify(exported).includes(hookSecret));
    await tool(editorWrite, "monitors.import", { version: 1, monitors: [{ id: "atomic-import", check: { kind: "heartbeat" }, paused: true }, { id: "atomic-import", check: { kind: "heartbeat" }, paused: true }] }, 409);
    for (const property of ["constructor", "toString", "__proto__"]) {
      await tool(ownerRead, "workspace.get", Object.fromEntries([[property, "untrusted argument"]]), 400);
    }
    await tool(ownerRead, "monitor.get", { monitorId: "atomic-import" }, 404);
    const imported = await tool<{ importedCount: number; monitors: { monitor: MonitorView; heartbeatToken?: string }[] }>(editorWrite, "monitors.import", { version: 1, monitors: [{ id: "imported-heartbeat", check: { kind: "heartbeat" }, paused: true }] }); assert.equal(imported.importedCount, 1); assert(imported.monitors[0]!.heartbeatToken);
    await tool(editorWrite, "monitor.delete", { monitorId: "imported-heartbeat", revision: 1 });
  });
  await scenario("advertised six-family boundaries execute through MCP and REST; invalid/contextual inputs mutate nothing", async () => {
    const boundary = await connect(await issue(owner, "manage", "MCP schema boundaries"));
    const rest = await issue(owner, "manage", "REST schema boundaries");
    const tools = (await boundary.client.listTools()).tools;
    const advertised = tools.find(item => item.name === "tomato.monitor.create")!.inputSchema as unknown as { properties: { check: { oneOf: { required: string[]; properties: Record<string, { enum?: string[]; maximum?: number; maxItems?: number; items?: { maxLength?: number } }> }[] } } };
    const branch = (kind: string) => advertised.properties.check.oneOf.find(item => item.properties.kind!.enum!.includes(kind))!;
    const maximum = (kind: string, field: string) => branch(kind).properties[field]!.maximum!;
    const cadence = (await globalTool<{ limits: { minimumIntervalMs: number } }>(boundary, "capabilities.get")).limits.minimumIntervalMs;
    const durableState = async () => runtime!.database.transaction(accountId, async tx => {
      const rows = [
        await tx.query("SELECT * FROM engine.wallet WHERE account_id=$1 ORDER BY account_id", [accountId]),
        await tx.query("SELECT * FROM engine.monitors WHERE account_id=$1 ORDER BY id", [accountId]),
        await tx.query("SELECT * FROM engine.jobs WHERE account_id=$1 ORDER BY id", [accountId]),
        await tx.query("SELECT * FROM engine.coverage WHERE account_id=$1 ORDER BY monitor_id,started_at", [accountId]),
        await tx.query("SELECT * FROM engine.retired_monitors WHERE account_id=$1 ORDER BY id", [accountId]),
        await tx.query("SELECT * FROM engine.notifications WHERE account_id=$1 ORDER BY id", [accountId]),
        await tx.query("SELECT * FROM engine.incidents WHERE account_id=$1 ORDER BY id", [accountId]),
        await tx.query("SELECT * FROM engine.pulses WHERE account_id=$1 ORDER BY monitor_id,pulse_id", [accountId]),
        await tx.query("SELECT * FROM engine.freshness WHERE account_id=$1 ORDER BY monitor_id,observed_at", [accountId]),
        await tx.query("SELECT * FROM engine.outbox WHERE account_id=$1 ORDER BY id", [accountId]),
        await tx.query("SELECT * FROM engine.audit WHERE account_id=$1 ORDER BY id", [accountId]),
      ];
      return JSON.stringify(rows);
    });
    let ordinal = 0;
    const valid = async (check: Record<string, unknown>) => {
      for (const transport of ["mcp", "rest"] as const) {
        const id = `schema-${transport}-${++ordinal}`, input = { id, check, paused: true, intervalMs: cadence };
        const created = transport === "mcp"
          ? await tool<{ monitor: MonitorView }>(boundary, "monitor.create", input)
          : (await request(anonymous, `/api/accounts/${accountId}/monitors`, "POST", input, 201, rest.apiKey)).data as unknown as { monitor: MonitorView };
        assert.equal(created.monitor.state, "PAUSED");
        assert.equal(created.monitor.intervalMs, cadence);
        for (const [key, value] of Object.entries(check)) {
          if (key === "headers") { assert.equal(created.monitor.check.kind, "http"); if (created.monitor.check.kind === "http") assert.deepEqual(created.monitor.check.headerNames, Object.keys(value as object).map(name => name.toLowerCase()).sort()); }
          else assert.deepEqual((created.monitor.check as unknown as Record<string, unknown>)[key], value);
        }
        if (transport === "mcp") await tool(boundary, "monitor.delete", { monitorId: id, revision: created.monitor.revision });
        else await request(anonymous, `/api/accounts/${accountId}/monitors/${id}`, "DELETE", { revision: created.monitor.revision }, 200, rest.apiKey);
      }
    };
    const samples: Record<string, Record<string, unknown>> = {
      http: { kind: "http", url: `${fixtures!.httpUrl}/schema` },
      dns: { kind: "dns", name: "schema.example.com", recordType: "TXT" },
      websocket: { kind: "websocket", url: new URL(fixtures!.websocketUrl).href },
      tcp: { kind: "tcp", hostname: "127.0.0.1", port: fixtures!.tcpPort },
      tls: { kind: "tls", hostname: "127.0.0.1", port: fixtures!.tlsPort },
      heartbeat: { kind: "heartbeat" },
    };
    // Construct real calls from the advertised required fields: omitted DNS type/port cannot hide behind defaults.
    for (const [kind, values] of Object.entries(samples)) await valid(Object.fromEntries(branch(kind).required.map(key => [key, values[key]])));
    await valid({ ...samples.http, maxRedirects: maximum("http", "maxRedirects"), maxBodyBytes: maximum("http", "maxBodyBytes"), status: [100, 599], contains: "C".repeat(4096), headers: { X: "H".repeat(8191) } });
    await valid({ ...samples.http, headers: { X: "Valid\té\xff" } });
    const dnsExpected = ["", "é".repeat(512), ...Array.from({ length: branch("dns").properties.expected!.maxItems! - 2 }, (_, index) => `answer-${String(index).padStart(2, "0")}`)].sort();
    await valid({ ...samples.dns, expected: dnsExpected });
    for (const kind of ["websocket", "tcp", "tls"]) await valid({ ...samples[kind], [kind === "websocket" ? "maxMessageBytes" : "maxResponseBytes"]: maximum(kind, kind === "websocket" ? "maxMessageBytes" : "maxResponseBytes"), send: "S".repeat(4096), expect: "E".repeat(4096) });
    await valid({ ...samples.heartbeat, graceMs: maximum("heartbeat", "graceMs") });
    const invalid = [
      { ...samples.http, maxRedirects: 6 }, { ...samples.http, status: [] }, { ...samples.http, status: [99] }, { ...samples.http, status: [600] },
      { ...samples.http, headers: Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`X-${index}`, ""])) },
      { ...samples.http, headers: { "Invalid name": "" } }, { ...samples.http, headers: { X: "H".repeat(8192) } },
      { ...samples.http, headers: { X: "é".repeat(4096) } }, { ...samples.http, headers: { X: "", x: "" } },
      { ...samples.http, headers: { Host: "identity.example.com" } }, { ...samples.http, headers: { X: "\r\n" } }, { ...samples.http, method: "HEAD", contains: "x" },
      { ...samples.http, headers: { X: "\u0001" } }, { ...samples.http, headers: { X: "\u0100" } }, { ...samples.http, headers: { X: "\u007f" } },
      { kind: "dns", name: "schema.example.com" }, { ...samples.dns, expected: Array.from({ length: 33 }, (_, index) => String(index)) },
      { ...samples.dns, expected: ["D".repeat(1025)] }, { ...samples.dns, expected: ["é".repeat(513)] }, { ...samples.dns, resolverUrl: "https://untrusted.example.com/dns-query" },
      { ...samples.websocket, maxMessageBytes: 65537 }, { ...samples.websocket, maxMessageBytes: 1, send: "xx" }, { ...samples.websocket, send: "😀".repeat(1025) },
      { ...samples.tcp, maxResponseBytes: 65537 }, { ...samples.tcp, port: 0 }, { ...samples.tcp, port: 65536 }, { ...samples.tcp, maxResponseBytes: 1, expect: "xx" },
      { kind: "tcp", hostname: "127.0.0.1" }, { kind: "tls", hostname: "127.0.0.1" }, { ...samples.tls, maxResponseBytes: 65537 },
      { ...samples.heartbeat, graceMs: 604800001 }, { ...samples.heartbeat, graceMs: -1 },
    ];
    for (const check of invalid) {
      const before = await durableState(), input = { id: `schema-invalid-${++ordinal}`, check, paused: true };
      await tool(boundary, "monitor.create", input, 400);
      await request(anonymous, `/api/accounts/${accountId}/monitors`, "POST", input, 400, rest.apiKey);
      assert.equal(await durableState(), before, "Rejected MCP/REST create must not mutate monitors, jobs, credits or coverage");
    }
    const before = await durableState(), current = await monitor(boundary, "family-http");
    await tool(boundary, "monitor.update", { monitorId: current.id, revision: current.revision, check: { ...samples.http, maxRedirects: 6 } }, 400);
    await request(anonymous, `/api/accounts/${accountId}/monitors/${current.id}`, "PUT", { revision: current.revision, check: { ...samples.http, maxRedirects: 6 } }, 400, rest.apiKey);
    const monitors = [{ id: "schema-import-valid", check: { kind: "heartbeat" }, paused: true }, { id: "schema-import-invalid", check: { ...samples.dns, expected: ["é".repeat(513)] }, paused: true }];
    await tool(boundary, "monitors.import", { version: 1, monitors }, 400);
    await request(anonymous, `/api/accounts/${accountId}/monitors/import`, "POST", { version: 1, monitors }, 400, rest.apiKey);
    assert.equal(await durableState(), before, "Rejected update/atomic import must preserve authoritative account state");
    const page = { slug: `a${"b".repeat(61)}z`, title: "Schema boundary", published: false, components: [] };
    for (const transport of ["mcp", "rest"] as const) {
      const beforePage = await tool<{ revision: number }>(boundary, "status_page.get");
      const input = { ...page, revision: beforePage.revision };
      if (transport === "mcp") await tool(boundary, "status_page.configure", input);
      else await request(anonymous, `/api/accounts/${accountId}/status-page`, "PUT", input, 200, rest.apiKey);
      const configured = await tool<{ page: { slug: string; revision: number } }>(boundary, "status_page.get");
      assert.equal(configured.page.slug, page.slug);
      if (transport === "mcp") await tool(boundary, "status_page.configure", input, 409);
      else await request(anonymous, `/api/accounts/${accountId}/status-page`, "PUT", input, 409, rest.apiKey);
      assert.deepEqual(await tool(boundary, "status_page.get"), configured, "Stale page configuration must mutate nothing");
      await tool(boundary, "status_page.unpublish", { revision: configured.page.revision });
      const unchanged = await tool<{ revision: number; page: null }>(boundary, "status_page.get");
      assert.equal(unchanged.page, null);
      if (transport === "mcp") await tool(boundary, "status_page.configure", input, 409);
      else await request(anonymous, `/api/accounts/${accountId}/status-page`, "PUT", input, 409, rest.apiKey);
      assert.deepEqual(await tool(boundary, "status_page.get"), unchanged, "Deleted-page tombstones must reject pre-delete publication revisions");
      await tool(boundary, "status_page.unpublish", { revision: unchanged.revision - 1 }, 409);
      if (transport === "mcp") await tool(boundary, "status_page.configure", { ...page, revision: unchanged.revision, slug: "invalid-trailing-" }, 400);
      else await request(anonymous, `/api/accounts/${accountId}/status-page`, "PUT", { ...page, revision: unchanged.revision, slug: "invalid-trailing-" }, 400, rest.apiKey);
      assert.deepEqual(await tool(boundary, "status_page.get"), unchanged);
    }
  });
  await scenario("legal export/new IDs remain real monitors across MCP, REST and native detail/edit/pause; sibling export stays canonical", async () => {
    const agent = await connect(await issue(owner, "write", "Unrestricted monitor identifiers"));
    const ids = ["export", "new"];
    for (const id of ids) {
      const name = `Configured ${id}`;
      const created = await tool<{ monitor: MonitorView }>(agent, "monitor.create", { id, name, check: { kind: "heartbeat" }, paused: true });
      assert.equal(created.monitor.id, id);
      assert.equal((await monitor(agent, id)).name, name);
      const rest = await request(anonymous, `/api/accounts/${accountId}/monitors/${id}`, "GET", undefined, 200, agent.key);
      assert.equal((rest.data.monitor as MonitorView).id, id);
      assert.equal((rest.data.monitor as MonitorView).name, name);
      const base = `/app/accounts/${accountId}/monitors/${id}`;
      const detail = await request(owner, base);
      assert.equal(detail.text.match(/<h1[^>]*>([^<]*)<\/h1>/)?.[1], name, "Native detail must identify the requested persisted monitor");
      const editorPage = await request(owner, `${base}/edit`);
      assert.equal(editorPage.text.match(/name="name"[^>]*value="([^"]+)"/)?.[1], name, "Native editor must contain the actual persisted name");
      const editedName = `Edited ${id}`;
      const edited = await request(owner, `${base}/edit`, "POST", {
        csrfToken: owner.csrf, revision: String(created.monitor.revision), id, name: editedName, kind: "heartbeat", paused: "true",
        intervalSeconds: "60", timeoutSeconds: "5", confirmationDelaySeconds: "1", executionWindowSeconds: "60",
      }, 303, undefined, true);
      assert.equal(edited.response.headers.get("Location"), base);
      assert.equal((await monitor(agent, id)).name, editedName);
      await tool(agent, "monitor.resume", { monitorId: id, revision: (await monitor(agent, id)).revision });
      const running = await monitor(agent, id);
      assert.equal(running.paused, false);
      await request(owner, `${base}/pause`, "POST", { csrfToken: owner.csrf, revision: String(running.revision) }, 303, undefined, true);
      assert.equal((await monitor(agent, id)).state, "PAUSED");
      const paused = await request(anonymous, `/api/accounts/${accountId}/monitors/${id}`, "GET", undefined, 200, agent.key);
      assert.equal((paused.data.monitor as MonitorView).name, editedName);
      assert.equal((paused.data.monitor as MonitorView).paused, true);
    }
    const exported = await tool<{ monitors: { id: string; name: string; paused: boolean }[] }>(agent, "monitors.export");
    const restExport = await request(anonymous, `/api/accounts/${accountId}/export`, "GET", undefined, 200, agent.key);
    assert.deepEqual(restExport.data.monitors, exported.monitors);
    for (const id of ids) {
      const row = exported.monitors.find(item => item.id === id);
      assert.equal(row?.name, `Edited ${id}`); assert.equal(row?.paused, true);
      await tool(agent, "monitor.delete", { monitorId: id, revision: (await monitor(agent, id)).revision });
      await tool(agent, "monitor.get", { monitorId: id }, 404);
      await request(anonymous, `/api/accounts/${accountId}/monitors/${id}`, "GET", undefined, 404, agent.key);
      await request(owner, `/app/accounts/${accountId}/monitors/${id}`, "GET", undefined, 404);
    }
  });
  await scenario("defaults copy only on opt-in, remain redacted and send only on real notification action", async () => {
    const defaults = await tool<{ defaults: { revision: number } }>(ownerManage, "notification_defaults.get");
    await tool(ownerManage, "notification_defaults.set", { revision: defaults.defaults.revision, webhookMode: "replace", webhook: { url: fixtures!.webhookUrl, secret: hookSecret } });
    const persistedDefaults = await runtime!.database.transaction(accountId, tx => tx.query<{ value: string }>("SELECT value FROM engine.metadata WHERE account_id=$1 AND key=$2", [accountId, "notification-defaults"]));
    assert.equal(persistedDefaults.length, 1);
    assert(!persistedDefaults[0]!.value.includes(hookSecret), "Workspace defaults must not persist plaintext notification credentials");
    const copied = await tool<{ monitor: MonitorView }>(editorManage, "monitor.create", { id: "copied-defaults", check: { kind: "heartbeat" }, paused: true, useNotificationDefaults: true }); assert.equal(copied.monitor.webhook?.url, fixtures!.webhookUrl); assert(!JSON.stringify(copied).includes(hookSecret));
    const plain = await tool<{ monitor: MonitorView }>(editorManage, "monitor.create", { id: "no-defaults", check: { kind: "heartbeat" }, paused: true }); assert.equal(plain.monitor.webhook, undefined);
    const revision = (await tool<{ defaults: { revision: number } }>(ownerManage, "notification_defaults.get")).defaults.revision;
    await tool(ownerManage, "notification_defaults.set", { revision, webhookMode: "remove" });
    assert.equal((await monitor(ownerRead, "copied-defaults")).webhook?.url, fixtures!.webhookUrl);
    const rows = await runtime!.database.transaction(accountId, tx => tx.query<{ data: string }>("SELECT data FROM engine.monitors WHERE account_id=$1 AND id=$2", [accountId, "copied-defaults"]));
    assert.equal(rows.length, 1); assert(!rows[0]!.data.includes(hookSecret), "Copied destinations must retain no plaintext secret at rest");
    const receiptCount = fixtures!.receipts.length;
    const sent = await tool<{ notifications: { id: string }[] }>(editorManage, "notification.test", { monitorId: "copied-defaults", revision: copied.monitor.revision }); assert.equal(sent.notifications.length, 1);
    const deliveries = await eventually("Real webhook test must deliver", () => tool<{ notifications: NotificationView[] }>(ownerRead, "notifications.list", { monitorId: "copied-defaults" }), result => result.notifications.some(item => item.id === sent.notifications[0]!.id && item.status === "delivered"));
    assert(fixtures!.receipts.length > receiptCount); assert(!JSON.stringify(deliveries).includes(hookSecret));
    const receipt = fixtures!.receipts.find(value => value.headers["idempotency-key"] === sent.notifications[0]!.id);
    assert(receipt, "The real recipient must observe the intended persisted notification");
    const timestamp = receipt.headers["x-tomato-timestamp"];
    assert.equal(typeof timestamp, "string");
    assert.equal(receipt.headers["x-tomato-signature"], createHmac("sha256", hookSecret).update(`${timestamp}.${receipt.body}`).digest("hex"), "Real webhook HMAC must use the original decrypted destination credential");
    const persistedNotification = await runtime!.database.transaction(accountId, tx => tx.query<{ data: string }>("SELECT data FROM engine.notifications WHERE account_id=$1 AND id=$2", [accountId, sent.notifications[0]!.id]));
    assert.equal(persistedNotification.length, 1);
    assert(!persistedNotification[0]!.data.includes(hookSecret), "Durable delivery records must not persist plaintext signing credentials");
    await tool(editorManage, "notification.retry", { eventId: sent.notifications[0]!.id }, 409);
    await tool(editorManage, "notification.test", { monitorId: "no-defaults", revision: plain.monitor.revision }, 409);
  });
  await scenario("bulk pause/resume revision checks are atomic, not a partially changed list", async () => {
    const before = [await monitor(ownerRead, "family-http"), await monitor(ownerRead, "family-dns")];
    await tool(editorWrite, "monitors.bulk", { action: "resume", monitors: [{ id: before[0]!.id, revision: before[0]!.revision }, { id: before[1]!.id, revision: before[1]!.revision + 1 }] }, 409);
    for (const item of before) { const unchanged = await monitor(ownerRead, item.id); assert.equal(unchanged.revision, item.revision); assert.equal(unchanged.paused, true); }
    const resumed = await tool<{ monitors: MonitorView[] }>(editorWrite, "monitors.bulk", { action: "resume", monitors: before.map(item => ({ id: item.id, revision: item.revision })) }); assert(resumed.monitors.every(item => !item.paused));
    const paused = await tool<{ monitors: MonitorView[] }>(editorWrite, "monitors.bulk", { action: "pause", monitors: resumed.monitors.map(item => ({ id: item.id, revision: item.revision })) }); assert(paused.monitors.every(item => item.paused));
    await tool(editorWrite, "monitors.bulk", { action: "resume", monitors: [{ id: before[0]!.id, revision: paused.monitors[0]!.revision }, { id: before[0]!.id, revision: paused.monitors[0]!.revision }] }, 400);
  });
  await scenario("maintenance exact boundaries suppress pulses, charges and alerts then require fresh evidence", async () => {
    const created = await tool<{ monitor: MonitorView; heartbeatToken: string }>(editorWrite, "monitor.create", { id: "maintenance-pulse", check: { kind: "heartbeat" }, intervalMs: 60000 });
    const before = await tool<EngineSnapshot>(ownerRead, "state.get");
    const startsAt = Date.now() - 10, endsAt = Date.now() + 1500;
    await tool(editorWrite, "maintenance.create", { monitorId: created.monitor.id, revision: created.monitor.revision + 1, startsAt, endsAt, reason: "Stale maintenance" }, 409);
    assert.deepEqual(await tool(ownerRead, "maintenance.list"), { maintenance: [] });
    assert.equal((await monitor(ownerRead, created.monitor.id)).revision, created.monitor.revision);
    const window = await tool<{ maintenance: MaintenanceWindow }>(editorWrite, "maintenance.create", { monitorId: created.monitor.id, revision: created.monitor.revision, startsAt, endsAt, reason: "Real maintenance boundary" });
    assert.equal((await monitor(ownerRead, created.monitor.id)).effectiveState, "MAINTENANCE");
    const suppressed = await pulse(accountId, created.monitor.id, created.heartbeatToken, "maintenance-pulse"); assert.equal(suppressed.accepted, false); assert.equal(suppressed.maintenance, true);
    const currentMaintenance = await monitor(ownerRead, created.monitor.id);
    await tool(editorWrite, "maintenance.create", { monitorId: created.monitor.id, revision: currentMaintenance.revision, startsAt, endsAt: endsAt + 1000, reason: "overlap" }, 409);
    const active = await tool<{ maintenance: MaintenanceWindow[] }>(ownerRead, "maintenance.list"); assert.equal(active.maintenance.find(item => item.id === window.maintenance.id)?.status, "active");
    const during = await tool<EngineSnapshot>(ownerRead, "state.get"); assert.equal(during.usage, before.usage); assert.equal(during.notifications.length, before.notifications.length);
    await sleep(Math.max(0, endsAt - Date.now()) + 30); await tick();
    const ended = await monitor(ownerRead, created.monitor.id); assert.equal(ended.effectiveState, "UNKNOWN"); assert.equal(ended.lastObservedAt, null);
    const report = await tool<AvailabilityReport>(ownerRead, "report.get", { monitorId: created.monitor.id, from: startsAt, to: Date.now() - 1 }); assert(report.durationsMs.MAINTENANCE > 0); assert.equal(report.observedMs, 0); assert.equal(report.uptimeRatio, null);
    const next = await tool<{ maintenance: MaintenanceWindow }>(editorWrite, "maintenance.create", { monitorId: created.monitor.id, revision: ended.revision, startsAt: Date.now(), endsAt: Date.now() + 60000, reason: "cancel proof" });
    const cancelRevision = (await monitor(ownerRead, created.monitor.id)).revision;
    await tool(editorWrite, "maintenance.cancel", { maintenanceId: next.maintenance.id, revision: cancelRevision - 1 }, 409);
    assert.equal((await monitor(ownerRead, created.monitor.id)).effectiveState, "MAINTENANCE", "Stale cancel must leave active maintenance intact");
    await tool(editorWrite, "maintenance.cancel", { maintenanceId: next.maintenance.id, revision: cancelRevision }); assert.equal((await monitor(ownerRead, created.monitor.id)).effectiveState, "UNKNOWN");
    assert.equal((await pulse(accountId, created.monitor.id, created.heartbeatToken, "after-maintenance")).accepted, true);
    const rotated = await tool<{ monitor: MonitorView; heartbeatToken: string }>(editorWrite, "monitor.heartbeat_token_rotate", { monitorId: created.monitor.id, revision: (await monitor(ownerRead, created.monitor.id)).revision });
    await pulse(accountId, created.monitor.id, created.heartbeatToken, "old-token", 401); assert.equal((await pulse(accountId, created.monitor.id, rotated.heartbeatToken, "rotated-token")).accepted, true);
    const instructions = await tool<{ url: string; idempotencyHeader: string }>(ownerRead, "monitor.heartbeat_instructions", { monitorId: created.monitor.id }); assert(instructions.url.includes(`/heartbeat/${accountId}/${created.monitor.id}`)); assert.equal(instructions.idempotencyHeader, "Idempotency-Key"); assert(!JSON.stringify(instructions).includes(rotated.heartbeatToken));
    await tool(editorWrite, "monitor.pause", { monitorId: created.monitor.id, revision: rotated.monitor.revision });
  });
  await scenario("actual HTTP failure creates incident; acknowledgement is not recovery; publication uses redacted health", async () => {
    fixtures!.set("management-down", "down");
    const created = await tool<{ monitor: MonitorView }>(editorWrite, "monitor.create", { id: "genuine-down", check: { kind: "http", url: `${fixtures!.httpUrl}/management-down`, contains: "TOMATOOK" }, intervalMs: 1000, timeoutMs: 500, confirmationDelayMs: 100, executionWindowMs: 10000 });
    const down = await eventually("Real failing target must confirm DOWN", () => monitor(ownerRead, created.monitor.id), item => item.state === "DOWN" && item.incidentId !== null);
    assert((fixtures!.hits.get("management-down") ?? 0) >= 2); assert(down.incidentId);
    const acknowledged = await tool<{ incident: Incident }>(editorWrite, "incident.acknowledge", { incidentId: down.incidentId }); assert(acknowledged.incident.acknowledgedAt); assert.equal(acknowledged.incident.closedAt, null);
    assert.equal((await monitor(ownerRead, down.id)).state, "DOWN");
    const cleared = await tool<{ incident: Incident }>(editorWrite, "incident.unacknowledge", { incidentId: down.incidentId }); assert.equal(cleared.incident.acknowledgedAt, null); assert.equal(cleared.incident.closedAt, null);
    const history = await tool<{ observations: unknown[] }>(ownerRead, "history.list", { monitorId: down.id }); assert(history.observations.length >= 2);
    const incidents = await tool<{ incidents: Incident[] }>(ownerRead, "incidents.list", { monitorId: down.id }); assert(incidents.incidents.some(item => item.id === down.incidentId));
    const coverage = await tool<{ coverage: unknown[] }>(ownerRead, "coverage.list", { monitorId: down.id, limit: 1 }); assert.equal(coverage.coverage.length, 1);
    const beforePublication = await tool<{ revision: number }>(ownerRead, "status_page.get");
    const publicationRevision = beforePublication.revision;
    await tool(ownerRead, "status_page.configure", { revision: publicationRevision, slug: "read-cannot-publish", title: "Denied", published: true, components: [{ monitorId: down.id, label: "API" }] }, 403);
    await tool(ownerWrite, "status_page.configure", { revision: publicationRevision, slug: "write-cannot-publish", title: "Denied", published: true, components: [{ monitorId: down.id, label: "API" }] }, 403);
    await tool(ownerManage, "status_page.configure", { revision: publicationRevision, slug: "invalid-publication", title: "Invalid", published: true, components: [{ monitorId: "nonexistent-component", label: "Missing" }] }, 404);
    assert.equal((await runtime!.database.query("SELECT 1 FROM identity.slugs WHERE slug=ANY($1::text[])", [["read-cannot-publish", "write-cannot-publish", "invalid-publication"]])).length, 0, "Rejected publication must not claim a global slug");
    await tool(ownerManage, "status_page.configure", { revision: publicationRevision, slug: "management-status", title: "Management status", published: true, components: [{ monitorId: down.id, label: "API" }] });
    const published = await tool<{ page: { revision: number } }>(ownerRead, "status_page.get");
    await tool(ownerManage, "status_update.create", { revision: publicationRevision, incidentId: down.incidentId, body: "Stale update" }, 409);
    assert.deepEqual(await tool(ownerRead, "status_page.get"), published, "Stale incident update must preserve publication and updates");
    const update = await tool<{ update: { id: string } }>(ownerManage, "status_update.create", { revision: published.page.revision, incidentId: down.incidentId, body: "We are investigating the actual outage." });
    const publicRead = await request(anonymous, "/api/public/status/management-status"); assert(publicRead.text.includes("We are investigating")); assert(!publicRead.text.includes(fixtures!.httpUrl)); assert(!publicRead.text.includes(hookSecret));
    const withUpdate = await tool<{ page: { revision: number } }>(ownerRead, "status_page.get");
    await tool(ownerManage, "status_update.remove", { updateId: update.update.id, revision: published.page.revision }, 409);
    assert((await request(anonymous, "/api/public/status/management-status")).text.includes("We are investigating"), "Stale removal cannot hide a published update");
    await tool(ownerManage, "status_update.remove", { updateId: update.update.id, revision: withUpdate.page.revision });
    const removed = await tool<{ page: { revision: number } }>(ownerRead, "status_page.get");
    await tool(ownerManage, "status_page.unpublish", { revision: removed.page.revision }); await request(anonymous, "/api/public/status/management-status", "GET", undefined, 404);
    await tool(editorWrite, "monitor.pause", { monitorId: down.id, revision: down.revision });
  });
  await scenario("unfunded heartbeat is UNKNOWN, while genuinely missed funded heartbeat stays DOWN in reports", async () => {
    const starved = native();
    await request(anonymous, "/api/operator/accounts", "POST", { id: "unfunded", name: "Unfunded", owner: { email: "unfunded-owner@example.test", name: "Unfunded fixture", password, emailVerified: true }, testingCredits: 1 }, 201, operator);
    await login(starved, "unfunded-owner@example.test"); const agent = await connect(await issue(starved, "manage", "unfunded-manage", "unfunded"));
    const created = await tool<{ monitor: MonitorView; heartbeatToken: string }>(agent, "monitor.create", { id: "starved", check: { kind: "heartbeat" }, intervalMs: 1000, timeoutMs: 100, executionWindowMs: 1000 }, undefined, "unfunded");
    assert.equal((await pulse("unfunded", "starved", created.heartbeatToken, "spend-only-credit")).accepted, true);
    const beforeRejected = await tool<{ balance: number; heartbeatCreditsUsed: number; heartbeatReceipts: number }>(agent, "usage.get", {}, undefined, "unfunded");
    assert.equal(beforeRejected.balance, 0);
    await pulse("unfunded", "starved", created.heartbeatToken, "cannot-charge", 402);
    const afterRejected = await tool<{ balance: number; heartbeatCreditsUsed: number; heartbeatReceipts: number }>(agent, "usage.get", {}, undefined, "unfunded");
    assert.equal(afterRejected.balance, beforeRejected.balance); assert.equal(afterRejected.heartbeatReceipts, beforeRejected.heartbeatReceipts); assert.equal(afterRejected.heartbeatCreditsUsed, beforeRejected.heartbeatCreditsUsed);
    await sleep(1200); await tick("unfunded");
    const unknown = await monitor(agent, "starved", "unfunded"); assert.equal(unknown.effectiveState, "UNKNOWN"); assert.equal(unknown.incidentId, null);
    const report = await tool<AvailabilityReport>(agent, "report.get", { monitorId: "starved", from: Date.now() - 1000, to: Date.now() - 1 }, undefined, "unfunded"); assert.equal(report.observedMs, 0); assert.equal(report.uptimeRatio, null);
    const funded = await tool<{ monitor: MonitorView; heartbeatToken: string }>(editorWrite, "monitor.create", { id: "funded-missing", check: { kind: "heartbeat" }, intervalMs: 1000, timeoutMs: 100, executionWindowMs: 10000 });
    assert.equal((await pulse(accountId, funded.monitor.id, funded.heartbeatToken, "funded-first")).accepted, true);
    const down = await eventually("Missing funded heartbeat must be genuine DOWN", () => monitor(ownerRead, funded.monitor.id), item => item.state === "DOWN" && item.incidentId !== null);
    await sleep(1200); const stillDown = await monitor(ownerRead, funded.monitor.id); assert.equal(stillDown.effectiveState, "DOWN");
    const downReport = await tool<AvailabilityReport>(ownerRead, "report.get", { monitorId: funded.monitor.id, from: Date.now() - 1000, to: Date.now() - 1 }); assert(downReport.durationsMs.DOWN > 0); assert.equal(downReport.durationsMs.UNKNOWN, 0);
    await tool(editorWrite, "monitor.pause", { monitorId: down.id, revision: down.revision });
  });
  await scenario("freshness expires real UP evidence rather than inventing continued availability", async () => {
    const freshOwner = native();
    await request(anonymous, "/api/operator/accounts", "POST", { id: "freshness", name: "Freshness", owner: { email: "fresh-owner@example.test", name: "Freshness fixture", password, emailVerified: true }, testingCredits: 1 }, 201, operator);
    await login(freshOwner, "fresh-owner@example.test"); const agent = await connect(await issue(freshOwner, "manage", "fresh-manage", "freshness"));
    const created = await tool<{ monitor: MonitorView }>(agent, "monitor.create", { id: "once-up", check: { kind: "http", url: `${fixtures!.httpUrl}/once-up`, contains: "TOMATOOK" }, intervalMs: 10000, timeoutMs: 500, executionWindowMs: 10000 }, undefined, "freshness");
    const up = await eventually("Real fixture must produce UP", () => monitor(agent, created.monitor.id, "freshness"), item => item.lastObservedAt !== null && item.state === "UP"); assert(up.lastObservedAt); assert(up.freshUntil);
    await sleep(Math.max(0, up.freshUntil - Date.now()) + 150); await tick("freshness");
    const stale = await monitor(agent, created.monitor.id, "freshness"); assert.equal(stale.effectiveState, "UNKNOWN");
    await tool(agent, "monitor.check_now", { monitorId: created.monitor.id, revision: stale.revision }, 402, "freshness");
    const report = await tool<AvailabilityReport>(agent, "report.get", { monitorId: created.monitor.id, from: up.lastObservedAt, to: Date.now() - 1 }, undefined, "freshness"); assert(report.durationsMs.UNKNOWN > 0); assert(report.coverageRatio < 1); assert.equal(report.uptimeRatio, 1);
    const oldTo = Date.now() - 1;
    const paused = await tool<{ monitor: MonitorView }>(agent, "monitor.pause", { monitorId: created.monitor.id, revision: stale.revision }, undefined, "freshness");
    await tool(agent, "monitor.update", { monitorId: created.monitor.id, revision: paused.monitor.revision, intervalMs: 60000, name: "Changed after stale historical evidence" }, undefined, "freshness");
    const closed = await tool<AvailabilityReport>(agent, "report.get", { monitorId: created.monitor.id, from: up.lastObservedAt, to: oldTo }, undefined, "freshness");
    assert(closed.durationsMs.UNKNOWN > 0, "Closing a stale UP segment must preserve UNKNOWN tail");
    assert(closed.durationsMs.UP <= up.freshUntil - up.lastObservedAt, "Historical UP must never exceed the original persisted freshness ceiling");
    const oldHealthy = await tool<AvailabilityReport>(agent, "report.get", { monitorId: created.monitor.id, from: up.lastObservedAt, to: up.lastObservedAt + 50 }, undefined, "freshness");
    assert.equal(oldHealthy.durationsMs.UP, 50); assert.equal(oldHealthy.durationsMs.UNKNOWN, 0); assert.equal(oldHealthy.uptimeRatio, 1);
    const oldStale = await tool<AvailabilityReport>(agent, "report.get", { monitorId: created.monitor.id, from: up.freshUntil + 1, to: oldTo }, undefined, "freshness");
    assert.equal(oldStale.durationsMs.UP, 0); assert.equal(oldStale.durationsMs.UNKNOWN, oldTo - up.freshUntil - 1);
  });
  await scenario("Check now uses a genuine queued probe, one credit and unchanged regular cadence", async () => {
    const created = await tool<{ monitor: MonitorView }>(editorWrite, "monitor.create", { id: "manual-outbound", check: { kind: "http", url: `${fixtures!.httpUrl}/manual-outbound`, contains: "TOMATOOK" }, intervalMs: 60000, timeoutMs: 500, confirmationDelayMs: 100, executionWindowMs: 10000 });
    const up = await eventually("Regular fixture observation must establish UP", () => monitor(ownerRead, created.monitor.id), value => value.state === "UP" && value.lastObservedAt !== null);
    const before = await tool<{ usage: number }>(ownerRead, "usage.get"), hitsBefore = fixtures!.hits.get("manual-outbound") ?? 0;
    await tool(ownerRead, "monitor.check_now", { monitorId: up.id, revision: up.revision }, 403);
    await tool(editorWrite, "monitor.check_now", { monitorId: up.id, revision: up.revision + 1 }, 409);
    fixtures!.set("manual-outbound", "down");
    await tool(editorWrite, "monitor.check_now", { monitorId: up.id, revision: up.revision });
    await tool(editorWrite, "monitor.check_now", { monitorId: up.id, revision: up.revision }, 409);
    const down = await eventually("Manual check must confirm the changed real target", () => monitor(ownerRead, up.id), value => value.state === "DOWN" && value.incidentId !== null);
    assert.equal(down.nextDueAt, up.nextDueAt, "Manual check cannot move regular cadence"); assert.equal(down.revision, up.revision);
    assert((fixtures!.hits.get("manual-outbound") ?? 0) >= hitsBefore + 2, "Failed manual primary must use real free temporal confirmation");
    const after = await tool<{ usage: number }>(ownerRead, "usage.get"); assert.equal(after.usage, before.usage + 1);
    const active = await tool<{ maintenance: MaintenanceWindow }>(editorWrite, "maintenance.create", { monitorId: up.id, revision: down.revision, startsAt: Date.now(), endsAt: Date.now() + 60000, reason: "Manual check suppressed" });
    const maintenance = await monitor(ownerRead, up.id); await tool(editorWrite, "monitor.check_now", { monitorId: up.id, revision: maintenance.revision }, 409);
    await tool(editorWrite, "maintenance.cancel", { maintenanceId: active.maintenance.id, revision: maintenance.revision });
    const current = await monitor(ownerRead, up.id);
    const paused = await tool<{ monitor: MonitorView }>(editorWrite, "monitor.pause", { monitorId: up.id, revision: current.revision });
    await tool(editorWrite, "monitor.check_now", { monitorId: up.id, revision: paused.monitor.revision }, 409);
    const heartbeat = await monitor(ownerRead, "family-heartbeat"); await tool(editorWrite, "monitor.check_now", { monitorId: heartbeat.id, revision: heartbeat.revision }, 409);
  });
  await scenario("last-owner protection, invite revoke and member role/removal honor live current roles", async () => {
    const members = await tool<{ members: { userId: string; username: string }[] }>(ownerRead, "members.list");
    const alice = members.members.find(item => item.username === "alice@example.test")!, dana = members.members.find(item => item.username === "dana@example.test")!;
    await tool(ownerManage, "member.remove", { userId: alice.userId }, 409); await tool(ownerManage, "member.role_set", { userId: alice.userId, role: "viewer" }, 409);
    const invitation = await tool<{ invitation: { id: string }; invitationUrl: string }>(ownerManage, "invitation.create", { username: "never-accepted@example.test", role: "viewer" }); assert(invitation.invitationUrl.includes("/invite/"));
    await tool(ownerManage, "invitation.revoke", { invitationId: invitation.invitation.id }); await tool(ownerManage, "invitations.list");
    await tool(ownerManage, "member.role_set", { userId: dana.userId, role: "viewer" }); await tool(editorManage, "monitor.create", { id: "demoted-forbidden", check: { kind: "heartbeat" }, paused: true }, 403);
    await tool(ownerManage, "member.role_set", { userId: dana.userId, role: "editor" });
    await tool(ownerManage, "member.remove", { userId: dana.userId }); await request(anonymous, `/api/accounts/${accountId}/workspace`, "GET", undefined, 401, editorManage.key);
  });
  await scenario("stable audit pagination includes every same-ms event and carries key IDs without secrets", async () => {
    for (let index = 0; index < 4; index++) await tool(ownerManage, "workspace.rename", { name: `Audit tie ${index}` });
    // Coalesce timestamps only for real actions above; leave identity, rows and row order untouched.
    const tiedAt = Date.now() - 1; await runtime!.database.query("UPDATE identity.audit SET occurred_at=$1 WHERE account_id=$2", [tiedAt, accountId]);
    const expected = await runtime!.database.query<{ id: string }>("SELECT id FROM identity.audit WHERE account_id=$1 ORDER BY sequence DESC", [accountId]);
    const collected: AuditView[] = []; let cursor: string | null | undefined;
    do { const page = await tool<{ entries: AuditView[]; cursor: string | null }>(ownerRead, "audit.list", { limit: 7, ...(cursor ? { cursor } : { before: tiedAt + 1 }) }); collected.push(...page.entries); cursor = page.cursor; assert(cursor === null || typeof cursor === "string"); assert(collected.length <= expected.length); } while (cursor);
    assert.deepEqual(collected.map(item => item.id), expected.map(item => item.id)); assert.equal(new Set(collected.map(item => item.id)).size, expected.length);
    assert(collected.some(item => item.apiKeyId === ownerManage.view.id)); assert(!JSON.stringify(collected).includes(ownerManage.key)); assert(!JSON.stringify(collected).includes(password)); assert(!JSON.stringify(collected).includes(hookSecret));
    const nativeIds: string[] = []; let nativeCursor: string | null = null;
    do {
      const query: URLSearchParams = new URLSearchParams({ limit: "7", ...(nativeCursor ? { cursor: nativeCursor } : { before: String(tiedAt + 1) }) });
      const page: Record<string, unknown> = (await request(owner, `/api/accounts/${accountId}/audit?${query}`)).data;
      assert(Array.isArray(page.entries)); assert(page.cursor === null || typeof page.cursor === "string");
      for (const entry of page.entries) { assert(entry && typeof entry === "object" && "id" in entry && typeof entry.id === "string"); nativeIds.push(entry.id); }
      nativeCursor = page.cursor; assert(nativeIds.length <= expected.length);
    } while (nativeCursor);
    assert.deepEqual(nativeIds, expected.map(item => item.id), "Native REST and SDK opaque audit pagination must agree");
    await tool(ownerRead, "audit.list", { limit: 0 }, 400); await tool(ownerRead, "audit.list", { cursor: "not-a-cursor" }, 400);
  });
  await scenario("management invocation rate limits are per live credential, not shared across keys", async () => {
    const limited = await connect(await issue(owner, "read", "rate-limited-read"));
    const isolated = await connect(await issue(owner, "read", "independent-read"));
    for (let invocation = 0; invocation < 120; invocation++) await globalTool(limited, "capabilities.get");
    await globalTool(limited, "capabilities.get", 429);
    const unaffected = await globalTool<{ payments: boolean }>(isolated, "capabilities.get"); assert.equal(unaffected.payments, false);
    const nativeLimited = native(); await login(nativeLimited, "alice@example.test");
    for (let invocation = 0; invocation < 120; invocation++) await request(nativeLimited, `/api/accounts/${accountId}/workspace`);
    const denied = await request(nativeLimited, `/api/accounts/${accountId}/workspace`, "GET", undefined, 429); assert.equal(denied.data.error, "management_rate_limited");
    await request(owner, `/api/accounts/${accountId}/workspace`);
  });
  await scenario("delegated own sessions and password change revoke real backing credentials", async () => {
    const secondViewer = native(); await login(secondViewer, "carol@example.test");
    const sessions = await tool<{ sessions: SessionView[] }>(viewerManage, "sessions.list"); assert(sessions.sessions.length >= 2);
    const secondSession = String((await request(secondViewer, "/api/session")).data.sessionId);
    await tool(viewerManage, "session.revoke", { sessionId: secondSession }); await request(secondViewer, "/api/session", "GET", undefined, 401);
    await tool(viewerManage, "sessions.revoke_others"); await request(viewer, "/api/session", "GET", undefined, 401);
    await login(viewer, "carol@example.test");
    const newPassword = randomBytes(24).toString("hex");
    await tool(viewerManage, "password.change", { currentPassword: "wrong-password-proof", newPassword }, 401);
    await tool(viewerManage, "password.change", { currentPassword: password, newPassword });
    await request(viewer, "/api/session", "GET", undefined, 401); await request(anonymous, `/api/accounts/${accountId}/workspace`, "GET", undefined, 401, viewerRead.key); await request(anonymous, `/api/accounts/${accountId}/workspace`, "GET", undefined, 401, viewerManage.key);
    await login(viewer, "carol@example.test", newPassword);
  });
  console.log(`PASS management verification: ${passed} scenarios; real SDK remote+stdio, Node/PostgreSQL/outbox, consumer-visible operations and genuine fixture outcomes`);
} finally {
  for (const agent of agents.reverse()) { try { await agent.client.close(); } catch { /* Revoked credentials need no remote teardown. */ } }
  await runtime?.close();
}
