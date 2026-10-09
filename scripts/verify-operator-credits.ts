import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { NativeClient } from "./local-client.ts";
import { createProductionTestRuntime, type ProductionTestRuntime } from "./production-test-runtime.ts";
import { z } from "zod";

const Usage = z.object({
  balance: z.number(), available: z.number(), usage: z.number(), heartbeatReceipts: z.number(),
  grants: z.array(z.object({ id: z.string(), credits: z.number(), reason: z.string() })),
});
const Audit = z.object({ entries: z.array(z.object({ actor: z.string(), action: z.string(), subject: z.string() })) });

/** Financial admission regression over the actual HTTP listener and PostgreSQL ledger. */
export async function verifyOperatorCredits(runtime: ProductionTestRuntime): Promise<void> {
  const password = randomBytes(24).toString("hex");
  const provision = (id: string) => ({ id, name: id, owner: { email: `${id}@example.test`, name: id, password, emailVerified: true } });
  const operatorRequest = async (route: string, body: unknown, expected: number, bearer = runtime.token, method = "POST") => {
    const response = await runtime.fetch(route, { method, headers: { "Content-Type": "application/json", ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) }, body: JSON.stringify(body) });
    assert.equal(response.status, expected);
    return response;
  };
  const absent = async (id: string) => {
    assert.deepEqual(await runtime.database.query("SELECT id FROM engine.accounts WHERE id=$1", [id]), []);
    assert.deepEqual(await runtime.database.query("SELECT id FROM public.auth_user WHERE email=$1", [`${id}@example.test`]), []);
    assert.deepEqual(await runtime.database.query('SELECT a.id FROM public.auth_account a JOIN public.auth_user u ON u.id=a."userId" WHERE u.email=$1', [`${id}@example.test`]), []);
    assert.deepEqual(await runtime.database.query("SELECT account_id FROM identity.members WHERE account_id=$1", [id]), []);
  };
  const owner = async (id: string) => {
    const client = new NativeClient(runtime.baseUrl);
    await client.login(`${id}@example.test`, password);
    const session = z.object({ csrfToken: z.string() }).parse(JSON.parse((await client.request("/api/session", { expected: 200 })).text));
    return { client, csrf: session.csrfToken };
  };
  const usage = async (client: NativeClient, id: string) => Usage.parse(JSON.parse((await client.request(`/api/accounts/${id}/usage`, { expected: 200 })).text));
  const audit = async (client: NativeClient, id: string) => {
    const parsed = Audit.parse(JSON.parse((await client.request(`/api/accounts/${id}/audit`, { expected: 200 })).text));
    return parsed.entries;
  };

  await operatorRequest("/api/operator/accounts", provision("credit-omitted"), 201);
  const unfunded = await owner("credit-omitted");
  const initial = await usage(unfunded.client, "credit-omitted");
  assert.equal(initial.balance, 0); assert.equal(initial.available, 0); assert.deepEqual(initial.grants, []);
  assert.equal((await audit(unfunded.client, "credit-omitted")).filter(entry => entry.action === "credit.grant").length, 0);
  const heartbeat = z.object({ heartbeatToken: z.string() }).parse(JSON.parse((await unfunded.client.request("/api/accounts/credit-omitted/monitors", { json: { id: "unfunded-heartbeat", check: { kind: "heartbeat" }, intervalMs: 60000, timeoutMs: 100, executionWindowMs: 1000 }, csrf: unfunded.csrf, expected: 201 })).text));
  const blocked = await runtime.fetch("/heartbeat/credit-omitted/unfunded-heartbeat", { method: "POST", headers: { Authorization: `Bearer ${heartbeat.heartbeatToken}`, "Idempotency-Key": "unfunded-pulse" } });
  assert.equal(blocked.status, 402); assert.deepEqual(await blocked.json(), { error: "insufficient_credits" });
  const afterBlocked = await usage(unfunded.client, "credit-omitted");
  assert.equal(afterBlocked.balance, 0); assert.equal(afterBlocked.usage, 0); assert.equal(afterBlocked.heartbeatReceipts, 0);
  console.log("PASS omitted operator credits create an unfunded workspace and real heartbeat admission spends nothing");

  await operatorRequest("/api/operator/accounts", { ...provision("credit-zero"), testingCredits: 0 }, 201);
  const zero = await owner("credit-zero");
  assert.equal((await usage(zero.client, "credit-zero")).balance, 0);
  assert.deepEqual((await usage(zero.client, "credit-zero")).grants, []);
  assert.equal((await audit(zero.client, "credit-zero")).filter(entry => entry.action === "credit.grant").length, 0);
  console.log("PASS explicit zero operator credits create no deposit or grant");

  await operatorRequest("/api/operator/accounts", { ...provision("credit-positive"), testingCredits: 1234 }, 201);
  const funded = await owner("credit-positive");
  const granted = await usage(funded.client, "credit-positive");
  assert.equal(granted.balance, 1234); assert.equal(granted.available, 1234); assert.equal(granted.grants.length, 1);
  assert.equal(granted.grants[0]!.credits, 1234); assert.equal(granted.grants[0]!.reason, "Operator-issued testing grant");
  const grants = (await audit(funded.client, "credit-positive")).filter(entry => entry.action === "credit.grant");
  assert.equal(grants.length, 1); assert.equal(grants[0]!.actor, "operator"); assert.equal(grants[0]!.subject, granted.grants[0]!.id);
  await operatorRequest("/api/operator/accounts", { ...provision("credit-positive"), testingCredits: 1234 }, 409);
  assert.equal((await usage(funded.client, "credit-positive")).balance, 1234);
  assert.equal((await usage(funded.client, "credit-positive")).grants.length, 1);
  assert.equal((await audit(funded.client, "credit-positive")).filter(entry => entry.action === "credit.grant").length, 1);
  console.log("PASS explicit positive operator credits create exactly one audit-tagged grant, including after duplicate provisioning");

  const invalid = [-1, 0.5, 1000000001, "1234", null, true];
  for (const [index, testingCredits] of invalid.entries()) {
    const id = `credit-invalid-${index}`;
    const response = await operatorRequest("/api/operator/accounts", { ...provision(id), testingCredits }, 400);
    assert.deepEqual(await response.json(), { error: "invalid_testing_credits" });
    await absent(id);
  }
  await operatorRequest("/api/operator/accounts", provision("credit-invalid-0"), 201);
  console.log("PASS invalid operator credit amounts provision no identity, credential, membership or workspace and allow a corrected retry");

  const key = z.object({ apiKey: z.string() }).parse(JSON.parse((await funded.client.request("/api/accounts/credit-positive/api-keys", { json: { name: "Credit denial regression", scope: "manage", expiresInDays: 1 }, csrf: funded.csrf, expected: 201 })).text));
  for (const [label, bearer] of [["anonymous", ""], ["key", key.apiKey]] as const) {
    const id = `credit-denied-${label}`;
    await operatorRequest("/api/operator/accounts", { ...provision(id), testingCredits: 9999 }, 401, bearer);
    await operatorRequest("/api/operator/accounts/credit-positive/credits/denied", { credits: 9999 }, 401, bearer, "PUT");
    await absent(id);
  }
  await funded.client.request("/api/operator/accounts", { json: { ...provision("credit-denied-session"), testingCredits: 9999 }, csrf: funded.csrf, expected: 401 });
  await funded.client.request("/api/operator/accounts/credit-positive/credits/denied", { method: "PUT", json: { credits: 9999 }, csrf: funded.csrf, expected: 401 });
  await absent("credit-denied-session");
  await funded.client.request("/api/accounts/credit-positive/credits/denied", { method: "PUT", json: { credits: 9999 }, csrf: funded.csrf, expected: 404 });
  await operatorRequest("/api/accounts/credit-positive/credits/denied", { credits: 9999 }, 404, key.apiKey, "PUT");

  const mcp = new Client({ name: "tomato-credit-denial", version: "0.1.0" }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(new URL("/mcp", runtime.baseUrl), { requestInit: { headers: { Authorization: `Bearer ${key.apiKey}` } } });
  try {
    await mcp.connect(transport);
    const read = await mcp.callTool({ name: "tomato.usage.get", arguments: { accountId: "credit-positive" } });
    assert.notEqual(read.isError, true);
    await assert.rejects(mcp.callTool({ name: "tomato.credit.grant", arguments: { accountId: "credit-positive", credits: 9999 } }), error => error instanceof StreamableHTTPError && error.code === 400);
  } finally {
    try { if (transport.sessionId) await transport.terminateSession(); }
    finally { await mcp.close(); }
  }
  const afterDenials = await usage(funded.client, "credit-positive");
  assert.equal(afterDenials.balance, 1234); assert.equal(afterDenials.grants.length, 1);
  assert.equal((await audit(funded.client, "credit-positive")).filter(entry => entry.action === "credit.grant").length, 1);
  console.log("PASS unauthenticated, session, API-key and actual MCP callers cannot provision credits or mint grants");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime: ProductionTestRuntime | undefined;
  try {
    runtime = await createProductionTestRuntime({ background: false });
    await verifyOperatorCredits(runtime);
  } finally { await runtime?.close(); }
}
