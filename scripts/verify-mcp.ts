import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { validateMcpUrl } from "./agent-stdio.ts";
import { NativeClient } from "./local-client.ts";
import { createProductionTestRuntime, type ProductionTestRuntime } from "./production-test-runtime.ts";

export interface McpSmokeEvidence {
  http: { protocolVersion: string; sessionCreated: boolean; tools: string[]; readSucceeded: true };
  stdio: { initialized: true; tools: string[]; readSucceeded: true };
}

/** Exercise the installed SDK, real HTTP listener, and spawned first-class stdio bridge. */
export async function runMcpSmoke(url: string | URL, key: string, restrictedKey?: string): Promise<McpSmokeEvidence> {
  const endpoint = validateMcpUrl(String(url));
  assert(key && !/[\s,]/.test(key), "A bearer key is required");
  const httpClient = new Client({ name: "tomato-http-smoke", version: "0.1.0" }, { capabilities: {} });
  const http = new StreamableHTTPClientTransport(endpoint, {
    requestInit: { headers: { Authorization: `Bearer ${key}` }, credentials: "omit", redirect: "error" },
    fetch: async (target, init) => {
      assert.equal(new URL(target).href, endpoint.href, "SDK requests must stay on the configured MCP endpoint");
      return fetch(endpoint, { ...init, credentials: "omit", redirect: "error" });
    },
  });
  const stdioClient = new Client({ name: "tomato-stdio-smoke", version: "0.1.0" }, { capabilities: {} });
  const stdioProtocolErrors: unknown[] = [];
  stdioClient.onerror = error => { stdioProtocolErrors.push(error); };
  const childEnv = { ...getDefaultEnvironment(), TOMATO_MCP_URL: endpoint.href, TOMATO_API_KEY: key };
  if (process.env.NODE_EXTRA_CA_CERTS) Object.assign(childEnv, { NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS });
  const unrelatedCwd = await mkdtemp(join(tmpdir(), "tomato-mcp-cwd-"));
  const stdio = new StdioClientTransport({
    command: "node",
    args: [fileURLToPath(new URL("./agent-stdio.ts", import.meta.url))],
    env: childEnv,
    cwd: unrelatedCwd,
    stderr: "pipe",
    maxBufferSize: 1024 * 1024,
  });
  let stderr = "";
  const restrictedClient = restrictedKey ? new Client({ name: "tomato-scoped-stdio-smoke", version: "0.1.0" }, { capabilities: {} }) : undefined;
  const restrictedStdio = restrictedKey ? new StdioClientTransport({ command: "npm", args: ["run", "--silent", "agent:stdio"], env: { ...childEnv, TOMATO_API_KEY: restrictedKey }, cwd: fileURLToPath(new URL("../", import.meta.url)), stderr: "pipe", maxBufferSize: 1024 * 1024 }) : undefined;
  const invalidKey = "tomato_key_invalid_stdio_fixture";
  const invalidClient = new Client({ name: "tomato-unauthorized-stdio-smoke", version: "0.1.0" }, { capabilities: {} });
  const invalidStdio = new StdioClientTransport({ command: "npm", args: ["run", "--silent", "agent:stdio"], env: { ...childEnv, TOMATO_API_KEY: invalidKey }, cwd: fileURLToPath(new URL("../", import.meta.url)), stderr: "pipe", maxBufferSize: 1024 * 1024 });
  let invalidStderr = "";
  invalidStdio.stderr?.on("data", (chunk: Buffer) => { invalidStderr = (invalidStderr + chunk.toString()).slice(-65536); });
  stdio.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
    if (stderr.length > 65536) stderr = stderr.slice(-65536);
  });
  try {
    // connect is the SDK's initialize + initialized lifecycle, not a hand-written handshake.
    await httpClient.connect(http, { timeout: 15000 });
    assert.equal(http.protocolVersion, "2025-11-25", "The SDK must negotiate Tomato's supported legacy revision");
    assert(http.sessionId, "HTTP initialization must create an identity-backed protocol session");
    assert(httpClient.getServerCapabilities()?.tools, "HTTP must advertise real tool capabilities");
    const httpCatalog = await httpClient.listTools(undefined, { timeout: 15000 });
    assert.equal(httpCatalog.nextCursor, undefined, "Tomato's finite catalog must be complete");
    assert(httpCatalog.tools.length > 0, "HTTP must discover real tools");
    for (const tool of httpCatalog.tools) {
      assert.equal(tool.inputSchema.type, "object", "Discovered tools must have usable input schemas");
      assert(tool.description, "Discovered tools must describe their actual operation");
      assert(tool.annotations, "Discovered tools must expose safety annotations");
    }
    assert(httpCatalog.tools.some(tool => tool.name === "tomato.workspaces.list"), "The authorized workspace read must be discoverable");
    const httpRead = await httpClient.callTool({ name: "tomato.workspaces.list", arguments: {} }, undefined, { timeout: 15000 });
    assert.notEqual(httpRead.isError, true, "HTTP workspace read must execute successfully");
    assert(Array.isArray(httpRead.content) && httpRead.content.some(block => block.type === "text"), "HTTP read must include compatible text content");
    assert(httpRead.structuredContent && typeof httpRead.structuredContent === "object", "HTTP read must expose structured management data");
    await stdioClient.connect(stdio, { timeout: 30000 });
    assert(stdioClient.getServerCapabilities()?.tools, "Stdio initialize must advertise the remote tool capabilities");
    const stdioCatalog = await stdioClient.listTools(undefined, { timeout: 15000 });
    assert.equal(stdioCatalog.nextCursor, undefined, "Stdio must expose the complete remote catalog");
    assert.deepEqual(stdioCatalog.tools, httpCatalog.tools, "Stdio must expose the same authorized tool schemas and annotations");
    const stdioRead = await stdioClient.callTool({ name: "tomato.workspaces.list", arguments: {} }, undefined, { timeout: 15000 });
    assert.notEqual(stdioRead.isError, true, "Stdio workspace read must execute the authorized remote operation");
    assert(Array.isArray(stdioRead.content) && stdioRead.content.some(block => block.type === "text"), "Stdio read must include compatible text content");
    assert.deepEqual(stdioRead.structuredContent, httpRead.structuredContent, "Both transports must return the same workspace management data");
    await assert.rejects(stdioClient.callTool({ name: "tomato.not_real", arguments: {} }, undefined, { timeout: 15000 }), error => error instanceof McpError && error.code === ErrorCode.InvalidParams, "Unknown stdio tool must be a protocol error");
    const malformed = await stdioClient.callTool({ name: "tomato.workspaces.list", arguments: { constructor: null } }, undefined, { timeout: 15000 });
    assert.equal(malformed.isError, true, "Undeclared stdio arguments must fail in the shared service");
    assert.equal((malformed.structuredContent as Record<string, unknown>).status, 400);
    assert.equal(stdioProtocolErrors.length, 0, "Absolute Node script launch from unrelated cwd must emit no unparsable protocol bytes");
    if (restrictedClient && restrictedStdio) {
      await restrictedClient.connect(restrictedStdio, { timeout: 30000 });
      const scopedCatalog = await restrictedClient.listTools(undefined, { timeout: 15000 });
      assert(!scopedCatalog.tools.some(tool => tool.name === "tomato.monitor.create"));
      const read = await restrictedClient.callTool({ name: "tomato.workspaces.list", arguments: {} }, undefined, { timeout: 15000 });
      assert.notEqual(read.isError, true);
      const accountId = (read.structuredContent as { accounts: { id: string }[] }).accounts[0]!.id;
      const denied = await restrictedClient.callTool({ name: "tomato.monitor.create", arguments: { accountId, id: "stdio-scope-denied", check: { kind: "heartbeat" } } }, undefined, { timeout: 15000 });
      assert.equal(denied.isError, true);
      assert.equal((denied.structuredContent as Record<string, unknown>).status, 403, "Known scoped stdio calls must reach canonical live authorization");
    }
    await assert.rejects(invalidClient.connect(invalidStdio, { timeout: 5000 }), "An invalid bearer must not initialize the stdio bridge");
    assert(!invalidStderr.includes(invalidKey), "Failed authentication must not disclose the configured bearer");
    assert(!stderr.includes(key), "The bridge must never disclose its bearer in stderr");
    return {
      http: { protocolVersion: http.protocolVersion!, sessionCreated: Boolean(http.sessionId), tools: httpCatalog.tools.map(tool => tool.name), readSucceeded: true },
      stdio: { initialized: true, tools: stdioCatalog.tools.map(tool => tool.name), readSucceeded: true },
    };
  } finally {
    await stdioClient.close();
    await restrictedClient?.close();
    await restrictedStdio?.close();
    await invalidClient.close();
    await invalidStdio.close();
    await stdio.close();
    try { if (http.sessionId) await http.terminateSession(); }
    finally { await httpClient.close(); }
    await rm(unrelatedCwd, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let runtime: ProductionTestRuntime | undefined;
  try {
    runtime = await createProductionTestRuntime();
    const password = randomBytes(24).toString("hex");
    const provision = await runtime.fetch("/api/operator/accounts", { method: "POST", headers: { Authorization: `Bearer ${runtime.token}`, "Content-Type": "application/json" }, body: JSON.stringify({ id: "mcp", name: "MCP fixture", owner: { email: "mcp-owner@example.test", name: "MCP fixture owner", password, emailVerified: true }, testingCredits: 100 }) });
    assert.equal(provision.status, 201);
    const owner = new NativeClient(runtime.baseUrl);
    await owner.login("mcp-owner@example.test", password);
    const session = JSON.parse((await owner.request("/api/session", { expected: 200 })).text) as { csrfToken: string };
    const manage = JSON.parse((await owner.request("/api/accounts/mcp/api-keys", { json: { name: "MCP manage smoke", scope: "manage", expiresInDays: 1 }, csrf: session.csrfToken, expected: 201 })).text) as { apiKey: string };
    const read = JSON.parse((await owner.request("/api/accounts/mcp/api-keys", { json: { name: "MCP read smoke", scope: "read", expiresInDays: 1 }, csrf: session.csrfToken, expected: 201 })).text) as { apiKey: string };
    await runMcpSmoke(new URL("/mcp", runtime.baseUrl), manage.apiKey, read.apiKey);
    console.log("PASS MCP SDK HTTP and stdio initialize/list/call interoperability over real Node/PostgreSQL");
  } finally {
    await runtime?.close();
  }
}
