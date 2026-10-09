import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";

/** The bridge has exactly one configured MCP destination, never a caller-selected URL. */
export function validateMcpUrl(value: string | undefined): URL {
  if (!value || value !== value.trim() || /[\s\\]/.test(value)) throw new Error("invalid_mcp_endpoint");
  let endpoint: URL;
  try { endpoint = new URL(value); } catch { throw new Error("invalid_mcp_endpoint"); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname);
  if (!(endpoint.protocol === "https:" || (endpoint.protocol === "http:" && loopback))
    || endpoint.username || endpoint.password || endpoint.pathname !== "/mcp" || endpoint.search || endpoint.hash
    || value.includes("?") || value.includes("#") || !/^https?:\/\/[^/@]+\/mcp$/.test(value)) {
    throw new Error("invalid_mcp_endpoint");
  }
  return endpoint;
}

/** Start a real SDK stdio server backed exclusively by the configured, authenticated remote MCP server. */
export async function runAgentStdio(): Promise<void> {
  if (process.argv.length !== 2) throw new Error("configure_mcp_using_environment_only");
  const endpoint = validateMcpUrl(process.env.TOMATO_MCP_URL);
  const key = process.env.TOMATO_API_KEY;
  if (!key || /[\s,]/.test(key)) throw new Error("tomato_api_key_required");
  const remote = new Client({ name: "tomato-stdio-bridge", version: "0.1.0" }, { capabilities: {} });
  const http = new StreamableHTTPClientTransport(endpoint, {
    requestInit: { headers: { Authorization: `Bearer ${key}` }, credentials: "omit", redirect: "error" },
    fetch: async (url, init) => {
      // This also prevents the SDK from forwarding credentials through redirects or OAuth URLs.
      if (new URL(url).href !== endpoint.href || !["POST", "GET", "DELETE"].includes(init?.method ?? "GET")) {
        throw new Error("invalid_mcp_destination");
      }
      return fetch(endpoint, { ...init, credentials: "omit", redirect: "error" });
    },
  });
  let local: Server | undefined;
  let closing: Promise<void> | undefined;
  const shutdown = (): Promise<void> => {
    if (!closing) closing = (async () => {
      if (http.sessionId) await http.terminateSession().catch(() => undefined);
      await remote.close().catch(() => undefined);
      await local?.close().catch(() => undefined);
    })();
    return closing;
  };
  try {
    // Client.connect performs initialize and notifications/initialized using the negotiated legacy revision.
    await remote.connect(http, { timeout: 15000 });
    if (!remote.getServerCapabilities()?.tools) throw new Error("remote_tools_unavailable");
    const catalog = await remote.listTools(undefined, { timeout: 15000 });
    if (catalog.nextCursor !== undefined) throw new Error("remote_catalog_must_be_complete");
    const names = new Set(catalog.tools.map(tool => tool.name));
    if (names.size !== catalog.tools.length) throw new Error("invalid_remote_catalog");
    const info = remote.getServerVersion();
    if (!info) throw new Error("remote_identity_unavailable");
    local = new Server({ ...info, name: "tomato-stdio" }, {
      capabilities: { tools: {} }, instructions: remote.getInstructions(),
    });
    local.setRequestHandler(ListToolsRequestSchema, async request => {
      if (request.params?.cursor !== undefined) {
        throw new McpError(ErrorCode.InvalidParams, "This complete tool catalog does not accept a cursor");
      }
      try {
        const current = await remote.listTools(undefined, { timeout: 15000 });
        const currentNames = new Set(current.tools.map(tool => tool.name));
        if (current.nextCursor !== undefined || currentNames.size !== current.tools.length) throw new Error("invalid_remote_catalog");
        return { tools: current.tools };
      } catch {
        throw new McpError(ErrorCode.InternalError, "remote_mcp_unavailable");
      }
    });
    local.setRequestHandler(CallToolRequestSchema, async request => {
      try {
        // Fixed tools/call only. The authoritative remote registry rejects unknown names and reauthorizes every call.
        return await remote.callTool({ name: request.params.name, arguments: request.params.arguments }, undefined, { timeout: 30000 });
      } catch (error) {
        if (error instanceof McpError) throw new McpError(error.code, "Remote MCP protocol error");
        if (error instanceof StreamableHTTPError && error.code === 400) throw new McpError(ErrorCode.InvalidParams, "Invalid remote MCP request");
        const structuredContent = { error: "remote_mcp_unavailable", status: 502 };
        return { isError: true, content: [{ type: "text" as const, text: JSON.stringify(structuredContent) }], structuredContent };
      }
    });
    local.onclose = () => { void shutdown(); };
    local.onerror = () => { process.stderr.write("Tomato stdio protocol error.\n"); };
    process.once("SIGINT", () => { void shutdown(); });
    process.once("SIGTERM", () => { void shutdown(); });
    process.stdin.once("end", () => { void shutdown(); });
    await local.connect(new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 1024 * 1024 }));
  } catch (error) {
    await shutdown();
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runAgentStdio().catch(() => {
    // No argv, bearer, remote exception, or HTTP response is ever written to stdout/stderr.
    process.stderr.write("Tomato stdio bridge could not start. Check TOMATO_MCP_URL and TOMATO_API_KEY and server availability.\n");
    process.exitCode = 1;
  });
}
