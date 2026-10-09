import type { Env } from "./runtime-types";
import type { Principal } from "./product-types";
import { authenticateBearer, executeManagement, hasManagementTool, identityCall, toolsFor } from "./management";
import { ApiError, body } from "./validation";

export const MCP_PROTOCOL_VERSIONS = ["2026-07-28", "2025-11-25"] as const;
const MODERN = MCP_PROTOCOL_VERSIONS[0];
const LEGACY = MCP_PROTOCOL_VERSIONS[1];
const META = "io.modelcontextprotocol/";
const SERVER_INFO = { name: "tomato", title: "Tomato", version: "0.1.0" };
const CAPABILITIES = { tools: {} };
const INSTRUCTIONS = "Manage Tomato using the tools authorized for this bearer. List workspaces first; account operations require an authorized accountId. Permissions and key scopes are checked on every operation.";
type RpcId = string | number | null;
type McpSession = { sessionId: string; protocolVersion: string; expiresAt: number; initialized: boolean };

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function response(value: unknown, status = 200, headers?: HeadersInit): Response {
  const result = new Headers(headers);
  result.set("Cache-Control", "no-store");
  result.set("X-Content-Type-Options", "nosniff");
  return Response.json(value, { status, headers: result });
}
function rpcError(id: RpcId, code: number, message: string, status = 400, data?: unknown, headers?: HeadersInit): Response {
  return response({ jsonrpc: "2.0", ...(id === null ? {} : { id }), error: { code, message, ...(data === undefined ? {} : { data }) } }, status, headers);
}
function mismatch(id: RpcId): Response {
  return rpcError(id, -32020, "Header mismatch", 400);
}
function unsupported(id: RpcId, requested: string): Response {
  return rpcError(id, -32022, "Unsupported protocol version", 400, { supported: [...MCP_PROTOCOL_VERSIONS], requested });
}
function complete(result: Record<string, unknown>, modern: boolean): Record<string, unknown> {
  return modern ? { ...result, resultType: "complete", _meta: { [`${META}serverInfo`]: SERVER_INFO } } : result;
}
function failure(error: unknown): { error: string; status: number } {
  // Only stable domain error identifiers are safe to expose. Never return exception text.
  return error instanceof ApiError && /^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(error.message)
    ? { error: error.message, status: error.status }
    : { error: "internal_error", status: 500 };
}
function toolResult(value: unknown, modern: boolean, isError = false): Record<string, unknown> {
  const structuredContent = object(value) ? value : { value: value ?? null };
  return complete({ content: [{ type: "text", text: JSON.stringify(structuredContent) }], structuredContent, ...(isError ? { isError: true } : {}) }, modern);
}
function decodeName(value: string | null): string | null {
  if (value === null) return null;
  if (value.startsWith("=?base64?") && value.endsWith("?=")) {
    const encoded = value.slice(9, -2);
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) return null;
    try {
      const binary = atob(encoded);
      if (btoa(binary) !== encoded) return null;
      return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(Uint8Array.from(binary, char => char.charCodeAt(0)));
    } catch { return null; }
  }
  return /^[\x09\x20-\x7e]*$/.test(value) && value.trim() === value ? value : null;
}
function binding(actor: Principal): { actorId: string; accountId: string; authBinding: string } {
  const accountId = actor.accounts[0]?.id;
  const authBinding = actor.apiKeyId ?? actor.sessionId;
  if (!accountId || !authBinding) throw new ApiError(401, "unauthorized");
  return { actorId: actor.actor.id, accountId, authBinding };
}
async function legacySession(request: Request, env: Env, actor: Principal, requireInitialized: boolean): Promise<McpSession> {
  const sessionId = request.headers.get("MCP-Session-Id");
  if (!sessionId) throw new ApiError(400, "mcp_session_required");
  const session = await identityCall<McpSession>(env, "/mcp/validate", { ...binding(actor), sessionId, requireInitialized });
  if (session.expiresAt <= Date.now()) throw new ApiError(404, "mcp_session_not_found");
  if (session.protocolVersion !== LEGACY) throw new ApiError(400, "unsupported_protocol_version");
  return session;
}

/** JSON-only Streamable HTTP, with independent modern requests and identity-backed legacy sessions. */
export async function handleMcp(request: Request, env: Env): Promise<Response | null> {
  const endpoint = new URL(request.url);
  if (endpoint.pathname !== "/mcp") return null;
  let id: RpcId = null;
  try {
    if (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname) && env.TEST_MODE === true)) {
      return rpcError(id, -32000, "https_required", 403);
    }
    const origin = request.headers.get("Origin");
    if (origin !== null && origin !== endpoint.origin) return rpcError(id, -32000, "origin_mismatch", 403);
    // Browser sessions are never an implicit MCP credential, even alongside a bearer.
    if (request.headers.has("Cookie") || !/^Bearer [^\s,]+$/i.test(request.headers.get("Authorization") ?? "")) {
      return rpcError(id, -32000, "unauthorized", 401, undefined, { "WWW-Authenticate": "Bearer" });
    }
    const actor = await authenticateBearer(request, env);
    if (request.method === "GET") return rpcError(id, -32600, "GET streaming is not supported", 405, undefined, { Allow: "POST, DELETE" });
    if (request.method === "DELETE") {
      const version = request.headers.get("MCP-Protocol-Version");
      if (version === MODERN) return rpcError(id, -32600, "Modern requests have no protocol session", 405, undefined, { Allow: "POST" });
      if (!version) return mismatch(id);
      if (version !== LEGACY) return unsupported(id, version);
      const session = await legacySession(request, env, actor, false);
      await identityCall(env, "/mcp/delete", { ...binding(actor), sessionId: session.sessionId });
      return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
    }
    if (request.method !== "POST") return rpcError(id, -32600, "Method not allowed", 405, undefined, { Allow: "POST, DELETE" });
    if (request.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
      return rpcError(id, -32600, "Content-Type must be application/json", 415);
    }
    const accept = (request.headers.get("Accept") ?? "").split(",").map(entry => entry.trim().toLowerCase());
    const accepts = (mime: string) => accept.some(entry => {
      const [type, ...parameters] = entry.split(";").map(part => part.trim());
      return type === mime && !parameters.some(parameter => /^q=0(?:\.0*)?$/.test(parameter));
    });
    if (!accepts("application/json") || !accepts("text/event-stream")) return rpcError(id, -32600, "Accept must include application/json and text/event-stream", 406);
    let message: Record<string, unknown>;
    try { message = await body(request, 1024 * 1024); }
    catch (error) {
      if (error instanceof ApiError && error.message === "invalid_json") return rpcError(id, -32700, "Parse error");
      if (error instanceof ApiError && error.message === "expected_object") return rpcError(id, -32600, "A single JSON-RPC request or notification is required");
      throw error;
    }
    const hasId = Object.hasOwn(message, "id");
    if (typeof message.id === "string" || (typeof message.id === "number" && Number.isSafeInteger(message.id))) id = message.id;
    if (message.jsonrpc !== "2.0" || typeof message.method !== "string" || !message.method || (hasId && id === null)
      || Object.hasOwn(message, "result") || Object.hasOwn(message, "error")) return rpcError(id, -32600, "Invalid request");
    if (message.params !== undefined && !object(message.params)) return rpcError(id, -32602, "Invalid params");
    const params = object(message.params) ? message.params : {};
    const meta = object(params._meta) ? params._meta : null;
    const headerVersion = request.headers.get("MCP-Protocol-Version");
    const modern = (meta !== null && Object.hasOwn(meta, `${META}protocolVersion`))
      || (message.method !== "initialize" && headerVersion === MODERN);
    if (modern) {
      const headerMethod = request.headers.get("Mcp-Method");
      if (!headerVersion || !/^[\x21-\x7e]+$/.test(headerVersion) || headerMethod !== message.method
        || !/^[\x09\x20-\x7e]+$/.test(headerMethod) || headerMethod.trim() !== headerMethod) return mismatch(id);
      if (!meta || typeof meta[`${META}protocolVersion`] !== "string") return rpcError(id, -32602, "Required protocol metadata is missing");
      if (headerVersion !== meta[`${META}protocolVersion`]) return mismatch(id);
      const sourceName = message.method === "resources/read" ? params.uri : params.name;
      if (["tools/call", "resources/read", "prompts/get"].includes(message.method)) {
        if (typeof sourceName !== "string") return rpcError(id, -32602, "Invalid name");
        if (decodeName(request.headers.get("Mcp-Name")) !== sourceName) return mismatch(id);
      }
      if (headerVersion !== MODERN) return unsupported(id, headerVersion);
      const client = meta[`${META}clientInfo`];
      if (!object(client) || typeof client.name !== "string" || !client.name || typeof client.version !== "string" || !client.version
        || !object(meta[`${META}clientCapabilities`])) return rpcError(id, -32602, "Required client metadata is missing or invalid");
      // A legacy session identifier must not make a modern request stateful.
    } else if (message.method === "initialize") {
      if (!hasId) return rpcError(id, -32600, "initialize must be a request");
      if (request.headers.has("MCP-Session-Id")) return rpcError(id, -32600, "Session is already initialized");
      const client = params.clientInfo;
      if (typeof params.protocolVersion !== "string" || !params.protocolVersion || !object(params.capabilities)
        || !object(client) || typeof client.name !== "string" || !client.name || typeof client.version !== "string" || !client.version) {
        return rpcError(id, -32602, "Invalid initialize params");
      }
      if (headerVersion !== null && headerVersion !== params.protocolVersion) return mismatch(id);
      const session = await identityCall<McpSession>(env, "/mcp/create", { ...binding(actor), protocolVersion: LEGACY });
      return response({ jsonrpc: "2.0", id, result: { protocolVersion: LEGACY, capabilities: CAPABILITIES, serverInfo: SERVER_INFO, instructions: INSTRUCTIONS } }, 200, { "MCP-Session-Id": session.sessionId });
    } else {
      if (!headerVersion) return mismatch(id);
      if (headerVersion !== LEGACY) return unsupported(id, headerVersion);
      const session = await legacySession(request, env, actor, message.method === "tools/list" || message.method === "tools/call");
      if (message.method === "notifications/initialized" && !hasId) {
        await identityCall(env, "/mcp/initialized", { ...binding(actor), sessionId: session.sessionId });
        return new Response(null, { status: 202, headers: { "Cache-Control": "no-store" } });
      }
      if (message.method === "notifications/cancelled" && !hasId) {
        return new Response(null, { status: 202, headers: { "Cache-Control": "no-store" } });
      }
    }
    if (!hasId) return rpcError(id, -32601, "Notification is not supported", 400);
    let result: Record<string, unknown>;
    switch (message.method) {
      case "server/discover":
        if (!modern) return rpcError(id, -32601, "Method not found", 404);
        result = complete({ supportedVersions: [...MCP_PROTOCOL_VERSIONS], capabilities: CAPABILITIES, instructions: INSTRUCTIONS }, true);
        break;
      case "ping": result = complete({}, modern); break;
      case "tools/list":
        if (params.cursor !== undefined) return rpcError(id, -32602, "This complete tool catalog does not accept a cursor");
        result = complete({ tools: toolsFor(actor) }, modern);
        break;
      case "tools/call": {
        if (typeof params.name !== "string" || !params.name || (params.arguments !== undefined && !object(params.arguments))) return rpcError(id, -32602, "Invalid tools/call params");
        if (!hasManagementTool(params.name)) return rpcError(id, -32602, "Unknown tool");
        try { result = toolResult(await executeManagement(env, actor, params.name, params.arguments ?? {}, endpoint.origin), modern); }
        catch (error) { result = toolResult(failure(error), modern, true); }
        break;
      }
      default: return rpcError(id, -32601, "Method not found", 404);
    }
    return response({ jsonrpc: "2.0", id, result });
  } catch (error) {
    const detail = failure(error);
    return rpcError(id, detail.status >= 500 ? -32603 : -32000, detail.error, detail.status, { status: detail.status }, detail.status === 401 ? { "WWW-Authenticate": "Bearer" } : undefined);
  }
}
