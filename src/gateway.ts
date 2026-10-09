import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import type { PgDatabase } from "./database";
import { ApiError } from "./validation";

export interface GatewayConfig { sourceOrigin: string; keyId: string; key: Buffer }
const signedHeaders = ["accept", "authorization", "content-type", "cookie", "idempotency-key", "last-event-id", "mcp-name", "mcp-protocol-version", "mcp-session-id", "mcp-method", "origin", "x-csrf-token"];
const workerAddress = "2a06:98c0:3600::103";
const account = "[A-Za-z0-9_-]{1,64}", event = "[A-Za-z0-9:_-]+";

/** Transport attestation never substitutes for the ordinary API/MCP credential. */
export function gatewayMachineRoute(path: string, method: string): boolean {
  if (path === "/mcp") return ["GET", "POST", "DELETE", "OPTIONS"].includes(method);
  if (new RegExp(`^/heartbeat/${account}/${account}$`).test(path)) return method === "POST";
  if (/^\/api\/public\/status\/[a-z0-9][a-z0-9-]{2,62}$/.test(path) || ["/api/session", "/api/capabilities", "/api/auth/sessions"].includes(path)) return method === "GET";
  if (["/api/auth/password", "/api/auth/sessions/revoke-others", "/api/operator/accounts"].includes(path)) return method === "POST";
  if (new RegExp(`^/api/auth/sessions/${account}$`).test(path)) return method === "DELETE";
  if (new RegExp(`^/api/operator/accounts/${account}/credits/${account}$`).test(path)) return method === "PUT";
  if (new RegExp(`^/api/operator/users/${account}/password$`).test(path)) return method === "POST";
  const legacy = path.match(new RegExp(`^/v1/accounts/${account}/(state|history|tick|credits/${account}|monitors(?:/${account}/(?:pause|resume))?)$`));
  if (legacy) return method === (legacy[1] === "state" || legacy[1] === "history" ? "GET" : legacy[1]!.startsWith("credits/") ? "PUT" : "POST");
  const scoped = path.match(new RegExp(`^/api/accounts/${account}/(.+)$`));
  if (!scoped) return false;
  const suffix = scoped[1]!;
  if (["state", "history", "incidents", "notifications", "usage", "export", "members", "audit", "coverage", "reports"].includes(suffix)) return method === "GET";
  if (["workspace", "notification-defaults", "status-page", "maintenance", "invitations"].includes(suffix)) return ["GET", "POST", "PUT", "DELETE"].includes(method);
  if (["monitors", "api-keys"].includes(suffix)) return ["GET", "POST"].includes(method);
  if (["settings/workspace", "settings/notification-defaults", "password", "settings/password", "settings/sessions/revoke", "settings/sessions/revoke-others", "monitors/bulk", "monitors/import", "notifications/retry", "status-page/unpublish", "team/invitations", "team/invitations/revoke", "team/members/role", "team/members/remove"].includes(suffix)) return ["POST", "PUT", "DELETE"].includes(method);
  if (suffix === "status-page/updates") return method === "POST";
  if (new RegExp(`^monitors/${account}/heartbeat-instructions$`).test(suffix)) return method === "GET";
  if (new RegExp(`^monitors/${account}$`).test(suffix)) return ["GET", "PUT", "DELETE"].includes(method);
  return ["POST", "PUT", "DELETE"].includes(method) && new RegExp(`^(?:monitors/${account}/(?:edit|delete|pause|resume|heartbeat-token|notification-test|check-now)|maintenance/${account}(?:/cancel)?|incidents/${event}/acknowledgement|(?:invitations|api-keys|members|status-page/updates)/${account}|notifications/${event}/retry)$`).test(suffix);
}

/** An invalid or disabled attestation fails closed; it cannot become direct ingress. */
export async function verifyGateway(config: GatewayConfig | undefined, database: PgDatabase, url: URL, method: string, headers: Headers, body: Buffer, trustedProxy: boolean): Promise<string | null> {
  const attestation = headers.get("X-Tomato-Gateway-V1");
  if (attestation === null) return null;
  if (!config || !trustedProxy || attestation.length > 12000 || /%|\\|\/\//.test(url.pathname) || !gatewayMachineRoute(url.pathname, method)) throw new ApiError(403, "invalid_gateway_attestation");
  const parts = attestation.split(".");
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]!) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1]!)) throw new ApiError(403, "invalid_gateway_attestation");
  const signature = createHmac("sha256", config.key).update("tomato-gateway-v1." + parts[0]).digest("base64url");
  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(parts[1]!))) throw new ApiError(403, "invalid_gateway_attestation");
  const raw = Buffer.from(parts[0]!, "base64url");
  let fields: unknown; try { fields = JSON.parse(raw.toString("utf8")); } catch { throw new ApiError(403, "invalid_gateway_attestation"); }
  if (raw.toString("base64url") !== parts[0] || !Array.isArray(fields) || fields.length !== 14) throw new ApiError(403, "invalid_gateway_attestation");
  const [version, keyId, source, target, signedMethod, path, originalOrigin, clientIP, timestamp, nonce, length, bodyDigest, headerDigest, addressKind] = fields;
  const now = Date.now();
  if (version !== 1 || keyId !== config.keyId || source !== config.sourceOrigin || target !== url.origin || signedMethod !== method || path !== url.pathname + url.search || originalOrigin !== null && originalOrigin !== config.sourceOrigin || typeof clientIP !== "string" || !isIP(clientIP) || typeof timestamp !== "number" || !Number.isSafeInteger(timestamp) || Math.abs(now - timestamp) > 30000 || typeof nonce !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(nonce) || length !== body.length || addressKind !== "edge-provider" && addressKind !== "worker-shared" || addressKind === "worker-shared" && clientIP !== workerAddress || addressKind === "edge-provider" && clientIP === workerAddress) throw new ApiError(403, "invalid_gateway_attestation");
  const context = JSON.stringify(signedHeaders.map(name => [name, headers.get(name)]));
  if (headers.get("Origin") !== (originalOrigin === null ? null : url.origin) || bodyDigest !== createHash("sha256").update(body).digest("base64url") || headerDigest !== createHash("sha256").update(context).digest("base64url")) throw new ApiError(403, "invalid_gateway_attestation");
  const cookie = headers.get("Cookie");
  if (cookie !== null && !(url.pathname === "/mcp" && cookie === "__tomato_legacy_cookie_present=1")) throw new ApiError(403, "invalid_gateway_attestation");
  // One statement commits admission before product dispatch. Retain future clock skew.
  const admitted = await database.query("WITH expired AS (DELETE FROM identity.gateway_nonces WHERE expires_at<=$1) INSERT INTO identity.gateway_nonces(key_id,nonce,expires_at) VALUES($2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce", [now, config.keyId, nonce, timestamp + 30001]);
  if (admitted.length !== 1) throw new ApiError(403, "gateway_replay");
  return clientIP;
}
