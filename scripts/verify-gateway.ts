import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import { createProductionTestRuntime } from "./production-test-runtime.ts";
import type { WalletView } from "../src/product-types.ts";

const key = randomBytes(32), sourceOrigin = "https://owned-gateway.example.test", keyId = "owned-gateway-proof";
const runtime = await createProductionTestRuntime({ background: false, httpServer: { trustedProxyIPs: ["127.0.0.1"], requireProxy: true, gateway: { sourceOrigin, keyId, key } } });
const contextHeaders = ["accept", "authorization", "content-type", "cookie", "idempotency-key", "last-event-id", "mcp-name", "mcp-protocol-version", "mcp-session-id", "mcp-method", "origin", "x-csrf-token"];
interface SignedRequest { path: string; method: string; headers: Headers; body: string }
function sign(path: string, method: string, body = "", authorization = `Bearer ${runtime.token}`, timestamp = Date.now()): SignedRequest {
  const url = new URL(path, runtime.baseUrl), headers = new Headers({ Accept: "application/json", Authorization: authorization });
  if (body) headers.set("Content-Type", "application/json");
  const payload = JSON.stringify([1, keyId, sourceOrigin, url.origin, method, url.pathname + url.search, null, "198.51.100.31", timestamp, randomBytes(16).toString("base64url"), Buffer.byteLength(body), createHash("sha256").update(body).digest("base64url"), createHash("sha256").update(JSON.stringify(contextHeaders.map(name => [name, headers.get(name)]))).digest("base64url"), "edge-provider"]);
  const encoded = Buffer.from(payload).toString("base64url");
  headers.set("X-Tomato-Gateway-V1", `${encoded}.${createHmac("sha256", key).update("tomato-gateway-v1." + encoded).digest("base64url")}`);
  return { path, method, headers, body };
}
// All calls share actual native HTTP parsing and the exact signed bytes.
const call = (request: SignedRequest) => runtime.fetch(request.path, { method: request.method, headers: request.headers, ...(request.body ? { body: request.body } : {}) });
try {
  const body = JSON.stringify({ id: "gateway-owner", name: "Owned gateway workspace", owner: { email: "gateway-owner@example.test", name: "Owned gateway operator", password: randomBytes(24).toString("hex"), emailVerified: true }, testingCredits: 7 });
  const original = sign("/api/operator/accounts", "POST", body);
  assert.equal((await call(original)).status, 201);
  assert.equal((await call(original)).status, 403);
  const initialUsage = await runtime.internalFetch("gateway-owner", "/usage"); assert.equal(initialUsage.status, 200);
  let wallet = await initialUsage.json() as WalletView;
  assert.equal(wallet.balance, 7); assert.equal(wallet.grants.length, 1);
  console.log("PASS signed native operator provisioning retains ordinary authorization and rejects replay before a second credit grant");

  const tampered = sign("/api/operator/accounts", "POST", body);
  tampered.body = body.replace('"testingCredits":7', '"testingCredits":700');
  assert.equal((await call(tampered)).status, 403);
  const headerChanged = sign("/api/operator/accounts", "POST", body); headerChanged.headers.set("Authorization", "Bearer replaced-after-signing");
  assert.equal((await call(headerChanged)).status, 403);
  const pathChanged = sign("/api/operator/accounts", "POST", body); pathChanged.path += "?replaced=1";
  assert.equal((await call(pathChanged)).status, 403);
  assert.equal((await call(sign("/api/operator/accounts", "POST", body, `Bearer ${runtime.token}`, Date.now() - 35000))).status, 403);
  assert.equal((await call(sign("/api/operator/accounts", "POST", body, "Bearer invalid-consumer"))).status, 401);
  console.log("PASS native body, authorization, query and stale-context tampering cannot mutate credits; transport attestation grants no operator authority");

  const denied = sign("/api/operator/accounts", "POST", body), target = new URL(denied.path, runtime.baseUrl);
  const duplicateStatus = await new Promise<number>((resolve, reject) => {
    const rawHeaders = Array.from(denied.headers.entries()).flat(); rawHeaders.push("Authorization", `Bearer ${runtime.token}`, "Host", target.host);
    const request = httpRequest(target, { method: "POST", headers: rawHeaders }, response => { response.resume(); response.once("end", () => resolve(response.statusCode!)); });
    request.once("error", reject); request.end(denied.body);
  });
  assert.equal(duplicateStatus, 400);
  console.log("PASS ambiguous duplicate authorization is rejected by actual native HTTP ingress before product dispatch");

  await runtime.restart();
  assert.equal((await call(original)).status, 403);
  const fresh = sign("/v1/accounts/gateway-owner/state", "GET"); assert.equal((await call(fresh)).status, 200);
  const restoredUsage = await runtime.internalFetch("gateway-owner", "/usage"); assert.equal(restoredUsage.status, 200);
  wallet = await restoredUsage.json() as WalletView;
  assert.equal(wallet.balance, 7); assert.equal(wallet.grants.length, 1);
  assert.equal((await runtime.database.query("SELECT id FROM engine.accounts WHERE id=$1", ["gateway-owner"])).length, 1);
  console.log("PASS persistent native replay fencing survives runtime restart while fresh authorized legacy API requests retain their workspace and wallet");
} finally { await runtime.close(); }
