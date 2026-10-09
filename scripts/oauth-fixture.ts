import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import https from "node:https";
import type { Duplex } from "node:stream";

export interface ControlledIdp {
  issuer: string;
  clientId: string;
  clientSecret: string;
  identity: { id: string; email: string; name: string; emailVerified: true };
  authorizationCount: number;
  tokenCount: number;
  profileCount: number;
  replayLastCode(): Promise<Response>;
  replayLastToken(): Promise<Response>;
  close(): Promise<void>;
}
/** Actual, isolated OAuth issuer: TLS, registered client, PKCE, single-use codes/tokens and authenticated profile endpoint. */
export async function createControlledIdp(certificate: string, key: string, redirectURI: string): Promise<ControlledIdp> {
  const clientId = randomBytes(24).toString("hex"), clientSecret = randomBytes(32).toString("hex");
  const identity = { id: randomUUID(), email: "controlled-oauth-user@example.test", name: "Controlled OAuth Fixture", emailVerified: true as const };
  const codes = new Map<string, { challenge: string; expiresAt: number }>(), tokens = new Map<string, number>(), sockets = new Set<Duplex>();
  let authorizationCount = 0, tokenCount = 0, profileCount = 0, lastExchange: string | null = null, lastToken: string | null = null;
  const server = https.createServer({ cert: certificate, key }, (request, response) => {
    const url = new URL(request.url ?? "/", "https://127.0.0.1");
    const json = (status: number, value: unknown) => { response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" }); response.end(JSON.stringify(value)); };
    if (url.pathname === "/authorize" && request.method === "GET") {
      const parameters = url.searchParams, challenge = parameters.get("code_challenge"), state = parameters.get("state");
      if (parameters.get("client_id") !== clientId || parameters.get("redirect_uri") !== redirectURI || parameters.get("response_type") !== "code" || parameters.get("code_challenge_method") !== "S256" || !challenge || !state) { json(400, { error: "invalid_request" }); return; }
      authorizationCount++;
      const code = randomBytes(32).toString("base64url"); codes.set(code, { challenge, expiresAt: Date.now() + 60000 });
      const callback = new URL(redirectURI); callback.searchParams.set("code", code); callback.searchParams.set("state", state);
      response.writeHead(302, { Location: callback.href, "Cache-Control": "no-store" }); response.end(); return;
    }
    if (url.pathname === "/token" && request.method === "POST") {
      let data = "";
      request.setEncoding("utf8");
      request.on("data", chunk => { data += chunk; if (data.length > 16384) request.destroy(); });
      request.on("end", () => {
        tokenCount++;
        const parameters = new URLSearchParams(data), code = parameters.get("code") ?? "", stored = codes.get(code), verifier = parameters.get("code_verifier") ?? "";
        if (parameters.get("grant_type") !== "authorization_code" || parameters.get("client_id") !== clientId || parameters.get("client_secret") !== clientSecret || parameters.get("redirect_uri") !== redirectURI || !stored || stored.expiresAt <= Date.now() || createHash("sha256").update(verifier).digest("base64url") !== stored.challenge) { json(400, { error: "invalid_grant" }); return; }
        codes.delete(code); lastExchange = data;
        const token = randomBytes(32).toString("base64url"); lastToken = token; tokens.set(token, Date.now() + 300000);
        json(200, { access_token: token, token_type: "Bearer", expires_in: 300, scope: "email profile" });
      }); return;
    }
    if (url.pathname === "/userinfo" && request.method === "GET") {
      profileCount++;
      const token = request.headers.authorization?.startsWith("Bearer ") ? request.headers.authorization.slice(7) : "", expiresAt = tokens.get(token);
      if (!expiresAt || expiresAt <= Date.now()) { json(401, { error: "invalid_token" }); return; }
      tokens.delete(token); json(200, { id: identity.id, email: identity.email, name: identity.name, email_verified: identity.emailVerified }); return;
    }
    json(404, { error: "not_found" });
  });
  server.on("connection", socket => { sockets.add(socket); socket.on("error", () => {}); socket.on("close", () => sockets.delete(socket)); });
  const ready = Promise.withResolvers<void>(); server.once("error", ready.reject); server.listen(0, "127.0.0.1", ready.resolve); await ready.promise;
  const address = server.address(); assert(address && typeof address !== "string");
  const issuer = `https://127.0.0.1:${address.port}/`;
  return { issuer, clientId, clientSecret, identity,
    get authorizationCount() { return authorizationCount; }, get tokenCount() { return tokenCount; }, get profileCount() { return profileCount; },
    async replayLastCode() { assert(lastExchange); return fetch(new URL("/token", issuer), { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: lastExchange }); },
    async replayLastToken() { assert(lastToken); return fetch(new URL("/userinfo", issuer), { headers: { Authorization: `Bearer ${lastToken}` } }); },
    async close() { codes.clear(); tokens.clear(); for (const socket of sockets) socket.destroy(); const closed = Promise.withResolvers<void>(); server.close(() => closed.resolve()); await closed.promise; },
  };
}
