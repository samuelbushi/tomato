import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { isIP } from "node:net";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as NodeReadableStream } from "node:stream/web";
import pg from "pg";
import { PgDatabase } from "./database";
import { databaseConfig, gatewayConfig, identityConfig, ownerConfig, secret } from "./config";
import { createProber } from "./egress";
import { createRuntime } from "./runtime";
import type { TomatoRuntime } from "./runtime";
import worker from "./worker";
import { verifyGateway, type GatewayConfig } from "./gateway";
import { ApiError } from "./validation";
const emptyBody = Buffer.alloc(0);
const criticalHeader = /^(?:host|authorization|cookie|origin|content-length|transfer-encoding|idempotency-key|mcp-session-id|mcp-protocol-version|mcp-method|mcp-name|x-csrf-token|x-tomato-gateway-v1|x-tomato-client-ip)$/i;

export interface HttpServerOptions {
  trustedProxyIPs?: string[];
  requireProxy?: boolean;
  gateway?: GatewayConfig;
}

export function createHttpServer(runtime: TomatoRuntime, origin: string, options: HttpServerOptions = {}) {
  const expected = new URL(origin);
  const trustedProxyIPs = options.trustedProxyIPs ?? [];
  if (trustedProxyIPs.some(ip => !isIP(ip)) || options.requireProxy && !trustedProxyIPs.length) throw new Error("invalid_trusted_proxy_configuration");
  const server = createServer({ maxHeaderSize: 16_384 }, async (incoming, outgoing) => {
    const disconnected = new AbortController();
    outgoing.once("close", () => { if (!outgoing.writableFinished) disconnected.abort(); });
    try {
      if (!incoming.url?.startsWith("/") || incoming.url.startsWith("//")) { outgoing.writeHead(400); outgoing.end(); return; }
      if (incoming.headers.host !== expected.host) { outgoing.writeHead(421); outgoing.end(); return; }
      const url = new URL(incoming.url, origin);
      if (url.pathname === "/health/live") { outgoing.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" }); outgoing.end('{"live":true}'); return; }
      if (url.pathname === "/health/ready") {
        const ready = await runtime.ready();
        outgoing.writeHead(ready ? 200 : 503, { "Content-Type": "application/json", "Cache-Control": "no-store" }); outgoing.end(JSON.stringify({ ready, mode: runtime.env.MODE })); return;
      }
      const peerIP = incoming.socket.remoteAddress?.replace(/^::ffff:/, "") ?? "";
      const trustedProxy = trustedProxyIPs.includes(peerIP);
      if (options.requireProxy && !trustedProxy) { outgoing.writeHead(403); outgoing.end(); return; }
      const headers = new Headers();
      const seen = new Set<string>();
      for (let i = 0; i < incoming.rawHeaders.length; i += 2) {
        const name = incoming.rawHeaders[i]!;
        const lower = name.toLowerCase();
        if (criticalHeader.test(lower) && seen.has(lower)) { outgoing.writeHead(400); outgoing.end(); incoming.resume(); return; }
        seen.add(lower);
        if (!/^(?:host|connection|transfer-encoding|upgrade|forwarded|x-forwarded-.*|x-tomato-client-ip)$/i.test(name)) headers.append(name, incoming.rawHeaders[i + 1]!);
      }
      const forwardedIP = incoming.headers["x-tomato-client-ip"];
      const directIP = trustedProxy && typeof forwardedIP === "string" && isIP(forwardedIP) ? forwardedIP : peerIP;
      const chunks: Buffer[] = [];
      let bytes = 0;
      if (Number(incoming.headers["content-length"]) > 1_048_576) { outgoing.writeHead(413); outgoing.end(); incoming.resume(); return; }
      for await (const chunk of incoming) {
        bytes += chunk.length;
        if (bytes > 1_048_576) { outgoing.writeHead(413); outgoing.end(); incoming.destroy(); return; }
        chunks.push(chunk);
      }
      const rawBody = bytes > 0 ? Buffer.concat(chunks, bytes) : emptyBody;
      const attestedIP = await verifyGateway(options.gateway, runtime.env.database, url, incoming.method ?? "GET", headers, rawBody, trustedProxy);
      for (const name of Array.from(headers.keys())) if (/^(?:x-tomato-.*|cf-.*|x-real-ip|true-client-ip)$/i.test(name)) headers.delete(name);
      const clientIP = attestedIP ?? directIP;
      if (isIP(clientIP)) headers.set("X-Tomato-Client-IP", clientIP);
      const request = new Request(url, { method: incoming.method, headers, signal: disconnected.signal,
        ...(bytes > 0 && incoming.method !== "GET" && incoming.method !== "HEAD" ? { body: rawBody as unknown as BodyInit } : {}) });
      const response = await worker.fetch(request, runtime.env);
      const responseHeaders: Record<string, string | string[]> = {};
      response.headers.forEach((value, name) => { if (name !== "set-cookie" && !/^(?:connection|transfer-encoding)$/i.test(name)) responseHeaders[name] = value; });
      const cookies = response.headers.getSetCookie();
      if (cookies.length) responseHeaders["set-cookie"] = cookies;
      outgoing.writeHead(response.status, responseHeaders);
      if (incoming.method === "HEAD" || !response.body) { outgoing.end(); return; }
      await pipeline(Readable.fromWeb(response.body as NodeReadableStream), outgoing);
    } catch (error) {
      if (!outgoing.headersSent) { outgoing.writeHead(error instanceof ApiError ? error.status : 500, { "Content-Type": "application/json", "Cache-Control": "no-store" }); outgoing.end(JSON.stringify({ error: error instanceof ApiError ? error.message : "internal_error" })); }
      else outgoing.destroy();
    }
  });
  server.requestTimeout = 35_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5000;
  return server;
}

async function main() {
  const auth = await identityConfig();
  const mode = process.env.TOMATO_MODE ?? "self-host";
  if (mode !== "self-host" && mode !== "hosted") throw new Error("invalid_runtime_mode");
  if (process.env.TEST_MODE === "true") throw new Error("production_entrypoint_disallows_test_mode");
  const workloads = process.env.TOMATO_WORKLOADS_ENABLED;
  if (workloads !== undefined && workloads !== "true" && workloads !== "false") throw new Error("invalid_workload_enablement");
  const database = new PgDatabase(new pg.Pool(await databaseConfig()));
  database.pool.on("error", () => { console.error("database_connection_unavailable"); });
  const prober = createProber(process.env.TOMATO_PROBER_URL ?? "http://prober:8080/execute", (await secret("TOMATO_PROBER_TOKEN"))!);
  let runtime: TomatoRuntime | undefined;
  try {
    runtime = await createRuntime({ database, origin: auth.baseURL, authSecret: auth.secret, dataKey: (await secret("DATA_KEY"))!, engineToken: (await secret("TOMATO_ENGINE_TOKEN"))!, mode, prober,
      smtp: auth.smtp, github: auth.github, google: auth.google, legacyMigration: auth.legacyMigration, mailBudget: auth.mailBudget, workloadsEnabled: workloads !== "false", signupEnabled: auth.signupEnabled, owner: await ownerConfig() });
    const trustedProxyIPs = (process.env.TOMATO_TRUSTED_PROXY_IPS ?? "").split(",").filter(Boolean);
    if (process.env.TOMATO_HTTPS_PROXY !== "true") throw new Error("explicit_https_proxy_required");
    const bindHost = process.env.TOMATO_BIND_HOST ?? "127.0.0.1";
    if (!["127.0.0.1", "::1"].includes(bindHost) && !(bindHost === "0.0.0.0" && process.env.TOMATO_INTERNAL_NETWORK === "true")) throw new Error("public_http_binding_forbidden");
    const server = createHttpServer(runtime, auth.baseURL, { trustedProxyIPs, requireProxy: true, gateway: await gatewayConfig() });
    runtime.startBackground();
    const port = Number(process.env.PORT ?? 3000);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("invalid_listen_port");
    await new Promise<void>((resolveListen, reject) => { server.once("error", reject); server.listen(port, bindHost, resolveListen); });
    let closing = false;
    async function stop() {
      if (closing) return;
      closing = true;
      const deadline = setTimeout(() => process.exit(1), 45_000).unref();
      await new Promise<void>(done => { server.close(() => done()); server.closeIdleConnections(); });
      await runtime!.stop(); await database.close(); clearTimeout(deadline);
    }
    process.once("SIGTERM", () => { void stop(); });
    process.once("SIGINT", () => { void stop(); });
    console.log(`tomato_listening port=${port} mode=${mode}`);
  } catch (error) { await runtime?.stop(); await database.close(); throw error; }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { console.error("tomato_startup_failed"); process.exitCode = 1; });
}
