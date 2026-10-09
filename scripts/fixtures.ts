import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import { promisify } from "node:util";
import dnsPacket from "dns-packet";

export type Availability = "up" | "down" | "stall";
export interface WebhookReceipt { body: string; headers: http.IncomingHttpHeaders; receivedAt: number }
export interface HttpResponsePlan { status?: number; headers?: Record<string, string>; body?: string | Uint8Array; delayMs?: number }
export interface Fixtures {
  ca: string;
  httpUrl: string;
  secondHttpUrl: string;
  httpsUrl: string;
  dohUrl: string;
  invalidHttpsUrl: string;
  websocketUrl: string;
  tcpPort: number;
  tlsPort: number;
  invalidTlsPort: number;
  webhookUrl: string;
  receipts: WebhookReceipt[];
  acceptedWebhooks: Map<string, { body: string; receivedAt: number }>;
  requestHeaders: Map<string, http.IncomingHttpHeaders[]>;
  streamWrites: Map<string, number>;
  hits: Map<string, number>;
  set(name: string, availability: Availability): void;
  httpSequence(name: string, responses: HttpResponsePlan[]): void;
  webhookPlan(responses: Array<"reject" | "lose-response" | "accept">): void;
  dnsResponse(name: string, response: "malformed" | "mismatched"): void;
  websocketMessage(name: string, message: string): void;
  streamBanner(name: "tcp" | "tls", chunks: string[], delayMs?: number): void;
  close(): Promise<void>;
}

const run = promisify(execFile);
type Server = http.Server | https.Server | net.Server | tls.Server;

export async function createFixtures(scratch: string): Promise<Fixtures> {
  const servers: Server[] = [];
  const sockets = new Set<net.Socket>();
  const modes = new Map<string, Availability>();
  const hits = new Map<string, number>();
  const receipts: WebhookReceipt[] = [];
  const acceptedWebhooks = new Map<string, { body: string; receivedAt: number }>();
  const requestHeaders = new Map<string, http.IncomingHttpHeaders[]>();
  const streamWrites = new Map<string, number>();
  const timers = new Set<NodeJS.Timeout>();
  const httpSequences = new Map<string, { responses: HttpResponsePlan[]; next: number }>();
  const dnsResponses = new Map<string, "malformed" | "mismatched">();
  const websocketMessages = new Map<string, string>();
  const streamBanners = new Map<string, { chunks: string[]; delayMs: number }>();
  let webhookResponses: Array<"reject" | "lose-response" | "accept"> = [];
  let nextWebhook = 0;
  const later = (delayMs: number, action: () => void): void => {
    const timer = setTimeout(() => { timers.delete(timer); action(); }, delayMs);
    timers.add(timer);
  };
  const observe = (name: string): Availability => {
    hits.set(name, (hits.get(name) ?? 0) + 1);
    return modes.get(name) ?? "up";
  };
  const close = async (): Promise<void> => {
    for (const timer of timers) clearTimeout(timer);
    timers.clear();
    for (const socket of sockets) socket.destroy();
    const closed: Promise<void>[] = [];
    for (const server of servers) {
      if (!server.listening) continue;
      const completion = Promise.withResolvers<void>();
      server.close(error => error ? completion.reject(error) : completion.resolve());
      closed.push(completion.promise);
    }
    await Promise.all(closed);
  };
  const listen = async (server: Server): Promise<number> => {
    servers.push(server);
    server.on("connection", socket => {
      sockets.add(socket);
      socket.on("error", () => {});
      socket.on("close", () => sockets.delete(socket));
    });
    const listening = Promise.withResolvers<void>();
    server.once("error", listening.reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", listening.reject); listening.resolve(); });
    await listening.promise;
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Fixture has no TCP port");
    return address.port;
  };
  try {
    const caKey = path.join(scratch, "ca.key");
    const caCert = path.join(scratch, "ca.pem");
    const keyFile = path.join(scratch, "server.key");
    const csr = path.join(scratch, "server.csr");
    const certFile = path.join(scratch, "server.pem");
    const ext = path.join(scratch, "server.ext");
    await writeFile(ext, "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n");
    await run("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Tomato Local Verification CA", "-keyout", caKey, "-out", caCert]);
    await run("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", keyFile, "-out", csr]);
    await run("openssl", ["x509", "-req", "-in", csr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial", "-days", "2", "-extfile", ext, "-out", certFile]);
    const [ca, key, cert] = await Promise.all([readFile(caCert, "utf8"), readFile(keyFile, "utf8"), readFile(certFile, "utf8")]);
    const invalidExt = path.join(scratch, "invalid-server.ext");
    const invalidCertFile = path.join(scratch, "invalid-server.pem");
    await writeFile(invalidExt, "subjectAltName=DNS:not-localhost.example.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n");
    await run("openssl", ["x509", "-req", "-in", csr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial", "-days", "2", "-extfile", invalidExt, "-out", invalidCertFile]);
    const invalidCert = await readFile(invalidCertFile, "utf8");
    const handler = (request: http.IncomingMessage, response: http.ServerResponse): void => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const name = url.pathname.slice(1) || "http";
      const mode = observe(name);
      const captured = requestHeaders.get(name) ?? [];
      captured.push({ ...request.headers });
      requestHeaders.set(name, captured);
      const sequence = httpSequences.get(name);
      const planned = sequence?.responses[Math.min(sequence.next++, sequence.responses.length - 1)];
      if (mode === "stall") return;
      if (planned) {
        const send = (): void => {
          if (response.destroyed) return;
          response.writeHead(planned.status ?? 200, { "Content-Type": "text/plain", ...planned.headers });
          response.end(planned.body ?? "TOMATOOK");
        };
        if (planned.delayMs) later(planned.delayMs, send);
        else send();
        return;
      }
      if (url.pathname === "/redirect-private") {
        response.writeHead(302, { Location: "http://169.254.169.254/latest/meta-data/" }); response.end(); return;
      }
      response.writeHead(mode === "down" ? 503 : 200, { "Content-Type": "text/plain" });
      response.end(mode === "down" ? "fixture unavailable" : "TOMATOOK");
    };
    const httpPort = await listen(http.createServer(handler));
    const secondHttpPort = await listen(http.createServer(handler));
    const httpsPort = await listen(https.createServer({ key, cert }, handler));
    const invalidHttpsPort = await listen(https.createServer({ key, cert: invalidCert }, handler));
    const dohPort = await listen(http.createServer(async (request, response) => {
      try {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        const chunks: Buffer[] = [];
        for await (const chunk of request) chunks.push(Buffer.from(chunk));
        const wire = request.method === "GET" ? Buffer.from(url.searchParams.get("dns") ?? "", "base64url") : Buffer.concat(chunks);
        const query = dnsPacket.decode(wire);
        const question = query.questions?.[0];
        if (!question) throw new Error("No DNS question");
        const name = question.name.replace(/\.$/, "");
        const mode = observe(name);
        if (mode === "stall") return;
        if (name === "resolver-error.example.com") { response.writeHead(503); response.end(); return; }
        if (dnsResponses.get(name) === "malformed") {
          response.writeHead(200, { "Content-Type": "application/dns-message" });
          response.end(Buffer.from([0xff, 0x00, 0x01]));
          return;
        }
        const common = { name: question.name, ttl: 1, class: "IN" as const };
        const answers: dnsPacket.Answer[] = [];
        if (mode === "up") {
          switch (question.type) {
            case "A": answers.push({ ...common, type: "A", data: name === "private-record.example.com" ? "10.20.30.40" : "127.0.0.1" }); break;
            case "AAAA": answers.push({ ...common, type: "AAAA", data: "::1" }); break;
            case "TXT": answers.push({ ...common, type: "TXT", data: [Buffer.from("TOMATOOK")] }); break;
            case "MX": answers.push({ ...common, type: "MX", data: { preference: 10, exchange: "mail.fixture.test" } }); break;
            case "NS": answers.push({ ...common, type: "NS", data: "ns.fixture.test" }); break;
            case "CNAME": answers.push({ ...common, type: "CNAME", data: "alias.fixture.test" }); break;
          }
        }
        const encoded = dnsPacket.encode({ type: "response", id: dnsResponses.get(name) === "mismatched" ? (query.id! + 1) & 0xffff : query.id, flags: dnsPacket.AUTHORITATIVE_ANSWER | (mode === "down" ? 3 : 0), questions: query.questions, answers });
        response.writeHead(200, { "Content-Type": "application/dns-message" }); response.end(encoded);
      } catch {
        response.writeHead(400); response.end("Malformed DNS wire request");
      }
    }));
    const websocket = http.createServer((_request, response) => { response.writeHead(426); response.end(); });
    websocket.on("upgrade", (request, socket) => {
      const name = new URL(request.url ?? "/", "http://127.0.0.1").pathname.slice(1) || "websocket";
      const mode = observe(name);
      if (mode === "stall") return;
      if (mode === "down") { socket.end("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"); return; }
      const keyHeader = request.headers["sec-websocket-key"];
      if (typeof keyHeader !== "string") { socket.destroy(); return; }
      const accept = createHash("sha1").update(`${keyHeader}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
      // The fixture sends a real RFC6455 text frame; the production prober owns its client handshake.
      const payload = Buffer.from(websocketMessages.get(name) ?? "TOMATOOK");
      const frame = payload.length < 126 ? Buffer.from([0x81, payload.length]) : Buffer.alloc(4);
      if (payload.length >= 126) { frame[0] = 0x81; frame[1] = 126; frame.writeUInt16BE(payload.length, 2); }
      socket.write(Buffer.concat([frame, payload]));
      socket.on("data", chunk => {
        if ((chunk[0] ?? 0) % 16 === 8) socket.end(Buffer.from([0x88, 0]));
      });
    });
    const websocketPort = await listen(websocket);
    const streamHandler = (name: string) => (socket: net.Socket): void => {
      const mode = observe(name);
      if (mode === "stall") return;
      socket.once("data", () => {
        const plan = streamBanners.get(name);
        const chunks = mode === "down" ? ["WRONG_REPLY"] : plan?.chunks ?? ["TOMATOOK"];
        const send = (index: number): void => {
          if (socket.destroyed) return;
          const chunk = chunks[index];
          if (chunk === undefined) { socket.end(); return; }
          streamWrites.set(name, (streamWrites.get(name) ?? 0) + 1);
          if (index === chunks.length - 1) socket.end(chunk);
          else { socket.write(chunk); later(plan?.delayMs ?? 25, () => send(index + 1)); }
        };
        send(0);
      });
    };
    const tcpPort = await listen(net.createServer(streamHandler("tcp")));
    const tlsServer = tls.createServer({ key, cert }, streamHandler("tls"));
    tlsServer.on("tlsClientError", () => {});
    const tlsPort = await listen(tlsServer);
    const invalidTlsServer = tls.createServer({ key, cert: invalidCert }, streamHandler("invalid_tls"));
    invalidTlsServer.on("tlsClientError", () => {});
    const invalidTlsPort = await listen(invalidTlsServer);
    const webhookPort = await listen(http.createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      const receipt = { body: Buffer.concat(chunks).toString("utf8"), headers: request.headers, receivedAt: Date.now() };
      receipts.push(receipt);
      const planned = webhookResponses[nextWebhook++] ?? "accept";
      if (planned === "reject") { response.writeHead(503); response.end("rejected"); return; }
      const idempotencyKey = request.headers["idempotency-key"];
      if (typeof idempotencyKey === "string" && !acceptedWebhooks.has(idempotencyKey)) {
        acceptedWebhooks.set(idempotencyKey, { body: receipt.body, receivedAt: receipt.receivedAt });
      }
      if (planned === "lose-response") { request.socket.destroy(); return; }
      response.writeHead(200); response.end("accepted");
    }));
    return {
      ca, httpUrl: `http://127.0.0.1:${httpPort}`, secondHttpUrl: `http://127.0.0.1:${secondHttpPort}`,
      httpsUrl: `https://127.0.0.1:${httpsPort}`, invalidHttpsUrl: `https://127.0.0.1:${invalidHttpsPort}`,
      dohUrl: `http://127.0.0.1:${dohPort}/dns-query`, websocketUrl: `ws://127.0.0.1:${websocketPort}`,
      tcpPort, tlsPort, invalidTlsPort, webhookUrl: `http://127.0.0.1:${webhookPort}/webhook`,
      receipts, acceptedWebhooks, requestHeaders, streamWrites, hits,
      set: (name, mode) => { modes.set(name, mode); },
      httpSequence: (name, responses) => {
        if (!responses.length) { httpSequences.delete(name); return; }
        httpSequences.set(name, { responses: responses.map(response => ({ ...response, headers: response.headers && { ...response.headers }, body: response.body instanceof Uint8Array ? response.body.slice() : response.body })), next: 0 });
      },
      webhookPlan: responses => { webhookResponses = [...responses]; nextWebhook = 0; },
      dnsResponse: (name, response) => { dnsResponses.set(name, response); },
      websocketMessage: (name, message) => { websocketMessages.set(name, message); },
      streamBanner: (name, chunks, delayMs = 25) => {
        if (!chunks.length) streamBanners.delete(name);
        else streamBanners.set(name, { chunks: [...chunks], delayMs });
      },
      close,
    };
  } catch (error) { await close(); throw error; }
}
