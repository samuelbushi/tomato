import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import tls from "node:tls";
import { promisify } from "node:util";
import type { IdentityConfig } from "../src/identity.ts";

export interface SmtpFixture {
  smtp: NonNullable<IdentityConfig["smtp"]>;
  certificate: string;
  privateKey: string;
  messages: string[];
  stop(): Promise<void>;
  close(): Promise<void>;
}
/** Owned real TLS SMTP receipt endpoint shared by auth acceptance; no simulated delivery. */
export async function createSmtpFixture(): Promise<SmtpFixture> {
  if (process.env.NODE_ENV === "production") throw new Error("smtp_test_fixture_disabled_in_production");
  const scratch = await mkdtemp(path.join(tmpdir(), "tomato-auth-smtp-")), cert = path.join(scratch, "smtp.pem"), key = path.join(scratch, "smtp.key");
  const messages: string[] = [], sockets = new Set<tls.TLSSocket>();
  let server: tls.Server | undefined, stopping: Promise<void> | undefined;
  const stop = (): Promise<void> => {
    if (stopping) return stopping;
    for (const socket of sockets) socket.destroy();
    const stopped = Promise.withResolvers<void>(); stopping = stopped.promise;
    if (server?.listening) server.close(error => error ? stopped.reject(error) : stopped.resolve()); else stopped.resolve();
    return stopping;
  };
  try {
    await promisify(execFile)("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"]);
    const certificate = await readFile(cert, "utf8"), privateKey = await readFile(key, "utf8");
    server = tls.createServer({ cert: certificate, key: privateKey }, socket => {
      sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.on("error", () => {}); socket.setEncoding("utf8"); socket.write("220 Tomato controlled SMTP fixture\r\n");
      let buffered = "", collecting = false, message = "";
      socket.on("data", chunk => {
        buffered += chunk;
        while (buffered.includes("\r\n")) { const index = buffered.indexOf("\r\n"), line = buffered.slice(0, index); buffered = buffered.slice(index + 2);
          if (collecting) { if (line === ".") { messages.push(message); message = ""; collecting = false; socket.write("250 Accepted\r\n"); } else message += `${line.startsWith("..") ? line.slice(1) : line}\r\n`; }
          else if (/^(EHLO|HELO)/.test(line)) socket.write("250-localhost\r\n250 8BITMIME\r\n");
          else if (/^(MAIL FROM|RCPT TO|RSET|NOOP)/.test(line)) socket.write("250 OK\r\n");
          else if (line === "DATA") { collecting = true; socket.write("354 End with dot\r\n"); }
          else if (line === "QUIT") socket.end("221 Bye\r\n");
          else socket.write("500 Unsupported\r\n");
        }
      });
    });
    const listening = Promise.withResolvers<void>(); server.once("error", listening.reject); server.listen(0, "127.0.0.1", listening.resolve); await listening.promise;
    const address = server.address(); assert(address && typeof address !== "string");
    return { smtp: { host: "127.0.0.1", port: address.port, secure: true, from: "Tomato <auth@example.test>", ca: certificate }, certificate, privateKey, messages, stop,
      async close() { try { await stop(); } finally { await rm(scratch, { recursive: true, force: true }); } },
    };
  } catch (error) { try { await stop(); } finally { await rm(scratch, { recursive: true, force: true }); } throw error; }
}
