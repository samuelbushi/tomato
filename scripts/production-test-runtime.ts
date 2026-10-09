import assert from "node:assert/strict";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { spawn, execFile, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer, type Server } from "node:http";
import { promisify } from "node:util";
import pg from "pg";
import { parseIntoClientConfig } from "pg-connection-string";
import { PgDatabase } from "../src/database.ts";
import { createRuntime, type RuntimeConfig, type TomatoRuntime } from "../src/runtime.ts";
import { createHttpServer, type HttpServerOptions } from "../src/server.ts";
import { createProber } from "../src/egress.ts";
import { tickAccounts, dispatchOutbox } from "../src/worker.ts";
import type { Env } from "../src/runtime-types.ts";
import { createFixtures, type Fixtures } from "./fixtures.ts";

export interface ProductionTestRuntime {
  database: PgDatabase;
  databaseUrl: string;
  baseUrl: string;
  token: string;
  env: Env;
  fixtures: Fixtures;
  fetch(input: Request | string | URL, init?: RequestInit): Promise<Response>;
  internalFetch(accountId: string, input: Request | string | URL, init?: RequestInit): Promise<Response>;
  startConsumer(): void;
  stopConsumer(): Promise<void>;
  restart(): Promise<void>;
  recover?: () => Promise<void>;
  close(): Promise<void>;
}
export interface ProductionTestOptions {
  background?: boolean;
  databaseConnections?: number;
  env?: Partial<Env>;
  fixtures?: Fixtures;
  runtime?: Partial<Omit<RuntimeConfig, "database" | "origin" | "authSecret" | "dataKey" | "engineToken" | "prober" | "allowLoopback">>;
  httpServer?: HttpServerOptions;
}

/** Every suite owns an independent database and non-bypass role; no shared data is reset. */
export async function createProductionTestRuntime(options: ProductionTestOptions = {}): Promise<ProductionTestRuntime> {
  assert(Number(process.versions.node.split(".")[0]) >= 24, "Production verification requires Node 24+");
  if (process.env.NODE_ENV === "production") throw new Error("test_runtime_disabled_in_production");
  const adminUrl = new URL(process.env.TEST_DATABASE_ADMIN_URL ?? "postgresql://localhost/postgres");
  if (!["postgres:", "postgresql:"].includes(adminUrl.protocol) || !["127.0.0.1", "localhost", "[::1]"].includes(adminUrl.hostname)) throw new Error("test_database_admin_must_be_local_postgresql");
  const id = `tomato_test_${randomBytes(12).toString("hex")}`;
  const password = randomBytes(32).toString("hex");
  const admin = new pg.Pool({ connectionString: adminUrl.href, max: 1 });
  const dbUrl = new URL(adminUrl);
  dbUrl.pathname = `/${id}`; dbUrl.username = id; dbUrl.password = password;
  const connections = options.databaseConnections ?? 12;
  assert(Number.isSafeInteger(connections) && connections >= 1 && connections <= 12, "Invalid owned runtime connection bound");
  const parameters = parseIntoClientConfig(dbUrl.href);
  const database = new PgDatabase(new pg.Pool({ ...parameters, max: connections, connectionTimeoutMillis: 2000 }));
  const token = randomBytes(32).toString("hex");
  const authSecret = randomBytes(32).toString("hex");
  const dataKey = randomBytes(32).toString("base64");
  const proberToken = randomBytes(32).toString("hex");
  let scratch: string | undefined;
  let fixtures: Fixtures | undefined;
  let proberProcess: ChildProcessWithoutNullStreams | undefined;
  let server: Server | undefined;
  let current: TomatoRuntime | undefined;
  let roleCreated = false, databaseCreated = false, closed = false;
  let timer: NodeJS.Timeout | undefined;
  let cycle: Promise<void> = Promise.resolve();
  let consumerEnabled = options.background !== false;
  let running = options.background !== false;
  let backgroundError: unknown;
  let baseUrl = "";
  const listen = async (target: Server, port = 0): Promise<number> => {
    await new Promise<void>((resolve, reject) => { target.once("error", reject); target.listen(port, "127.0.0.1", () => { target.off("error", reject); resolve(); }); });
    const address = target.address(); assert(address && typeof address !== "string"); return address.port;
  };
  const closeServer = async (target?: Server): Promise<void> => {
    if (!target?.listening) return;
    await new Promise<void>((resolve, reject) => { target.close(error => error ? reject(error) : resolve()); target.closeIdleConnections(); });
  };
  const closeProber = async (): Promise<void> => {
    const child = proberProcess;
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>(resolve => {
      const deadline = setTimeout(() => child.kill("SIGKILL"), 5000);
      child.once("exit", () => { clearTimeout(deadline); resolve(); });
      child.kill("SIGTERM");
    });
  };
  const cleanup = async (): Promise<void> => {
    if (closed) return;
    closed = true; running = false; clearTimeout(timer);
    const failures: unknown[] = [];
    for (const action of [() => cycle, () => closeServer(server), () => current?.stop(), closeProber, () => options.fixtures ? undefined : fixtures?.close(), () => database.close(),
      async () => { if (databaseCreated) await admin.query(`DROP DATABASE "${id}" WITH (FORCE)`); },
      async () => { if (roleCreated) await admin.query(`DROP ROLE "${id}"`); }, () => admin.end(),
      async () => { if (scratch) await rm(scratch, { recursive: true, force: true }); }]) {
      try { await action(); } catch (error) { failures.push(error); }
    }
    if (backgroundError) failures.push(backgroundError);
    if (failures.length) throw new AggregateError(failures, "production_test_cleanup_failed");
  };
  try {
    // Identifiers and password are cryptographically generated hex, never caller SQL.
    await admin.query(`CREATE ROLE "${id}" LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`); roleCreated = true;
    await admin.query(`CREATE DATABASE "${id}" OWNER "${id}"`); databaseCreated = true;
    await database.migrate();
    scratch = await mkdtemp(path.join(tmpdir(), "tomato-production-test-"));
    fixtures = options.fixtures ?? await createFixtures(scratch);
    const fixturePorts = [fixtures.httpUrl, fixtures.secondHttpUrl, fixtures.httpsUrl, fixtures.invalidHttpsUrl, fixtures.websocketUrl, fixtures.webhookUrl, fixtures.dohUrl].map(url => Number(new URL(url).port));
    fixturePorts.push(fixtures.tcpPort, fixtures.tlsPort, fixtures.invalidTlsPort);
    const proberEntry = new URL("../container/server.mjs", import.meta.url).href;
    const proberScript = `
      import { createEgressServer } from ${JSON.stringify(proberEntry)};
      let input = "";
      for await (const chunk of process.stdin) {
        input += chunk.toString();
        if (input.length > 65536) throw new Error("fixture_config_too_large");
      }
      const server = createEgressServer(JSON.parse(input));
      process.once("SIGTERM", () => { server.close(() => process.exit(0)); server.closeIdleConnections(); });
      server.listen(0, "127.0.0.1", () => { process.stdout.write(JSON.stringify({port:server.address().port}) + "\\n"); });
    `;
    // The prober's process receives no database, account, SMTP or admin credentials.
    proberProcess = spawn(process.execPath, ["--input-type=module", "-e", proberScript], {
      env: { NODE_ENV: "test", TOMATO_TRANSPORT_TEST: "1" }, stdio: ["pipe", "pipe", "pipe"],
    });
    const child = proberProcess;
    const startup = Promise.withResolvers<number>();
    const startupTimer = setTimeout(() => startup.reject(new Error("test_prober_startup_timeout")), 20000);
    let output = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      output += chunk;
      if (output.length > 4096) { startup.reject(new Error("invalid_test_prober_startup")); return; }
      if (!output.includes("\n")) return;
      try {
        const value: unknown = JSON.parse(output.split("\n")[0]!);
        assert(value && typeof value === "object" && "port" in value && typeof value.port === "number" && Number.isInteger(value.port) && value.port > 0 && value.port <= 65535);
        startup.resolve(value.port);
      } catch { startup.reject(new Error("invalid_test_prober_startup")); }
    });
    child.stderr.resume();
    child.once("error", error => { startup.reject(error); if (!closed) backgroundError = error; });
    child.once("exit", () => {
      startup.reject(new Error("test_prober_exited_before_startup"));
      if (!closed) backgroundError = new Error("test_prober_exited");
    });
    child.stdin.end(JSON.stringify({ token: proberToken, test: { allowLoopback: true, allowedPorts: fixturePorts, ca: fixtures.ca, resolverUrl: fixtures.dohUrl } }));
    let proberPort: number;
    try { proberPort = await startup.promise; } finally { clearTimeout(startupTimer); }
    const prober = createProber(`http://127.0.0.1:${proberPort}/execute`, proberToken);
    const reservation = createServer();
    const port = await listen(reservation);
    await closeServer(reservation);
    baseUrl = `http://127.0.0.1:${port}`;
    const initialize = async (): Promise<void> => {
      current = await createRuntime({ database, origin: baseUrl, authSecret, dataKey, engineToken: token, prober, allowLoopback: true, resolverUrl: fixtures!.dohUrl, minIntervalMs: 1000, signupEnabled: false, mode: "hosted", ...options.runtime });
      Object.assign(current.env, options.env);
      // Mandatory isolation controls cannot be disabled by consumer options.
      current.env.database = database; current.env.PROBER = prober; current.env.TEST_MODE = true; current.env.DATA_KEY = dataKey;
      server = createHttpServer(current, baseUrl, options.httpServer);
      await listen(server, port);
    };
    await initialize();
    const schedule = (): void => {
      if (!running || closed || backgroundError) return;
      timer = setTimeout(() => {
        cycle = (async () => {
          try { await tickAccounts(database, current!.env); if (consumerEnabled) await dispatchOutbox(database, current!.env, 4); }
          catch (error) { backgroundError = error; }
          finally { schedule(); }
        })();
      }, 75);
    };
    schedule();
    return {
      database, databaseUrl: dbUrl.href, baseUrl, token, fixtures,
      get env() { assert(current); return current.env; },
      async fetch(input, init) {
        if (backgroundError) throw backgroundError;
        const url = input instanceof Request ? new URL(input.url) : new URL(String(input), baseUrl);
        assert.equal(url.origin, baseUrl, "Test HTTP requests must remain in the exact owned runtime");
        const match = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9_-]+)\//);
        if (match) await database.query("INSERT INTO engine.accounts(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING", [match[1], match[1]]);
        return fetch(input instanceof Request ? input : url, init);
      },
      async internalFetch(accountId, input, init) {
        if (backgroundError) throw backgroundError;
        await database.query("INSERT INTO engine.accounts(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING", [accountId, accountId]);
        assert(current);
        return current.env.accounts.fetch(accountId, input instanceof Request ? input : new URL(String(input), baseUrl).href, init);
      },
      startConsumer() { consumerEnabled = true; if (!running) { running = true; schedule(); } },
      async stopConsumer() { consumerEnabled = false; await cycle; if (backgroundError) throw backgroundError; },
      async restart() {
        const resume = running; running = false; clearTimeout(timer); await cycle;
        if (backgroundError) throw backgroundError;
        await closeServer(server); await current!.stop(); await initialize();
        running = resume; schedule();
      },
      ...(process.env.TEST_DATABASE_RECOVERY_CONTAINER ? { recover: async () => {
        const container = process.env.TEST_DATABASE_RECOVERY_CONTAINER!, command = promisify(execFile);
        if (!/^[A-Za-z0-9_-]{1,100}$/.test(container)) throw new Error("owned_recovery_container_required");
        const label = (await command("docker", ["inspect", "--format", '{{index .Config.Labels "org.tomato.proof"}}', container], { timeout: 10000 })).stdout.trim();
        if (label !== "identity-enrollment-continuity") throw new Error("owned_recovery_container_required");
        const resume = running; running = false; clearTimeout(timer); await cycle;
        if (backgroundError) throw backgroundError;
        await closeServer(server); await current!.stop();
        const key = randomBytes(32), iv = randomBytes(12), aad = Buffer.from(`tomato-owned-pg18-recovery:${id}`), backup = path.join(scratch!, "recovery.aesgcm");
        let plaintext: Buffer | undefined, recovered: Buffer | undefined;
        try {
          const dumped = await command("docker", ["exec", container, "pg_dump", "-U", "postgres", "-d", id, "--format=custom", "--no-owner", "--no-acl"], { timeout: 30000, maxBuffer: 64 * 1024 * 1024, encoding: "buffer" });
          plaintext = dumped.stdout;
          const cipher = createCipheriv("aes-256-gcm", key, iv); cipher.setAAD(aad);
          await writeFile(backup, Buffer.concat([iv, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]), { mode: 0o600, flag: "wx" }); plaintext.fill(0);
          const bytes = await readFile(backup), decrypt = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12)); decrypt.setAAD(aad); decrypt.setAuthTag(bytes.subarray(-16));
          recovered = Buffer.concat([decrypt.update(bytes.subarray(12, -16)), decrypt.final()]);
          const restored = spawn("docker", ["exec", "-i", container, "pg_restore", "-U", id, "-d", id, "--clean", "--if-exists", "--no-owner", "--no-acl"], { stdio: ["pipe", "ignore", "ignore"] });
          const done = new Promise<void>((resolve, reject) => { restored.once("error", reject); restored.once("exit", code => code === 0 ? resolve() : reject(new Error("owned_pg18_restore_failed"))); });
          restored.stdin.on("error", () => {}); restored.stdin.end(recovered); await done;
          await initialize(); running = resume; schedule();
        } catch { throw new Error("owned_pg18_encrypted_recovery_failed"); }
        finally { plaintext?.fill(0); recovered?.fill(0); key.fill(0); await rm(backup, { force: true }); }
      } } : {}),
      close: cleanup,
    };
  } catch (error) {
    try { await cleanup(); } catch (cleanupError) { throw new AggregateError([error, cleanupError], "production_test_initialization_failed"); }
    throw error;
  }
}
