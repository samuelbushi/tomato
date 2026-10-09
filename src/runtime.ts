import nodemailer from "nodemailer";
import { parse as parsePgConnection } from "pg-connection-string";
import { readFile } from "node:fs/promises";
import { createAccountService } from "./engine";
import { createIdentity } from "./identity";
import { emailIdentity } from "./auth";
import type { IdentityConfig, IdentityService, ProvisionInput } from "./identity";
import type { PgDatabase } from "./database";
import type { Env } from "./runtime-types";
import type { ProberService } from "./egress";
import { dispatchOutbox, tickAccounts } from "./worker";
import { admitMail, validateMailBudget } from "./mail-admission";

export interface RuntimeConfig {
  database: PgDatabase;
  origin: string;
  authSecret: string;
  engineToken: string;
  dataKey: string;
  mode?: "self-host" | "hosted";
  prober?: ProberService;
  allowLoopback?: boolean;
  resolverUrl?: string;
  minIntervalMs?: number;
  identity?: IdentityService;
  smtp?: IdentityConfig["smtp"];
  github?: IdentityConfig["github"];
  google?: IdentityConfig["google"];
  signupEnabled?: boolean;
  legacyMigration?: IdentityConfig["legacyMigration"];
  mailBudget?: IdentityConfig["mailBudget"];
  workloadsEnabled?: boolean;
  owner?: ProvisionInput;
}

export interface TomatoRuntime {
  env: Env;
  identity: IdentityService;
  startBackground(): void;
  ready(): Promise<boolean>;
  stop(): Promise<void>;
}

export async function createRuntime(config: RuntimeConfig): Promise<TomatoRuntime> {
  const origin = new URL(config.origin);
  const mode = config.mode ?? "self-host";
  if (origin.origin !== config.origin || origin.username || origin.password) throw new Error("invalid_origin");
  if (config.allowLoopback) {
    const options = config.database.pool.options;
    const host = options.connectionString ? parsePgConnection(options.connectionString).host : options.host;
    if (!["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname) || !["localhost", "127.0.0.1", "::1"].includes(String(host))) throw new Error("test_mode_requires_isolated_loopback");
  } else if (origin.protocol !== "https:" || !config.prober) throw new Error("production_requires_https_and_prober");
  if (config.authSecret.length < 32 || config.engineToken.length < 32) throw new Error("invalid_runtime_secrets");
  if (Buffer.from(config.dataKey, "base64").length !== 32) throw new Error("invalid_data_encryption_key");
  if (config.mailBudget) validateMailBudget(config.mailBudget);
  const role = await config.database.query<{ rolsuper: boolean; rolbypassrls: boolean }>("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user");
  if (!role[0] || role[0].rolsuper || role[0].rolbypassrls) throw new Error("runtime_database_role_must_enforce_rls");
  const identity = config.identity ?? createIdentity(config.database, {
    baseURL: config.origin, secret: config.authSecret, allowLoopback: config.allowLoopback,
    signupEnabled: config.signupEnabled ?? false, smtp: config.smtp, github: config.github, google: config.google, legacyMigration: config.legacyMigration, mailBudget: config.mailBudget,
  });
  const smtp = config.smtp ? nodemailer.createTransport({ host: config.smtp.host, port: config.smtp.port, secure: config.smtp.secure, requireTLS: !config.smtp.secure,
    connectionTimeout: 5000, greetingTimeout: 5000, socketTimeout: 10000, dnsTimeout: 5000,
    tls: { rejectUnauthorized: true, ...(config.smtp.ca ? { ca: config.smtp.ca } : {}) },
    ...(config.smtp.user ? { auth: { user: config.smtp.user, pass: config.smtp.password } } : {}) }) : undefined;
  const [css, javascript] = await Promise.all([readFile(new URL("../public/tomato.css", import.meta.url)), readFile(new URL("../public/tomato.js", import.meta.url))]);
  const assets: Record<string, Buffer> = { "/tomato.css": css, "/tomato.js": javascript };
  const env: Env = {
    database: config.database, identity, accounts: undefined as unknown as Env["accounts"], MODE: mode,
    AUTH_SECRET: config.authSecret, DATA_KEY: config.dataKey, ENGINE_TOKEN: config.engineToken, PROBER: config.prober,
    WORKLOADS_ENABLED: config.workloadsEnabled ?? true,
    ASSETS: {
      async fetch(input, init) {
        const request = input instanceof Request ? input : new Request(input, init);
        const path = new URL(request.url).pathname;
        const bytes = Object.hasOwn(assets, path) ? assets[path] : undefined;
        if (!bytes) return new Response(null, { status: 404 });
        if (request.method !== "GET" && request.method !== "HEAD") return new Response(null, { status: 405, headers: { Allow: "GET, HEAD" } });
        return new Response(request.method === "HEAD" ? null : bytes as unknown as BodyInit, { headers: {
          "Content-Type": path.endsWith(".css") ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8",
          "Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff", "Content-Length": String(bytes.byteLength),
        } });
      },
    },
    ...(config.allowLoopback ? { TEST_MODE: true, TEST_DNS_RESOLVER: config.resolverUrl, TEST_MIN_INTERVAL_MS: String(config.minIntervalMs ?? 1000) } : {}),
    ...(smtp && config.smtp ? { EMAIL_FROM: config.smtp.from, EMAIL: {
      async send(message) {
        if (config.workloadsEnabled === false) throw new Error("monitoring_workloads_disabled");
        await admitMail(config.database, config.mailBudget);
        const recipient = emailIdentity(message.to);
        const result = await smtp.sendMail({ from: config.smtp!.from, to: { address: recipient, name: "" }, subject: message.subject, text: message.text, headers: message.headers });
        if (!result.accepted.some(address => String(address).toLowerCase() === recipient)) throw new Error("smtp_recipient_not_accepted");
      },
    } } : {}),
  };
  env.accounts = createAccountService(config.database, env);
  if (config.owner) await identity.ensureBootstrapOwner(config.owner);
  let stopping = false;
  let started = false;
  let tickTimer: NodeJS.Timeout | undefined;
  let dispatchTimer: NodeJS.Timeout | undefined;
  let tickWork: Promise<void> = Promise.resolve();
  let dispatchWork: Promise<void> = Promise.resolve();
  let lastTick = 0;
  let lastDispatch = 0;
  async function tick() {
    try { await tickAccounts(config.database, env); lastTick = Date.now(); }
    catch { console.error("scheduler_unavailable"); }
    finally { if (!stopping) tickTimer = setTimeout(() => { tickWork = tick(); }, 1000); }
  }
  async function dispatch() {
    try { await dispatchOutbox(config.database, env, 4); lastDispatch = Date.now(); }
    catch { console.error("dispatcher_unavailable"); }
    finally { if (!stopping) dispatchTimer = setTimeout(() => { dispatchWork = dispatch(); }, 250); }
  }
  return {
    env, identity,
    startBackground() {
      if (started || stopping || config.workloadsEnabled === false) return;
      started = true;
      tickWork = tick(); dispatchWork = dispatch();
    },
    async ready(): Promise<boolean> {
      if (stopping || started && (Date.now() - lastTick > 30_000 || Date.now() - lastDispatch > 60_000)) return false;
      try {
        await config.database.query("SELECT 1");
        return config.prober ? await config.prober.ready() : Boolean(config.allowLoopback);
      } catch { return false; }
    },
    async stop() {
      stopping = true;
      clearTimeout(tickTimer); clearTimeout(dispatchTimer);
      await Promise.allSettled([tickWork, dispatchWork]);
      await identity.drain();
      smtp?.close();
    },
  };
}
