import { gzipSync } from "node:zlib";
import { handleApp } from "./app";
import { handleMcp } from "./mcp";
import { dispatchWebhook, runProbe } from "./probes";
import { ApiError, constantEqual, identifier, json, policy } from "./validation";
import type { ClaimedCheck, EngineMessage, NotificationRecord, StoredObservation } from "./types";
import type { Env } from "./runtime-types";
import type { PgDatabase } from "./database";

async function accountCall<T>(env: Env, accountId: string, path: string, value?: unknown): Promise<T> {
  const response = await env.accounts.fetch(identifier(accountId), `https://account.internal${path}`, {
    method: "POST", headers: { "Content-Type": "application/json", "X-Tomato-Account": accountId },
    ...(value !== undefined ? { body: JSON.stringify(value) } : {}),
  });
  const result = await response.json() as T & {error?:string};
  if (!response.ok) throw new ApiError(response.status, result.error ?? "account_operation_failed");
  return result;
}

async function dispatchNotification(env: Env, accountId: string, eventId: string): Promise<void> {
  const { notification } = await accountCall<{ notification: NotificationRecord | null }>(env, accountId, "/notifications/claim", { eventId });
  if (!notification) return;
  let delivered = false;
  let lastError: string | null = null;
  try {
    if (notification.channel === "email") {
      if (!env.EMAIL || !env.EMAIL_FROM || !notification.email) throw new ApiError(503, "email_not_configured");
      const label = notification.type === "test" ? "Notification test" : notification.type === "certificate" ? "Certificate expiry warning" : notification.type === "down" ? "Monitor down" : "Monitor recovered";
      await env.EMAIL.send({
        from: { email: env.EMAIL_FROM, name: "Tomato" }, to: notification.email.address,
        subject: `Tomato: ${label}`,
        text: `${label}\nMonitor: ${notification.monitorName ?? notification.monitorId}\nOccurred: ${new Date(notification.occurredAt).toISOString()}\nEvent: ${notification.id}\n${notification.incidentId ? `Incident: ${notification.incidentId}\n` : ""}`,
        headers: { "X-Tomato-Event": notification.id },
      });
      delivered = true;
    } else {
      if (!notification.url || !notification.secret) throw new Error("invalid_notification_destination");
      const payload = JSON.stringify({ id: notification.id, monitorId: notification.monitorId, incidentId: notification.incidentId, type: notification.type, occurredAt: notification.occurredAt, ...(notification.certificate ? { certificate: notification.certificate } : {}) });
      const timestamp = String(Date.now());
      const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(notification.secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${payload}`));
      const signatureHex = Buffer.from(signature).toString("hex");
      const result = await dispatchWebhook(notification.url, payload, { "Content-Type": "application/json", "Idempotency-Key": notification.id, "X-Tomato-Timestamp": timestamp, "X-Tomato-Signature": signatureHex }, 10000, policy(env));
      delivered = result.status >= 200 && result.status < 300;
      if (!delivered) lastError = result.code;
    }
  } catch { lastError = notification.channel === "email" ? "email_send_failed" : "delivery_failed"; }
  await accountCall(env, accountId, "/notifications/complete", { eventId, leaseToken: notification.leaseToken, success: delivered, lastError });
}

/** Target and provider I/O always happens between committed claim and completion transactions. */
export async function executeMessage(env: Env, message: EngineMessage): Promise<void> {
  identifier(message.accountId);
  if (message.kind === "check") {
    const { claim } = await accountCall<{ claim: ClaimedCheck | null }>(env, message.accountId, "/claim", { jobId: message.jobId });
    if (!claim) return;
    if (claim.check.kind === "heartbeat") throw new Error("heartbeat_cannot_be_an_outbound_job");
    const result = await runProbe(claim.check, claim.timeoutMs, policy(env));
    await accountCall(env, message.accountId, "/complete", { jobId: message.jobId, leaseToken: claim.leaseToken, result });
  } else if (message.kind === "notification") {
    await dispatchNotification(env, message.accountId, message.eventId);
  } else if (message.kind === "archive") {
    const { batch } = await accountCall<{ batch: { id: string; observations: StoredObservation[] } | null }>(env, message.accountId, "/archive/claim");
    if (!batch) return;
    const bytes = gzipSync(JSON.stringify({ version: 1, accountId: message.accountId, observations: batch.observations }));
    if (bytes.byteLength > 2097152) throw new Error("archive_batch_limit");
    await env.database.transaction(message.accountId, async tx => {
      await tx.query("INSERT INTO archives(id,payload,created_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", [batch.id, bytes, Date.now()]);
      const stored = await tx.query<{payload:Buffer}>("SELECT payload FROM archives WHERE id=$1", [batch.id]);
      if (!stored[0]?.payload.equals(bytes)) throw new Error("archive_content_conflict");
    });
    await accountCall(env, message.accountId, "/archive/complete", { batchId: batch.id });
  } else throw new Error("invalid_engine_message");
}

export async function tickAccounts(database: PgDatabase, env: Env): Promise<void> {
  let cursor = "";
  for (;;) {
    const accounts = await database.query<{id:string}>("SELECT id FROM engine.accounts WHERE id>$1 ORDER BY id LIMIT 50", [cursor]);
    if (!accounts.length) return;
    for (let offset = 0; offset < accounts.length; offset += 4) {
      await Promise.all(accounts.slice(offset, offset + 4).map(account => accountCall(env, account.id, "/tick")));
    }
    cursor = accounts.at(-1)!.id;
  }
}

let dispatchCursor = "";
/** Durable at-least-once dispatch. Claim fences protect each operation independently;
 * a crashed dispatcher leaves a short reclaimable lease, not a lost in-memory queue.
 */
export async function dispatchOutbox(database: PgDatabase, env: Env, limit = 4): Promise<number> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 16) throw new Error("invalid_dispatch_limit");
  const accounts = await database.query<{id:string}>("SELECT id FROM engine.accounts WHERE id>$1 ORDER BY id LIMIT 200", [dispatchCursor]);
  if (!accounts.length) { dispatchCursor = ""; return 0; }
  const claimed: {accountId:string; id:string; token:string; message:EngineMessage}[] = [];
  for (const account of accounts) {
    const remaining = limit - claimed.length;
    const rows = await database.transaction(account.id, async tx => {
      const now = Date.now();
      const due = await tx.query<{id:string;message:string}>("SELECT id,message FROM outbox WHERE next_due<=$1 AND dispatch_until<=$1 ORDER BY next_due,id LIMIT $2", [now, remaining]);
      const result: {accountId:string;id:string;token:string;message:EngineMessage}[] = [];
      for (const row of due) {
        const token = crypto.randomUUID();
        const message = JSON.parse(row.message) as EngineMessage;
        if (message.accountId !== account.id) throw new Error("outbox_account_mismatch");
        await tx.query("UPDATE outbox SET dispatch_token=$1,dispatch_until=$2 WHERE id=$3", [token, now + 5000, row.id]);
        result.push({accountId:account.id,id:row.id,token,message});
      }
      return result;
    });
    claimed.push(...rows);
    dispatchCursor = account.id;
    if (claimed.length >= limit) break;
  }
  await Promise.all(claimed.map(async row => {
    try { await executeMessage(env, row.message); }
    catch (error) { console.error("engine_work_failed", error instanceof Error ? error.name : "unknown_error"); }
    finally {
      await database.transaction(row.accountId, tx => tx.query("UPDATE outbox SET dispatch_token=NULL,dispatch_until=0,next_due=GREATEST(next_due,$1) WHERE id=$2 AND dispatch_token=$3", [Date.now() + 1000, row.id, row.token]));
    }
  }));
  return claimed.length;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const mcp = await handleMcp(request, env);
      if (mcp) return mcp;
      const heartbeat = url.pathname.match(/^\/heartbeat\/([A-Za-z0-9_-]{1,64})\/([A-Za-z0-9_-]{1,64})$/);
      if (heartbeat && request.method === "POST") return await env.accounts.fetch(heartbeat[1]!, new Request(`https://account.internal/monitors/${heartbeat[2]}/heartbeat`, request));
      const application = await handleApp(request, env);
      if (application) return application;
      if (!env.ENGINE_TOKEN) return json({ error: "engine_auth_not_configured" }, 503);
      if (!constantEqual(request.headers.get("Authorization") ?? "", `Bearer ${env.ENGINE_TOKEN}`)) return json({ error: "unauthorized" }, 401);
      const route = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9_-]{1,64})\/(state|history|tick|credits\/[A-Za-z0-9_-]{1,64}|monitors(?:\/[A-Za-z0-9_-]{1,64}\/(?:pause|resume))?)$/);
      if (!route) throw new ApiError(404, "not_found");
      const accountId = route[1]!, suffix = route[2]!;
      const allowed = (request.method === "GET" && (suffix === "state" || suffix === "history")) || (request.method === "PUT" && suffix.startsWith("credits/")) || (request.method === "POST" && (suffix === "monitors" || suffix === "tick" || /^monitors\/[^/]+\/(pause|resume)$/.test(suffix)));
      if (!allowed) throw new ApiError(405, "method_not_allowed");
      const forwarded = new Request(`https://account.internal/${suffix}`, request);
      forwarded.headers.set("X-Tomato-Account", accountId);
      return await env.accounts.fetch(accountId, forwarded);
    } catch (error) {
      if (error instanceof ApiError) return json({ error: error.message }, error.status);
      throw error;
    }
  },
};
