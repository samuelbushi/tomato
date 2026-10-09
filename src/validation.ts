import { EGRESS_OVERHEAD_MS, validateCheck } from "./probes";
import type { MonitorInput, MonitorView, MonitorRecord, ProbeResult } from "./types";
import type { Env, ProbePolicy } from "./runtime-types";
export interface ValidatedMonitorInput extends MonitorInput {
  name: string;
  paused: boolean;
  timeoutMs: number;
  confirmationDelayMs: number;
  executionWindowMs: number;
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

export function json(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
}

export function identifier(value: string): string {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(value)) throw new ApiError(400, "invalid_identifier");
  return value;
}

export function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ApiError(400, "expected_object");
  return value as Record<string, unknown>;
}

export function integer(value: unknown, min: number, max: number, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new ApiError(400, `invalid_${name}`);
  }
  return value;
}

export function policy(env: Env): ProbePolicy {
  const local = env.TEST_MODE === true;
  return {
    allowLoopback: local,
    resolverUrl: local && env.TEST_DNS_RESOLVER ? env.TEST_DNS_RESOLVER : "https://cloudflare-dns.com/dns-query",
    egress: env.PROBER,
  };
}

export function monitorInput(value: unknown, env: Env): ValidatedMonitorInput {
  const input = record(value);
  const id = input.id === undefined || input.id === "" ? crypto.randomUUID() : identifier(typeof input.id === "string" ? input.id : "");
  const candidateCheck = { ...record(input.check) };
  if ((candidateCheck.kind === "http" || candidateCheck.kind === "websocket") && typeof candidateCheck.url === "string" && !candidateCheck.url.includes("://")) candidateCheck.url = `https://${candidateCheck.url}`;
  let defaultName = id;
  try { if (typeof candidateCheck.url === "string") defaultName = new URL(candidateCheck.url).hostname; } catch { throw new ApiError(400, "invalid_check"); }
  const name = input.name === undefined || input.name === "" ? defaultName : text(input.name, 120, "name");
  if (input.paused !== undefined && typeof input.paused !== "boolean") throw new ApiError(400, "invalid_paused");
  const paused = input.paused === true;
  const minInterval = env.TEST_MODE ? Number(env.TEST_MIN_INTERVAL_MS ?? 60000) : 60000;
  const intervalMs = integer(input.intervalMs ?? 60000, Math.max(1000, minInterval), 30 * 86400000, "interval");
  const timeoutMs = integer(input.timeoutMs ?? 5000, 100, 30000, "timeout");
  const confirmationDelayMs = integer(input.confirmationDelayMs ?? 1000, 100, 60000, "confirmation_delay");
  let check;
  try { check = validateCheck(candidateCheck, policy(env)); }
  catch { throw new ApiError(400, "invalid_check"); }
  const egressOverhead = env.PROBER && check.kind !== "heartbeat" ? EGRESS_OVERHEAD_MS : 0;
  const executionWindowMs = integer(input.executionWindowMs ?? Math.max(timeoutMs * 2 + egressOverhead, Math.min(intervalMs, 60000)), timeoutMs + egressOverhead + 500, 300000, "execution_window");
  let webhook: MonitorInput["webhook"];
  if (input.webhook !== undefined) {
    const candidate = record(input.webhook);
    if (typeof candidate.url !== "string" || typeof candidate.secret !== "string" || candidate.secret.length < 16 || candidate.secret.length > 256) {
      throw new ApiError(400, "invalid_webhook");
    }
    try { validateCheck({ kind: "http", url: candidate.url }, policy(env)); }
    catch { throw new ApiError(400, "invalid_webhook"); }
    if (new URL(candidate.url).protocol !== "https:" && !env.TEST_MODE) throw new ApiError(400, "webhook_requires_https");
    webhook = { url: candidate.url, secret: candidate.secret };
  }
  let email: MonitorInput["email"];
  if (input.email !== undefined) {
    if (!env.EMAIL || !env.EMAIL_FROM) throw new ApiError(503, "email_not_configured");
    const candidate = record(input.email);
    if (typeof candidate.address !== "string" || candidate.address.length > 254 || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(candidate.address)) throw new ApiError(400, "invalid_email");
    email = { address: candidate.address };
  }
  const certificateExpiryDays = integer(input.certificateExpiryDays ?? 14, 0, 365, "certificate_expiry_days");
  return { id, name, check, intervalMs, paused, timeoutMs, confirmationDelayMs, executionWindowMs, certificateExpiryDays, ...(webhook ? { webhook } : {}), ...(email ? { email } : {}) };
}

export async function body(request: Request, maxBytes = 32768): Promise<Record<string, unknown>> {
  const reader = request.body?.getReader();
  if (!reader) throw new ApiError(400, "missing_body");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes) { await reader.cancel(); throw new ApiError(413, "body_too_large"); }
      chunks.push(chunk.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return record(JSON.parse(new TextDecoder().decode(bytes))); }
  catch (error) { if (error instanceof ApiError) throw error; throw new ApiError(400, "invalid_json"); }
}

export function probeResult(value: unknown, now: number): ProbeResult {
  const result = record(value);
  if (!["success", "failure", "unknown"].includes(String(result.outcome)) || typeof result.code !== "string" || result.code.length > 128) {
    throw new ApiError(400, "invalid_result");
  }
  const startedAt = integer(result.startedAt, 0, now + 1000, "started_at");
  integer(result.finishedAt, startedAt, now + 1000, "finished_at");
  if (typeof result.latencyMs !== "number" || !Number.isFinite(result.latencyMs) || result.latencyMs < 0 || result.latencyMs > 60000) throw new ApiError(400, "invalid_latency");
  return result as unknown as ProbeResult;
}

export function monitorView(monitor: MonitorRecord, now = Date.now()): MonitorView {
  const { heartbeatTokenHash: _hash, webhook, check, certificate, ...rest } = monitor;
  const heartbeatDown = monitor.check.kind === "heartbeat" && monitor.state === "DOWN";
  const freshUntil = heartbeatDown || monitor.lastObservedAt === null ? null : monitor.check.kind === "heartbeat"
    ? monitor.heartbeatDeadline ?? monitor.lastObservedAt + monitor.intervalMs
    : monitor.lastObservedAt + monitor.intervalMs + monitor.executionWindowMs;
  const effectiveState = monitor.maintenanceUntil && monitor.maintenanceUntil > now && !monitor.paused ? "MAINTENANCE" : !monitor.paused && !heartbeatDown && monitor.state !== "UNKNOWN" && monitor.state !== "MAINTENANCE" && (freshUntil === null || freshUntil < now) ? "UNKNOWN" : monitor.state;
  const displayCheck = check.kind === "http" ? (() => {
    const { headers, ...safe } = check;
    return { ...safe, headerNames: Object.keys(headers ?? {}).sort(), hasHeaders: Object.keys(headers ?? {}).length > 0 };
  })() : check;
  const view: MonitorView = { ...rest, name: monitor.name ?? monitor.id, check: displayCheck, freshUntil, effectiveState };
  if (certificate) {
    const daysRemaining = (certificate.validTo - now) / 86400000, thresholdDays = monitor.certificateExpiryDays ?? 14;
    view.certificate = { ...certificate, daysRemaining, thresholdDays, status: certificate.validTo <= now ? "expired" : daysRemaining <= thresholdDays ? "expiring" : "valid", stale: certificate.observedAt + monitor.intervalMs + monitor.executionWindowMs < now };
  }
  if (webhook) view.webhook = { url: webhook.url };
  return view;
}

export function text(value: unknown, max: number, name: string, multiline = false): string {
  const controls = multiline ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/ : /[\u0000-\u001f\u007f]/;
  if (typeof value !== "string" || !value.trim() || value.length > max || controls.test(value)) throw new ApiError(400, `invalid_${name}`);
  return value.trim();
}

export async function digest(text: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

export function constantEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
