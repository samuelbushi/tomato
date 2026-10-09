import { ApiError, body, constantEqual, identifier, integer, json } from "./validation";
import { randomToken } from "./identity";
import { RECOVERY_NOTICE } from "./auth";
import type { Env } from "./runtime-types";
import type { EngineSnapshot, MonitorView } from "./types";
import type { AccountSummary, AuthenticatedView, DeliveryView, InvitationView, InvitationPreview, MemberView, SessionView, ApiKeyView, AuditView, Principal, PublicPageConfig, PublicStatusView, UiPage, WalletView, NotificationDefaultsView, MaintenanceWindow } from "./product-types";
import { renderUi } from "./ui";
import { executeManagement, readiness, toolsFor } from "./management";
import { accountManagement } from "./management-routes";

const PUBLIC_HOME = renderUi({ kind: "landing" });
const encoder = new TextEncoder();
interface ParsedInput { values: Record<string, unknown>; form: URLSearchParams | null }

function csrfName(env: Env): string { return env.TEST_MODE ? "tomato-csrf" : "__Host-tomato-csrf"; }
function enrollmentName(env: Env): string { return env.TEST_MODE ? "tomato-enrollment" : "__Host-tomato-enrollment"; }
function cookie(request: Request, name: string): string {
  for (const part of (request.headers.get("Cookie") ?? "").split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return value.join("=");
  }
  return "";
}
function setCookie(env: Env, name: string, value: string, maxAge: number, sameSite: "Strict" | "Lax" = "Strict"): string {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAge}${env.TEST_MODE ? "" : "; Secure"}`;
}
function secureResponse(response: Response): Response {
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin");
  response.headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  return response;
}
function html(page: UiPage, status = 200, headers?: HeadersInit, head = false): Response {
  const resultHeaders = new Headers(headers);
  resultHeaders.set("Content-Type", "text/html; charset=utf-8");
  resultHeaders.set("Cache-Control", page.kind === "landing" ? "public, max-age=60" : "no-store");
  return secureResponse(new Response(head ? null : page.kind === "landing" ? PUBLIC_HOME : renderUi(page), { status, headers: resultHeaders }));
}
function redirect(location: string, headers?: HeadersInit): Response {
  const resultHeaders = new Headers(headers);
  resultHeaders.set("Location", location);
  resultHeaders.set("Cache-Control", "no-store");
  return secureResponse(new Response(null, { status: 303, headers: resultHeaders }));
}
async function identity<T>(env: Env, path: string, input: Record<string, unknown>): Promise<T> {
  const response = await env.identity.fetch(new Request(`https://identity.internal${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) }));
  const value = await response.json() as T & { error?: string };
  if (!response.ok) throw new ApiError(response.status, value.error ?? "identity_unavailable");
  return value;
}
async function account<T>(env: Env, accountId: string, path: string, method = "GET", value?: unknown): Promise<T> {
  const response = await env.accounts.fetch(identifier(accountId), new Request(`https://account.internal${path}`, { method, headers: { "Content-Type": "application/json", "X-Tomato-Account": accountId }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) }));
  const result = await response.json() as T & { error?: string };
  if (!response.ok) throw new ApiError(response.status, result.error ?? "account_unavailable");
  return result;
}
async function parseInput(request: Request, maxBytes = 32768): Promise<ParsedInput> {
  if (request.method === "DELETE" && request.body === null) return { values: {}, form: null };
  if (request.headers.get("Content-Type")?.split(";", 1)[0] === "application/json") return { values: await body(request, maxBytes), form: null };
  if (request.headers.get("Content-Type")?.split(";", 1)[0] !== "application/x-www-form-urlencoded") throw new ApiError(415, "unsupported_content_type");
  const reader = request.body?.getReader();
  if (!reader) throw new ApiError(400, "missing_body");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > maxBytes) { await reader.cancel(); throw new ApiError(413, "body_too_large"); }
      chunks.push(chunk.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const form = new URLSearchParams(new TextDecoder().decode(bytes));
  const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of form) values[key] = value;
  return { values, form };
}
function requireOrigin(request: Request): void {
  if (request.headers.get("Origin") !== new URL(request.url).origin) throw new ApiError(403, "origin_mismatch");
}
async function anonymousCsrf(env: Env): Promise<{ token: string; signed: string }> {
  if (!env.AUTH_SECRET || env.AUTH_SECRET.length < 32) throw new ApiError(503, "auth_not_configured");
  const token = `${Date.now()}.${randomToken()}`;
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(token));
  return { token, signed: `${token}.${btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}` };
}
async function verifyAnonymousCsrf(request: Request, env: Env, value: unknown): Promise<void> {
  requireOrigin(request);
  const signed = cookie(request, csrfName(env));
  const parts = signed.split(".");
  const token = parts.slice(0, 2).join(".");
  if (parts.length !== 3 || typeof value !== "string" || !constantEqual(value, token) || !env.AUTH_SECRET) throw new ApiError(403, "csrf_mismatch");
  const timestamp = Number(parts[0]);
  if (!Number.isFinite(timestamp) || timestamp > Date.now() || Date.now() - timestamp > 15 * 60000) throw new ApiError(403, "csrf_expired");
  let signature: Uint8Array<ArrayBuffer>;
  try { signature = Uint8Array.from(atob(parts[2]!.replace(/-/g, "+").replace(/_/g, "/")), char => char.charCodeAt(0)); }
  catch { throw new ApiError(403, "csrf_mismatch"); }
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify("HMAC", key, signature, encoder.encode(token))) throw new ApiError(403, "csrf_mismatch");
}
async function principal(request: Request, env: Env, accountId?: string): Promise<Principal> {
  const authorization = request.headers.get("Authorization");
  const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
  return await identity<Principal>(env, "/authenticate", { token, cookie: request.headers.get("Cookie") ?? "", ...(accountId ? { accountId } : {}) });
}
function mutation(request: Request, actor: Principal, input: Record<string, unknown>): void {
  if (actor.apiKeyId) { if (actor.scope === "read") throw new ApiError(403, "write_scope_required"); return; }
  requireOrigin(request);
  const token = request.headers.get("X-CSRF-Token") ?? input.csrfToken;
  if (typeof token !== "string" || !constantEqual(token, actor.csrfToken)) throw new ApiError(403, "csrf_mismatch");
}
function sessionOnly(actor: Principal): void {
  if ((!actor.sessionId || actor.apiKeyId) && actor.scope !== "manage") throw new ApiError(403, "manage_scope_required");
}
function editor(actor: Principal): void {
  if (!actor.account || actor.account.role === "viewer") throw new ApiError(403, "editor_required");
}
function owner(actor: Principal): void {
  if (actor.apiKeyId && actor.scope !== "manage") throw new ApiError(403, "manage_scope_required");
  if (actor.account?.role !== "owner") throw new ApiError(403, "owner_required");
}
function context(actor: Principal, env: Env): AuthenticatedView {
  if (!actor.account) throw new ApiError(404, "account_not_found");
  return { actor: actor.actor, accounts: actor.accounts, account: actor.account, csrfToken: actor.csrfToken, generatedAt: Date.now(), emailConfigured: Boolean(env.EMAIL && env.EMAIL_FROM), mode: env.MODE };
}
function formNumber(values: Record<string, unknown>, field: string, fallback?: number): number {
  const value = values[field];
  if (value === undefined || value === "") { if (fallback !== undefined) return fallback; throw new ApiError(400, `missing_${field}`); }
  const number = Number(value);
  if (!Number.isFinite(number)) throw new ApiError(400, `invalid_${field}`);
  return number;
}
function monitorForm(values: Record<string, unknown>, id?: string): Record<string, unknown> {
  const kind = String(values.kind ?? "http");
  const check: Record<string, unknown> = { kind };
  if (kind === "http" || kind === "websocket") check.url = String(values.url ?? "");
  if (kind === "http") {
    check.method = values.method ?? "GET";
    if (typeof values.status === "string" && values.status.trim()) check.status = values.status.split(",").map(part => Number(part.trim()));
    if (values.containsEnabled === "on") check.contains = String(values.contains ?? "");
    check.maxBodyBytes = formNumber(values, "maxBodyBytes", 65536);
    check.maxRedirects = formNumber(values, "maxRedirects", 3);
    if (values.headersMode === "replace") {
      try { check.headers = JSON.parse(String(values.headers ?? "{}")); }
      catch { throw new ApiError(400, "invalid_http_headers_json"); }
    }
  } else if (kind === "dns") {
    check.name = String(values.dnsName ?? ""); check.recordType = values.recordType;
    if (typeof values.expected === "string" && values.expected.trim()) check.expected = values.expected.split(/\r?\n/).map(item => item.trim()).filter(Boolean);
  } else if (kind === "tcp" || kind === "tls") {
    check.hostname = String(values.hostname ?? ""); check.port = formNumber(values, "port"); check.maxResponseBytes = formNumber(values, "maxResponseBytes", 16384);
  } else if (kind === "heartbeat") check.graceMs = Math.round(formNumber(values, "graceSeconds", 0) * 1000);
  if (kind === "websocket") check.maxMessageBytes = formNumber(values, "maxMessageBytes", 16384);
  if (kind === "tcp" || kind === "tls" || kind === "websocket") {
    if (values.sendEnabled === "on") check.send = String(values.send ?? "");
    if (values.expectEnabled === "on") check.expect = String(values.expect ?? "");
  }
  const result: Record<string, unknown> = { id: id ?? String(values.id ?? ""), name: String(values.name ?? ""), check, intervalMs: Math.round(formNumber(values, "intervalSeconds", 60) * 1000), timeoutMs: Math.round(formNumber(values, "timeoutSeconds", 5) * 1000), confirmationDelayMs: Math.round(formNumber(values, "confirmationDelaySeconds", 1) * 1000), executionWindowMs: Math.round(formNumber(values, "executionWindowSeconds", 60) * 1000) };
  result.useNotificationDefaults = values.useNotificationDefaults === "on" || values.useNotificationDefaults === "true";
  result.paused = values.paused === "on" || values.paused === "true";
  result.certificateExpiryDays = formNumber(values, "certificateExpiryDays", 14);
  if (id) result.revision = formNumber(values, "revision");
  for (const field of ["headersMode", "webhookMode", "emailMode"]) if (values[field] !== undefined) result[field] = values[field];
  if (values.webhookMode === "replace") result.webhook = { url: String(values.webhookUrl ?? ""), secret: String(values.webhookSecret ?? "") };
  if (values.emailMode === "replace") result.email = { address: String(values.emailAddress ?? "") };
  if (!result.id) delete result.id;
  if (!result.name) delete result.name;
  return result;
}
async function audit(env: Env, actor: Principal, action: string, subject: string): Promise<void> {
  if (actor.account) await identity(env, "/audit/append", { accountId: actor.account.id, actor: actor.actor.id, action, subject });
}
function requireOperator(request: Request, env: Env): void {
  if (!env.ENGINE_TOKEN || !constantEqual(request.headers.get("Authorization") ?? "", `Bearer ${env.ENGINE_TOKEN}`)) throw new ApiError(401, "unauthorized");
}

async function maintainedAuth(request: Request, env: Env, endpoint: string, values: Record<string, unknown>): Promise<Response> {
  const headers = new Headers(request.headers);
  headers.set("Content-Type", "application/json"); headers.delete("Content-Length");
  const response = await env.identity.authHandler(new Request(new URL(`/api/auth${endpoint}`, request.url), { method: "POST", headers, body: JSON.stringify(values) }));
  if (!response.ok) {
    const value: unknown = await response.json();
    const message = value && typeof value === "object" && "message" in value && typeof value.message === "string" ? value.message : value && typeof value === "object" && "error" in value && typeof value.error === "string" ? value.error : "authentication_failed";
    throw new ApiError(response.status, message);
  }
  return response;
}
function authCookies(response: Response): Headers {
  const headers = new Headers();
  for (const value of response.headers.getSetCookie()) headers.append("Set-Cookie", value);
  return headers;
}
function loginDestination(value: unknown): string { return typeof value === "string" && /^\/invite\/tomato_invite_[A-Za-z0-9_-]{43}$/.test(value) ? value : "/app"; }

export async function handleApp(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === "/tomato.css" || path === "/tomato.js") {
    if (!env.ASSETS) throw new ApiError(404, "not_found");
    return await env.ASSETS.fetch(request);
  }
  let failedEditor: { actor: Principal; values: Record<string, unknown>; monitor: MonitorView | null } | undefined;
  const api = path.startsWith("/api/");
  if (!api && path !== "/" && !["/login", "/logout", "/signup", "/forgot-password", "/reset-password", "/verify-email", "/auth/social", "/enroll", "/enroll/invitation", "/enroll/contact", "/enroll/verify"].includes(path) && !path.startsWith("/app") && !path.startsWith("/invite/") && !path.startsWith("/status/")) return null;
  try {
    if (!env.TEST_MODE && url.protocol !== "https:") return secureResponse(new Response(null, { status: 308, headers: { Location: `https://${url.host}${url.pathname}${url.search}`, "Cache-Control": "no-store" } }));
    const legacyAuth = /^\/api\/auth\/(?:login|logout|password|sessions(?:\/.*)?)$/;
    if (path.startsWith("/api/auth/") && !legacyAuth.test(path)) return secureResponse(await env.identity.authHandler(request));
    if (["/enroll", "/enroll/invitation", "/enroll/contact", "/enroll/verify"].includes(path)) {
      if (request.headers.has("Authorization")) throw new ApiError(403, "cookie_enrollment_required");
      if (request.method === "GET") {
        const csrf = await anonymousCsrf(env), headers = { "Set-Cookie": setCookie(env, csrfName(env), csrf.signed, 900) };
        if (path === "/enroll") return html({ kind: "enrollment", stage: "proof", csrfToken: csrf.token }, 200, headers);
        if (path === "/enroll/invitation") throw new ApiError(405, "method_not_allowed");
        const state = await identity<{ expiresAt: number; email: string | null; sent: boolean }>(env, "/enrollment/status", { claim: cookie(request, enrollmentName(env)) });
        return html({ kind: "enrollment", stage: path === "/enroll/verify" ? "verify" : "contact", csrfToken: csrf.token, expiresAt: state.expiresAt, email: state.email, emailToken: path === "/enroll/verify" ? url.searchParams.get("token") ?? "" : undefined, notice: state.sent ? "SMTP accepted your verification message. Open its link in this browser before this claim expires." : undefined }, 200, headers);
      }
      if (request.method !== "POST") throw new ApiError(405, "method_not_allowed");
      const { values } = await parseInput(request); await verifyAnonymousCsrf(request, env, values.csrfToken);
      const trustedClientIp = request.headers.get("X-Tomato-Client-IP"), claim = cookie(request, enrollmentName(env));
      if (path === "/enroll" || path === "/enroll/invitation") {
        const started = await identity<{ claim: string; expiresAt: number }>(env, path === "/enroll" ? "/enrollment/start" : "/enrollment/invitation", { username: values.username, password: values.password, invitationToken: values.invitationToken, trustedClientIp });
        return redirect("/enroll/contact", { "Set-Cookie": setCookie(env, enrollmentName(env), started.claim, Math.max(1, Math.floor((started.expiresAt - Date.now()) / 1000)), "Lax") });
      }
      if (path === "/enroll/contact") {
        await identity(env, "/enrollment/contact", { claim, email: values.email, trustedClientIp });
        return redirect("/enroll/contact");
      }
      await identity(env, "/enrollment/complete", { claim, emailToken: values.emailToken, trustedClientIp });
      return redirect("/login", { "Set-Cookie": setCookie(env, enrollmentName(env), "", 0, "Lax") });
    }
    if (["/signup", "/forgot-password", "/reset-password", "/verify-email"].includes(path)) {
      const mode = path === "/signup" ? "signup" : path === "/forgot-password" ? "forgot" : path === "/reset-password" ? "reset" : "verify";
      if (mode === "signup" && !env.identity.capabilities.signup) throw new ApiError(403, "signup_disabled");
      if (!env.identity.capabilities.email) throw new ApiError(503, "smtp_not_configured");
      if (request.method === "GET") {
        const csrf = await anonymousCsrf(env);
        return html({ kind: "login", pilotOnly: true, csrfToken: csrf.token, mode, resetToken: mode === "reset" ? url.searchParams.get("token") ?? "" : undefined }, 200, { "Set-Cookie": setCookie(env, csrfName(env), csrf.signed, 900) });
      }
      if (request.method !== "POST") throw new ApiError(405, "method_not_allowed");
      const { values } = await parseInput(request); await verifyAnonymousCsrf(request, env, values.csrfToken);
      const endpoint = mode === "signup" ? "/sign-up/email" : mode === "forgot" ? "/request-password-reset" : mode === "reset" ? "/reset-password" : "/send-verification-email";
      const input = mode === "signup" ? { email: values.email, name: values.name, password: values.password, callbackURL: "/login" } : mode === "forgot" ? { email: values.email, redirectTo: new URL("/reset-password", url.origin).href } : mode === "reset" ? { newPassword: values.password, token: values.token } : { email: values.email, callbackURL: "/login" };
      const result = await maintainedAuth(request, env, endpoint, input);
      const csrf = await anonymousCsrf(env), headers = authCookies(result); headers.append("Set-Cookie", setCookie(env, csrfName(env), csrf.signed, 900));
      return html({ kind: "login", pilotOnly: true, csrfToken: csrf.token, notice: mode === "reset" ? "Password reset. Sign in with your new password." : mode === "forgot" ? RECOVERY_NOTICE : "Check your email for the next step.", ...env.identity.capabilities }, 200, headers);
    }
    if (path === "/auth/social" && request.method === "POST") {
      const { values } = await parseInput(request); await verifyAnonymousCsrf(request, env, values.csrfToken);
      const response = await maintainedAuth(request, env, "/sign-in/social", { provider: values.provider, callbackURL: new URL("/app", url.origin).href });
      const result: unknown = await response.json();
      if (!result || typeof result !== "object" || !("url" in result) || typeof result.url !== "string" || new URL(result.url).protocol !== "https:") throw new ApiError(503, "oauth_unavailable");
      return redirect(result.url, authCookies(response));
    }
    if (path === "/") {
      if (request.method !== "GET" && request.method !== "HEAD") return html({ kind: "error", status: 405, error: "method_not_allowed" }, 405, { Allow: "GET, HEAD" });
      return html({ kind: "landing" }, 200, undefined, request.method === "HEAD");
    }
    if ((path === "/login" || path === "/api/auth/login") && request.method === "GET") {
      const csrf = await anonymousCsrf(env);
      if (api) {
        const response = json({ csrfToken: csrf.token });
        response.headers.set("Set-Cookie", setCookie(env, csrfName(env), csrf.signed, 900));
        return secureResponse(response);
      }
      return html({ kind: "login", csrfToken: csrf.token, pilotOnly: true, next: loginDestination(url.searchParams.get("next")), ...env.identity.capabilities }, 200, { "Set-Cookie": setCookie(env, csrfName(env), csrf.signed, 900) });
    }
    if ((path === "/login" || path === "/api/auth/login") && request.method === "POST") {
      const { values } = await parseInput(request);
      await verifyAnonymousCsrf(request, env, values.csrfToken ?? request.headers.get("X-CSRF-Token"));
      const destination = loginDestination(values.next), verificationReturn = new URL("/login", url.origin);
      if (destination !== "/app") verificationReturn.searchParams.set("next", destination);
      const result = await maintainedAuth(request, env, "/sign-in/email", { email: values.email, password: values.password, callbackURL: verificationReturn.href });
      const headers = authCookies(result); headers.append("Set-Cookie", setCookie(env, csrfName(env), "", 0));
      if (api) {
        const sessionCookie = result.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");
        const actor = await identity<Principal>(env, "/authenticate", { cookie: sessionCookie });
        const response = json(actor);
        for (const value of headers.getSetCookie()) response.headers.append("Set-Cookie", value);
        return secureResponse(response);
      }
      return redirect(destination, headers);
    }
    const invite = path.match(/^\/invite\/(tomato_invite_[A-Za-z0-9_-]{43})$/);
    if (invite) {
      if (request.method === "GET") {
        const preview = await identity<InvitationPreview>(env, "/invitations/preview", { token: invite[1] });
        if (preview.legacyUsername) {
          const csrf = await anonymousCsrf(env);
          return html({ kind: "enrollment", stage: preview.legacyExisting ? "proof" : "invite", username: preview.legacyUsername, invitationToken: preview.legacyExisting ? undefined : invite[1], csrfToken: csrf.token, notice: preview.legacyExisting ? "This invitation targets an existing username. Prove its original password and verify your actual contact first; then sign in and return to the unchanged invitation link." : `This unchanged invitation targets ${preview.legacyUsername} for the ${preview.invitation.role} role in ${preview.accountName}. Verify your own actual contact to accept exactly this membership.` }, 200, { "Set-Cookie": setCookie(env, csrfName(env), csrf.signed, 900) });
        }
        let signedIn = false, csrfToken: string;
        try { const actor = await principal(request, env); signedIn = actor.actor.username === preview.invitation.username; csrfToken = actor.csrfToken; } catch (error) { if (!(error instanceof ApiError) || error.status !== 401) throw error; csrfToken = ""; }
        const csrf = await anonymousCsrf(env);
        return html({ kind: "invite", invitationToken: invite[1]!, accountName: preview.accountName, username: preview.invitation.username, role: preview.invitation.role, expiresAt: preview.invitation.expiresAt, identityStatus: preview.identityStatus, signedIn, csrfToken: signedIn ? csrfToken : csrf.token }, 200, { "Set-Cookie": setCookie(env, csrfName(env), csrf.signed, 900) });
      }
      if (request.method === "POST") {
        const { values } = await parseInput(request);
        if (values.register === "true") {
          await verifyAnonymousCsrf(request, env, values.csrfToken);
          await identity(env, "/invitations/register", { token: invite[1], name: values.name, password: values.password, trustedClientIp: request.headers.get("X-Tomato-Client-IP") });
          return redirect(`/login?next=${encodeURIComponent(path)}`);
        }
        const actor = await principal(request, env); mutation(request, actor, values);
        const joined = await identity<{ accountId: string }>(env, "/invitations/accept", { token: invite[1], userId: actor.actor.id, sessionId: actor.sessionId });
        return redirect(`/app/accounts/${identifier(joined.accountId)}`);
      }
      throw new ApiError(405, "method_not_allowed");
    }
    const publicRoute = path.match(/^\/(?:status|api\/public\/status)\/([a-z0-9][a-z0-9-]{2,62})$/);
    if (publicRoute && request.method === "GET") {
      const { accountId } = await identity<{ accountId: string | null }>(env, "/slugs/lookup", { slug: publicRoute[1] });
      if (!accountId) throw new ApiError(404, "status_page_not_found");
      const page = await account<PublicStatusView>(env, accountId, "/public-status");
      if (page.slug !== publicRoute[1]) throw new ApiError(404, "status_page_not_found");
      return api ? secureResponse(json(page)) : html({ kind: "public-status", page });
    }
    if (path.startsWith("/api/operator/")) {
      requireOperator(request, env);
      const { values } = await parseInput(request);
      if (path === "/api/operator/accounts" && request.method === "POST") {
        const testingCredits = values.testingCredits === undefined ? 0 : integer(values.testingCredits, 0, 1000000000, "testing_credits");
        const created = await identity<{ account: AccountSummary; owner: { id: string; username: string } }>(env, "/provision", values);
        if (env.MODE === "hosted" && testingCredits > 0) {
          await account(env, created.account.id, "/credits/initial-testing", "PUT", { credits: testingCredits, reason: "Operator-issued testing grant" });
          await identity(env, "/audit/append", { accountId: created.account.id, actor: "operator", action: "credit.grant", subject: "initial-testing" });
        }
        return secureResponse(json(created, 201));
      }
      const grant = path.match(/^\/api\/operator\/accounts\/([A-Za-z0-9_-]{1,64})\/credits\/([A-Za-z0-9_-]{1,64})$/);
      if (grant && request.method === "PUT") {
        const result = await account(env, grant[1]!, `/credits/${grant[2]}`, "PUT", values);
        await identity(env, "/audit/append", { accountId: grant[1], actor: "operator", action: "credit.grant", subject: grant[2] });
        return secureResponse(json(result));
      }
      const recovery = path.match(/^\/api\/operator\/users\/([A-Za-z0-9_-]{1,64})\/password$/);
      if (recovery && request.method === "POST") return secureResponse(json(await identity(env, "/recovery", { userId: recovery[1], newPassword: values.newPassword })));
      throw new ApiError(404, "not_found");
    }
    const accountRoute = path.match(/^\/(?:api|app)\/accounts\/([A-Za-z0-9_-]{1,64})(?:\/(.*))?$/);
    const actor = await principal(request, env, accountRoute?.[1]);
    if (path === "/api/session" && request.method === "GET") return secureResponse(json(actor));
    if (path === "/api/capabilities" && request.method === "GET") return secureResponse(json(readiness(env, url.origin)));
    if (path === "/app" && request.method === "GET") {
      sessionOnly(actor);
      if (actor.accounts.length === 1) return redirect(`/app/accounts/${actor.accounts[0]!.id}`);
      return html({ kind: "accounts", actor: actor.actor, accounts: actor.accounts, csrfToken: actor.csrfToken });
    }
    if ((path === "/logout" || path === "/api/auth/logout") && request.method === "POST") {
      sessionOnly(actor); const { values } = await parseInput(request); mutation(request, actor, values);
      const response = await maintainedAuth(request, env, "/sign-out", {}), headers = authCookies(response);
      if (api) return secureResponse(new Response(response.body, { status: response.status, headers: response.headers }));
      return redirect("/login", headers);
    }
    if (path.startsWith("/api/auth/")) {
      sessionOnly(actor);
      const personal = (name: string, input: Record<string, unknown> = {}) => executeManagement(env, actor, `tomato.${name}`, { ...input, accountId: actor.accounts[0]?.id }, url.origin);
      if (path === "/api/auth/sessions" && request.method === "GET") return secureResponse(json(await personal("sessions.list")));
      const { values }: { values: Record<string, unknown> } = request.method === "DELETE" ? { values: {} } : await parseInput(request); mutation(request, actor, values);
      if (path === "/api/auth/password" && request.method === "POST") return secureResponse(json(await personal("password.change", { currentPassword: values.currentPassword, newPassword: values.newPassword })));
      if (path === "/api/auth/sessions/revoke-others" && request.method === "POST") return secureResponse(json(await personal("sessions.revoke_others")));
      const revoke = path.match(/^\/api\/auth\/sessions\/([A-Za-z0-9_-]{1,64})$/);
      if (revoke && request.method === "DELETE") return secureResponse(json(await personal("session.revoke", { sessionId: revoke[1] })));
      throw new ApiError(404, "not_found");
    }
    if (!accountRoute || !actor.account) throw new ApiError(404, "not_found");
    {
    if (!api) sessionOnly(actor);
    const accountId = actor.account.id;
    async function account<T>(env: Env, _accountId: string, path: string, method = "GET", value?: unknown): Promise<T> { return accountManagement<T>(env, actor, path, method, value, url.origin); }
    async function manage<T>(name: string, input: Record<string, unknown> = {}): Promise<T> { const result = await executeManagement(env, actor, `tomato.${name}`, { ...input, accountId }, url.origin); return result as T; }
    async function identity<T>(_env: Env, path: string, input: Record<string, unknown>): Promise<T> {
      const reads: Record<string, string> = { "/members": "members.list", "/invitations": "invitations.list", "/api-keys": "keys.list", "/sessions": "sessions.list" };
      if (reads[path]) return manage<T>(reads[path]);
      if (path === "/audit") return manage<T>("audit.list", { ...(input.before !== undefined ? { before: input.before } : {}), ...(input.cursor !== undefined ? { cursor: input.cursor } : {}), ...(input.limit !== undefined ? { limit: input.limit } : {}) });
      if (path === "/invitations/create") return manage<T>("invitation.create", { username: input.username, role: input.role });
      if (path === "/invitations/revoke") return manage<T>("invitation.revoke", { invitationId: input.id });
      if (path === "/members/change") return manage<T>(input.remove ? "member.remove" : "member.role_set", { userId: input.userId, ...(!input.remove ? { role: input.role } : {}) });
      if (path === "/api-keys/revoke") return manage<T>("key.revoke", { keyId: input.id });
      if (path === "/password") return manage<T>("password.change", { currentPassword: input.currentPassword, newPassword: input.newPassword });
      if (path === "/sessions/revoke") return manage<T>("session.revoke", { sessionId: input.id });
      if (path === "/sessions/revoke-others") return manage<T>("sessions.revoke_others");
      throw new ApiError(404, "not_found");
    }
    const suffix = accountRoute[2] ?? "";
    const root = `/app/accounts/${accountId}`;
    const identityInput = { actorId: actor.actor.id, accountId, apiKeyId: actor.apiKeyId ?? undefined, authSessionId: actor.sessionId ?? undefined };
    if (request.method === "GET") {
      if (api) {
        if (suffix === "workspace") return secureResponse(json(await manage("workspace.get")));
        if (["coverage", "reports", "maintenance", "notification-defaults"].includes(suffix)) return secureResponse(json(await account(env, accountId, `/${suffix}${url.search}`)));
        if (suffix === "state" || suffix === "monitors") {
          const snapshot = await account<EngineSnapshot>(env, accountId, "/state");
          const monitors = snapshot.monitors;
          if (suffix === "monitors") return secureResponse(json({ monitors, generatedAt: Date.now() }));
          return secureResponse(json({ ...snapshot, monitors, generatedAt: Date.now() }));
        }
        if (["history", "incidents", "notifications", "usage"].includes(suffix)) return secureResponse(json(await account(env, accountId, `/${suffix}${url.search}`)));
        if (suffix === "export") return secureResponse(json(await account(env, accountId, "/export")));
        if (suffix === "members") return secureResponse(json(await identity(env, "/members", identityInput)));
        if (suffix === "invitations") { owner(actor); return secureResponse(json(await identity(env, "/invitations", identityInput))); }
        if (suffix === "api-keys") { sessionOnly(actor); return secureResponse(json(await identity(env, "/api-keys", identityInput))); }
        if (suffix === "status-page") return secureResponse(json(await account(env, accountId, "/status-page")));
        if (suffix === "audit") return secureResponse(json(await identity(env, "/audit", { ...identityInput, ...(url.searchParams.has("before") ? { before: Number(url.searchParams.get("before")) } : {}), ...(url.searchParams.has("cursor") ? { cursor: url.searchParams.get("cursor") } : {}), ...(url.searchParams.has("limit") ? { limit: Number(url.searchParams.get("limit")) } : {}) })));
        const monitorRoute = suffix.match(/^monitors\/([A-Za-z0-9_-]{1,64})(?:\/(heartbeat-instructions))?$/);
        if (monitorRoute) {
          const result = await account<{ monitor: MonitorView }>(env, accountId, `/monitors/${monitorRoute[1]}`);
          if (monitorRoute[2]) {
            if (result.monitor.check.kind !== "heartbeat") throw new ApiError(400, "not_heartbeat");
            return secureResponse(json({ url: `${url.origin}/heartbeat/${accountId}/${result.monitor.id}`, method: "POST", authorization: "Bearer <your saved token>", idempotencyHeader: "Idempotency-Key", intervalMs: result.monitor.intervalMs, graceMs: result.monitor.check.graceMs ?? 0 }));
          }
          return secureResponse(json({ monitor: result.monitor }));
        }
        throw new ApiError(404, "not_found");
      }
      const view = { ...context(actor, env), origin: url.origin };
      if (suffix === "settings") return html({ ...view, origin: url.origin, kind: "settings", ...(await manage<{ sessions: SessionView[] }>("sessions.list")), notificationDefaults: (await account<{ defaults: NotificationDefaultsView }>(env, accountId, "/notification-defaults")).defaults, readiness: readiness(env, url.origin) });
      if (suffix === "team") {
        owner(actor);
        const members = await identity<{ members: MemberView[] }>(env, "/members", identityInput);
        const invitations = await identity<{ invitations: InvitationView[] }>(env, "/invitations", identityInput);
        return html({ ...view, kind: "team", ...members, ...invitations });
      }
      if (suffix === "api-keys") return html({ ...view, kind: "api-keys", ...(await identity<{ keys: ApiKeyView[] }>(env, "/api-keys", identityInput)) });
      if (suffix === "import-export") return html({ ...view, kind: "import-export" });
      if (suffix === "api-docs") return html({ ...view, kind: "api-docs", origin: url.origin, tools: toolsFor(actor) });
      if (suffix === "audit") return html({ ...view, kind: "audit", ...(await identity<{ entries: AuditView[] }>(env, "/audit", identityInput)) });
      const snapshot = await account<EngineSnapshot>(env, accountId, "/state");
      const monitors = snapshot.monitors;
      if (suffix === "wallet" || suffix === "") {
        const wallet = await account<WalletView>(env, accountId, "/usage");
        if (suffix === "wallet") return html({ ...view, kind: "wallet", wallet });
        return html({ ...view, origin: url.origin, kind: "dashboard", monitors, wallet, incidents: snapshot.incidents, deliveries: snapshot.notifications as DeliveryView[], readiness: readiness(env, url.origin), notificationDefaults: (await account<{ defaults: NotificationDefaultsView }>(env, accountId, "/notification-defaults")).defaults });
      }
      if (suffix === "notifications") return html({ ...view, kind: "notifications", monitors, deliveries: snapshot.notifications as DeliveryView[] });
      if (suffix === "reports") {
        const search = new URLSearchParams(url.search);
        for (const field of ["from", "to"]) { const value = search.get(field); if (value && value.includes("T")) search.set(field, String(Date.parse(`${value}${value.endsWith("Z") ? "" : "Z"}`))); }
        return html({ ...view, origin: url.origin, kind: "reports", report: await account(env, accountId, `/reports?${search}`), monitors });
      }
      if (suffix === "status-page") { const result = await account<{ page: PublicPageConfig | null; revision: number }>(env, accountId, "/status-page"); return html({ ...view, kind: "status-page-edit", page: result.page, pageRevision: result.revision, monitors, incidents: snapshot.incidents }); }
      if (suffix === "new-monitor") { editor(actor); return html({ ...view, origin: url.origin, kind: "monitor-edit", monitor: null, notificationDefaults: (await account<{ defaults: NotificationDefaultsView }>(env, accountId, "/notification-defaults")).defaults }); }
      const monitorRoute = suffix.match(/^monitors\/([A-Za-z0-9_-]{1,64})(?:\/(edit))?$/);
      if (monitorRoute) {
        const monitor = monitors.find(item => item.id === monitorRoute[1]);
        if (!monitor) throw new ApiError(404, "monitor_not_found");
        if (monitorRoute[2]) { editor(actor); return html({ ...view, kind: "monitor-edit", monitor }); }
        return html({ ...view, origin: url.origin, kind: "monitor", monitor, observations: snapshot.observations.filter(item => item.monitorId === monitor.id), incidents: snapshot.incidents.filter(item => item.monitorId === monitor.id), deliveries: snapshot.notifications.filter(item => item.monitorId === monitor.id) as DeliveryView[], coverage: snapshot.coverage.filter(item => item.monitorId === monitor.id), maintenance: (await account<{ maintenance: MaintenanceWindow[] }>(env, accountId, "/maintenance")).maintenance.filter(item => item.monitorId === monitor.id), report: await account(env, accountId, `/reports?monitorId=${monitor.id}`) });
      }
      throw new ApiError(404, "not_found");
    }
    if (!["POST", "PUT", "DELETE"].includes(request.method)) throw new ApiError(405, "method_not_allowed");
    const parsed: ParsedInput = request.method === "DELETE" && !request.body ? { values: {}, form: null } : await parseInput(request, suffix === "monitors/import" ? 1048576 : 32768);
    const values = parsed.values;
    mutation(request, actor, values);
    if (suffix === "settings/workspace" || suffix === "workspace") { const result = await manage("workspace.rename", { name: values.name }); return api ? secureResponse(json(result)) : redirect(`${root}/settings`); }
    if (suffix === "settings/notification-defaults" || suffix === "notification-defaults") {
      const input = parsed.form ? { revision: formNumber(values, "revision"), webhookMode: values.webhookMode, emailMode: values.emailMode, ...(values.webhookMode === "replace" ? { webhook: { url: values.webhookUrl, secret: values.webhookSecret } } : {}), ...(values.emailMode === "replace" ? { email: { address: values.emailAddress } } : {}) } : values;
      const result = await account(env, accountId, "/notification-defaults", "PUT", input);
      return api ? secureResponse(json(result)) : redirect(`${root}/settings`);
    }
    if (suffix === "monitors/bulk") {
      const input = parsed.form ? { action: values.action, monitors: parsed.form.getAll("monitorId").map(id => ({ id, revision: formNumber(values, `revision_${id}`) })) } : values;
      const result = await account(env, accountId, "/monitors/bulk", "POST", input);
      return api ? secureResponse(json(result)) : redirect(root);
    }
    if (suffix === "maintenance") {
      const timestamp = (value: unknown): number => typeof value === "string" ? Date.parse(`${value}${value.endsWith("Z") ? "" : "Z"}`) : Number(value);
      const input = parsed.form ? { monitorId: values.monitorId, revision: formNumber(values, "revision"), startsAt: timestamp(values.startsAt), endsAt: timestamp(values.endsAt), reason: values.reason } : values;
      const result = await account(env, accountId, "/maintenance", "POST", input);
      return api ? secureResponse(json(result, 201)) : redirect(`${root}/monitors/${values.monitorId}`);
    }
    const maintenanceCancel = suffix.match(/^maintenance\/([A-Za-z0-9_-]{1,64})(?:\/cancel)?$/);
    if (maintenanceCancel) { const result = await account(env, accountId, `/maintenance/${maintenanceCancel[1]}`, "DELETE", { revision: formNumber(values, "revision") }); return api ? secureResponse(json(result)) : redirect(values.monitorId ? `${root}/monitors/${values.monitorId}` : root); }
    const acknowledgement = suffix.match(/^incidents\/([A-Za-z0-9:_-]+)\/acknowledgement$/);
    if (acknowledgement) { const result = await manage(values.acknowledged === false || values.acknowledged === "false" || request.method === "DELETE" ? "incident.unacknowledge" : "incident.acknowledge", { incidentId: acknowledgement[1] }); return api ? secureResponse(json(result)) : redirect(values.monitorId ? `${root}/monitors/${values.monitorId}` : root); }
    if (suffix === "settings/password" || (api && suffix === "password")) {
      sessionOnly(actor); await identity(env, "/password", { ...values, userId: actor.actor.id, sessionId: actor.sessionId, client: request.headers.get("X-Tomato-Client-IP") ?? "unknown" });
      return api ? secureResponse(json({ changed: true })) : redirect(`${root}/settings`);
    }
    if (suffix === "settings/sessions/revoke" || suffix === "settings/sessions/revoke-others") {
      sessionOnly(actor);
      await identity(env, suffix.endsWith("revoke-others") ? "/sessions/revoke-others" : "/sessions/revoke", { userId: actor.actor.id, sessionId: actor.sessionId, id: values.sessionId });
      return redirect(`${root}/settings`);
    }
    if (suffix === "api-keys" && request.method === "POST") {
      sessionOnly(actor);
      const result = await manage<{ key: ApiKeyView; apiKey: string }>("key.create", { name: values.name, scope: values.scope, ...(values.expiresInDays !== undefined ? { expiresInDays: Number(values.expiresInDays) } : {}), ...(values.expiresAt !== undefined ? { expiresAt: values.expiresAt } : {}) });
      return api ? secureResponse(json(result, 201)) : html({ ...context(actor, env), origin: url.origin, kind: "api-key-reveal", ...result });
    }
    const keyRevoke = suffix.match(/^api-keys(?:\/(revoke|[A-Za-z0-9_-]{1,64}))$/);
    if (keyRevoke) {
      sessionOnly(actor); await identity(env, "/api-keys/revoke", { ...identityInput, id: keyRevoke[1] === "revoke" ? values.keyId : keyRevoke[1] });
      return api ? secureResponse(json({ revoked: true })) : redirect(`${root}/api-keys`);
    }
    if (suffix === "team/invitations" || suffix === "invitations") {
      owner(actor);
      const result = await identity<{ invitation: InvitationView; invitationToken: string }>(env, "/invitations/create", { ...values, ...identityInput });
      const invitationUrl = `${url.origin}/invite/${result.invitationToken}`;
      return api ? secureResponse(json({ ...result, invitationUrl }, 201)) : html({ ...context(actor, env), kind: "invitation-reveal", invitation: result.invitation, invitationUrl });
    }
    const inviteRevoke = suffix.match(/^(?:team\/invitations\/revoke|invitations\/([A-Za-z0-9_-]{1,64}))$/);
    if (inviteRevoke) {
      owner(actor); await identity(env, "/invitations/revoke", { ...identityInput, id: inviteRevoke[1] ?? values.invitationId });
      return api ? secureResponse(json({ revoked: true })) : redirect(`${root}/team`);
    }
    const memberChange = suffix.match(/^(?:team\/members\/(role|remove)|members\/([A-Za-z0-9_-]{1,64}))$/);
    if (memberChange) {
      owner(actor); await identity(env, "/members/change", { ...identityInput, userId: memberChange[2] ?? values.userId, role: values.role, remove: memberChange[1] === "remove" || request.method === "DELETE" });
      return api ? secureResponse(json({ changed: true })) : redirect(`${root}/team`);
    }
    if (suffix === "status-page" || suffix.startsWith("status-page/")) {
      owner(actor);
      if (suffix === "status-page/unpublish" || request.method === "DELETE" && suffix === "status-page") {
        const previous = await account<{ page: PublicPageConfig | null }>(env, accountId, "/status-page");
        await account(env, accountId, "/status-page", "DELETE", { revision: formNumber(values, "revision") });
        await audit(env, actor, "status_page.unpublish", previous.page?.slug ?? accountId);
        return api ? secureResponse(json({ unpublished: true })) : redirect(`${root}/status-page`);
      }
      if (suffix === "status-page/updates" && request.method === "POST") {
        const result = await account(env, accountId, "/status-page/updates", "POST", { ...values, revision: formNumber(values, "revision") });
        await audit(env, actor, "status_page.update", String(values.incidentId ?? ""));
        return api ? secureResponse(json(result, 201)) : redirect(`${root}/status-page`);
      }
      const updateDelete = suffix.match(/^status-page\/updates\/(remove|[A-Za-z0-9_-]{1,64})$/);
      if (updateDelete) {
        const updateId = updateDelete[1] === "remove" ? values.updateId : updateDelete[1];
        await account(env, accountId, "/status-page/updates", "DELETE", { id: identifier(String(updateId)), revision: formNumber(values, "revision") });
        await audit(env, actor, "status_page.update_remove", String(updateId));
        return api ? secureResponse(json({ removed: true })) : redirect(`${root}/status-page`);
      }
      if (suffix !== "status-page") throw new ApiError(404, "not_found");
      const existing = (await account<{ page: PublicPageConfig | null }>(env, accountId, "/status-page")).page;
      const pageInput = parsed.form ? { revision: formNumber(values, "revision"), slug: values.slug, title: values.title, published: values.published === "on", components: parsed.form.getAll("componentId").map(monitorId => ({ monitorId, label: String(values[`componentLabel_${monitorId}`] ?? "") })) } : values;
      if (existing && existing.slug !== pageInput.slug) throw new ApiError(409, "status_slug_immutable_until_unpublished");
      const result = await account(env, accountId, "/status-page", "PUT", pageInput);
      await audit(env, actor, "status_page.configure", String(pageInput.slug));
      return api ? secureResponse(json(result)) : redirect(`${root}/status-page`);
    }
    editor(actor);
    if (suffix === "monitors/import") {
      let configuration: unknown = values;
      if (parsed.form) { try { configuration = JSON.parse(String(values.configuration ?? "")); } catch { throw new ApiError(400, "invalid_import_json"); } }
      const result = await account<{ importedCount: number; monitors: { monitor: MonitorView; heartbeatToken?: string }[] }>(env, accountId, "/monitors/import", "POST", configuration);
      await audit(env, actor, "monitors.import", accountId);
      if (api) return secureResponse(json(result, 201));
      return html({
        ...context(actor, env), kind: "import-export", importedCount: result.importedCount,
        importedHeartbeats: result.monitors.flatMap(entry => entry.heartbeatToken ? [{
          monitorId: entry.monitor.id, name: entry.monitor.name, token: entry.heartbeatToken,
          url: `${url.origin}/heartbeat/${accountId}/${entry.monitor.id}`,
        }] : []),
      });
    }
    if ((!api && suffix === "new-monitor") || (suffix === "monitors" && request.method === "POST")) {
      if (parsed.form) failedEditor = { actor, values, monitor: null };
      const input = parsed.form ? monitorForm(values) : values;
      const result = await account<{ monitor: MonitorView; heartbeatToken?: string }>(env, accountId, "/monitors", "POST", input);
      await audit(env, actor, "monitor.create", result.monitor.id);
      if (api) return secureResponse(json({ ...result, monitor: result.monitor }, 201));
      if (result.heartbeatToken) return html({ ...context(actor, env), kind: "heartbeat-token", monitor: result.monitor, heartbeatToken: result.heartbeatToken, heartbeatUrl: `${url.origin}/heartbeat/${accountId}/${result.monitor.id}` });
      return redirect(`${root}/monitors/${result.monitor.id}`);
    }
    const monitorMutation = suffix.match(/^monitors\/([A-Za-z0-9_-]{1,64})(?:\/(edit|delete|pause|resume|heartbeat-token|notification-test|check-now))?$/);
    if (monitorMutation) {
      const id = monitorMutation[1]!;
      const action = monitorMutation[2];
      if (parsed.form && action === "edit") failedEditor = { actor, values, monitor: (await account<{ monitor: MonitorView }>(env, accountId, `/monitors/${id}`)).monitor };
      let target: string; let method: string; let payload: unknown;
      if (action === "delete" || (!action && request.method === "DELETE")) { target = `/monitors/${id}`; method = "DELETE"; payload = { revision: parsed.form ? formNumber(values, "revision") : values.revision }; }
      else if (action === "edit" || (!action && request.method === "PUT")) { target = `/monitors/${id}`; method = "PUT"; payload = parsed.form ? monitorForm(values, id) : { ...values, id }; }
      else if (action && ["pause", "resume", "heartbeat-token", "notification-test", "check-now"].includes(action)) { target = `/monitors/${id}/${action}`; method = "POST"; payload = { ...values, ...(parsed.form && values.revision !== undefined ? { revision: formNumber(values, "revision") } : {}) }; }
      else throw new ApiError(405, "method_not_allowed");
      const result = await account<{ monitor?: MonitorView; heartbeatToken?: string }>(env, accountId, target, method, payload);
      await audit(env, actor, `monitor.${action ?? method.toLowerCase()}`, id);
      if (api) return secureResponse(json({ ...result, ...(result.monitor ? { monitor: result.monitor } : {}) }));
      if (result.heartbeatToken) {
        const monitor = result.monitor ?? (await account<{ monitor: MonitorView }>(env, accountId, `/monitors/${id}`)).monitor;
        return html({ ...context(actor, env), kind: "heartbeat-token", monitor: monitor, heartbeatToken: result.heartbeatToken, heartbeatUrl: `${url.origin}/heartbeat/${accountId}/${id}` });
      }
      return redirect(action === "delete" ? root : `${root}/monitors/${id}`);
    }
    const notificationRetry = suffix.match(/^notifications\/(retry|[A-Za-z0-9:_-]+\/retry)$/);
    if (notificationRetry) {
      const eventId = notificationRetry[1] === "retry" ? values.eventId : notificationRetry[1]!.slice(0, -6);
      const result = await account(env, accountId, "/notifications/retry", "POST", { eventId });
      await audit(env, actor, "notification.retry", String(eventId));
      return api ? secureResponse(json(result)) : redirect(`${root}/notifications`);
    }
    throw new ApiError(404, "not_found");
    }
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    if (api) return secureResponse(json({ error: error.message }, error.status));
    if (error.status === 401 && path !== "/login" && !path.startsWith("/invite/") && !path.startsWith("/enroll")) return redirect("/login");
    if (failedEditor && !api) {
      const entered: Record<string, string> = {};
      for (const [name, value] of Object.entries(failedEditor.values)) if (typeof value === "string" && !/password|secret|headers|csrf/i.test(name)) entered[name] = value;
      return html({ ...context(failedEditor.actor, env), origin: url.origin, kind: "monitor-edit", monitor: failedEditor.monitor, entered, error: error.message }, error.status);
    }
    if (path === "/login") {
      const csrf = await anonymousCsrf(env);
      return html({ kind: "login", csrfToken: csrf.token, pilotOnly: true, next: loginDestination(url.searchParams.get("next")), ...env.identity.capabilities, error: error.message }, error.status, { "Set-Cookie": setCookie(env, csrfName(env), csrf.signed, 900) });
    }
    return html({ kind: "error", status: error.status, error: error.message }, error.status);
  }
}
