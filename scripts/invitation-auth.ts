import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import type { IdentityConfig } from "../src/identity.ts";
import type { Principal } from "../src/product-types.ts";
import { createProductionTestRuntime } from "./production-test-runtime.ts";

export interface InvitationAcceptanceFixture { verifyOutage(): Promise<void>; close(): Promise<void> }
interface AnonymousInvitation { id: string; path: string; email: string; cookie: string; csrfToken: string }

/** Independent browser cookie jars exercise real rendered forms and real TLS SMTP receipts, not remembered tab state. */
export async function verifyClosedInvitationFlow(smtp: NonNullable<IdentityConfig["smtp"]>, messages: string[]): Promise<InvitationAcceptanceFixture> {
  const runtime = await createProductionTestRuntime({ runtime: { mode: "self-host", signupEnabled: false, smtp } }), password = randomBytes(24).toString("hex");
  try {
    await runtime.env.identity.provision({ id: "closed-invites", name: "Joined Workspace", owner: { email: "invite-owner@example.test", name: "Invitation Fixture Owner", password, emailVerified: true } });
    const ownerLogin = await runtime.fetch("/api/auth/sign-in/email", { method: "POST", headers: { Origin: runtime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email: "invite-owner@example.test", password }) }); assert.equal(ownerLogin.status, 200);
    const ownerCookie = ownerLogin.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; "), ownerSession = await runtime.fetch("/api/session", { headers: { Cookie: ownerCookie } }); assert.equal(ownerSession.status, 200); const owner = await ownerSession.json() as Principal;
    const createInvitation = async (email: string): Promise<AnonymousInvitation> => {
      const created = await runtime.fetch("/api/accounts/closed-invites/invitations", { method: "POST", headers: { Origin: runtime.baseUrl, Cookie: ownerCookie, "Content-Type": "application/json", "X-CSRF-Token": owner.csrfToken }, body: JSON.stringify({ username: email, role: "viewer" }) }); assert.equal(created.status, 201);
      const invitation = await created.json() as { invitation: { id: string }; invitationToken: string }, path = `/invite/${invitation.invitationToken}`;
      const anonymous = await runtime.fetch(path), html = await anonymous.text(); assert.equal(anonymous.status, 200); const csrf = html.match(/name="csrfToken" value="([^"]+)"/); assert(csrf);
      return { id: invitation.invitation.id, path, email, csrfToken: csrf[1]!, cookie: anonymous.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ") };
    };
    const register = (invitation: AnonymousInvitation, forgedAddress: number) => runtime.fetch(invitation.path, { method: "POST", headers: { Origin: runtime.baseUrl, Cookie: invitation.cookie, "Content-Type": "application/json", "X-Tomato-Client-IP": `203.0.113.${forgedAddress}`, "X-Forwarded-For": `198.51.100.${forgedAddress}` }, body: JSON.stringify({ register: "true", csrfToken: invitation.csrfToken, name: "Invited 张 Identity", password, email: "uninvited-override@example.test", trustedClientIp: `192.0.2.${forgedAddress}` }), redirect: "manual" });
    const counter = async (key: string): Promise<number> => (await runtime.database.query<{ count: number }>("SELECT count FROM identity.attempts WHERE key=$1", [key]))[0]?.count ?? 0;
    const callerKey = `invitation-register-caller:${createHmac("sha256", runtime.env.AUTH_SECRET).update("127.0.0.1").digest("hex")}`;
    const signup = await runtime.fetch("/api/auth/sign-up/email", { method: "POST", headers: { Origin: runtime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email: "invited-fresh@example.test", name: "Fresh Invited Identity", password }) }); assert.equal(signup.status, 403);
    const first = await createInvitation("invited-fresh@example.test"), before = messages.length;
    const registered = await register(first, 1); assert.equal(registered.status, 303);
    const registeredReturn = new URL(registered.headers.get("Location")!, runtime.baseUrl); assert.equal(registeredReturn.searchParams.get("next"), first.path);
    let mail: string | undefined; const deadline = Date.now() + 10000;
    while (Date.now() < deadline) { mail = messages.slice(before).find(value => value.includes("Verify your Tomato email")); if (mail) break; await delay(20); }
    assert(mail); const decoded = mail.replace(/=\r\n/g, "").replace(/=3D/g, "="), link = decoded.match(/http[^\s<>]+\/api\/auth\/verify-email\?[^\s<>]+/); assert(link);
    // Discard the registration browser's cookies: only the delivered verification link opens this fresh tab.
    const verified = await runtime.fetch(link[0], { redirect: "manual" }); assert.equal(verified.status, 302);
    const returnURL = new URL(verified.headers.get("Location")!, runtime.baseUrl); assert.equal(returnURL.pathname, "/login"); assert.equal(returnURL.searchParams.get("next"), first.path);
    const loginPage = await runtime.fetch(returnURL), loginHtml = await loginPage.text(); assert.equal(loginPage.status, 200);
    const loginCsrf = loginHtml.match(/name="csrfToken" value="([^"]+)"/), next = loginHtml.match(/name="next" value="([^"]+)"/); assert(loginCsrf); assert(next); assert.equal(next[1], first.path);
    const freshCookie = loginPage.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");
    const signedIn = await runtime.fetch("/login", { method: "POST", headers: { Origin: runtime.baseUrl, Cookie: freshCookie, "Content-Type": "application/json" }, body: JSON.stringify({ email: first.email, password, csrfToken: loginCsrf[1], next: next[1] }), redirect: "manual" }); assert.equal(signedIn.status, 303); assert.equal(signedIn.headers.get("Location"), first.path);
    const sessionCookie = signedIn.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; "), acceptancePage = await runtime.fetch(first.path, { headers: { Cookie: sessionCookie } }); assert.equal(acceptancePage.status, 200);
    const acceptCsrf = (await acceptancePage.text()).match(/name="csrfToken" value="([^"]+)"/); assert(acceptCsrf);
    const accepted = await runtime.fetch(first.path, { method: "POST", headers: { Origin: runtime.baseUrl, Cookie: sessionCookie, "Content-Type": "application/json" }, body: JSON.stringify({ csrfToken: acceptCsrf[1] }), redirect: "manual" }); assert.equal(accepted.status, 303); assert.equal(accepted.headers.get("Location"), "/app/accounts/closed-invites");
    const joined = await runtime.fetch(accepted.headers.get("Location")!, { headers: { Cookie: sessionCookie } }); assert.equal(joined.status, 200);
    const sessionResponse = await runtime.fetch("/api/session", { headers: { Cookie: sessionCookie } }); assert.equal(sessionResponse.status, 200); const principal = await sessionResponse.json() as Principal; assert.equal(principal.actor.username, first.email); assert.equal(principal.accounts.find(value => value.id === "closed-invites")?.role, "viewer"); assert.equal(principal.accounts.filter(value => value.role === "owner").length, 1);
    const replayed = await runtime.fetch(first.path, { method: "POST", headers: { Origin: runtime.baseUrl, Cookie: sessionCookie, "Content-Type": "application/json" }, body: JSON.stringify({ csrfToken: acceptCsrf[1] }), redirect: "manual" }); assert.equal(replayed.status, 404); assert.equal((await register(first, 2)).status, 404);
    assert.equal((await runtime.database.query<{ count: number }>("SELECT COUNT(*)::integer AS count FROM public.auth_user WHERE email=$1", ["uninvited-override@example.test"]))[0]!.count, 0);
    const concurrent = await createInvitation("invited-concurrent@example.test"), concurrencyBefore = messages.length;
    const concurrentResponses = await Promise.all(Array.from({ length: 6 }, (_, index) => register(concurrent, index + 10)));
    assert.equal(concurrentResponses.filter(response => response.status === 429).length, 3); assert(concurrentResponses.every(response => [303, 400, 409, 422, 429].includes(response.status)));
    assert.equal(await counter(`invitation-register:${concurrent.id}`), 3); assert.equal(await counter(callerKey), 4);
    assert(messages.slice(concurrencyBefore).filter(value => value.includes("Verify your Tomato email")).length <= 3);
    assert.equal((await runtime.database.query<{ count: number }>("SELECT COUNT(*)::integer AS count FROM public.auth_user WHERE email=$1", [concurrent.email]))[0]!.count, 1);
    return { close: runtime.close, async verifyOutage() {
      const outageBefore = messages.length, outage = await createInvitation("invited-outage@example.test");
      for (let attempt = 0; attempt < 3; attempt++) assert.equal((await register(outage, attempt + 30)).status, 503);
      assert.equal((await register(outage, 33)).status, 429); assert.equal(await counter(`invitation-register:${outage.id}`), 3); assert.equal(await counter(callerKey), 7);
      assert.equal(messages.length, outageBefore); assert.equal((await runtime.database.query<{ count: number }>("SELECT COUNT(*)::integer AS count FROM public.auth_user WHERE email=$1", [outage.email]))[0]!.count, 0);
      const secondOutage = await createInvitation("invited-second-outage@example.test");
      for (let attempt = 0; attempt < 3; attempt++) assert.equal((await register(secondOutage, attempt + 40)).status, 503);
      const callerBlocked = await createInvitation("invited-caller-blocked@example.test"); assert.equal((await register(callerBlocked, 50)).status, 429); assert.equal(await counter(callerKey), 10); assert.equal(await counter(`invitation-register:${callerBlocked.id}`), 0);
      assert.equal(messages.length, outageBefore);
    } };
  } catch (error) { await runtime.close(); throw error; }
}
