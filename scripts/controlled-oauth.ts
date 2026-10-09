import assert from "node:assert/strict";
import tls from "node:tls";
import { setTimeout as delay } from "node:timers/promises";
import { createControlledOAuthIdentity, type IdentityConfig, type IdentityService } from "../src/identity.ts";
import type { Principal } from "../src/product-types.ts";
import type { ProductionTestRuntime } from "./production-test-runtime.ts";
import { createControlledIdp } from "./oauth-fixture.ts";

/** Maintained Better Auth follows a real owned TLS issuer; no user-info shortcut or production-provider impersonation. */
export async function verifyControlledOAuth(runtime: ProductionTestRuntime, config: IdentityConfig, certificate: string, key: string): Promise<void> {
  assert.equal(typeof tls.setDefaultCACertificates, "function", "Controlled TLS OAuth proof requires Node 24.5+ CA API");
  const authorities = tls.getCACertificates("default"), previousNodeEnv = process.env.NODE_ENV, previousService = runtime.env.identity;
  const issuer = await createControlledIdp(certificate, key, `${runtime.baseUrl}/api/auth/callback/tomato-controlled-idp`);
  let service: IdentityService | undefined;
  try {
    process.env.NODE_ENV = "test";
    tls.setDefaultCACertificates([...authorities, certificate]);
    assert.throws(() => createControlledOAuthIdentity(runtime.database, { ...config, baseURL: "https://non-test.example.test" }, issuer), /isolated_test_loopback/);
    service = createControlledOAuthIdentity(runtime.database, config, issuer); runtime.env.identity = service;
    const start = async () => {
      const response = await runtime.fetch("/api/auth/sign-in/social", { method: "POST", headers: { Origin: runtime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ provider: "tomato-controlled-idp", callbackURL: `${runtime.baseUrl}/app`, disableRedirect: true }), redirect: "manual" });
      assert.equal(response.status, 200);
      const body = await response.json() as { url: string };
      const authorization = new URL(body.url); assert.equal(authorization.origin, new URL(issuer.issuer).origin);
      assert.equal(authorization.searchParams.get("code_challenge_method"), "S256"); assert(authorization.searchParams.get("code_challenge")); assert(authorization.searchParams.get("state"));
      const authorized = await fetch(authorization, { redirect: "manual" }); assert.equal(authorized.status, 302);
      const callback = new URL(authorized.headers.get("Location")!); assert.equal(callback.origin, runtime.baseUrl);
      return { callback, cookie: response.headers.getSetCookie().map(value => value.split(";")[0]).join("; ") };
    };
    const rejectedFlow = await start(), tampered = new URL(rejectedFlow.callback);
    tampered.searchParams.set("state", `invalid-${tampered.searchParams.get("state")}`);
    const rejected = await runtime.fetch(tampered, { headers: { Cookie: rejectedFlow.cookie }, redirect: "manual" });
    assert(rejected.status >= 400 || rejected.headers.get("Location")?.includes("error="), "Maintained OAuth must reject mismatched state");
    assert.equal(issuer.tokenCount, 0); assert.equal(issuer.profileCount, 0);
    assert.equal((await runtime.database.query<{ count: number }>("SELECT COUNT(*)::integer AS count FROM public.auth_account WHERE \"providerId\"='tomato-controlled-idp'"))[0]!.count, 0);
    const acceptedFlow = await start();
    const accepted = await runtime.fetch(acceptedFlow.callback, { headers: { Cookie: acceptedFlow.cookie }, redirect: "manual" });
    assert.equal(accepted.status, 302); assert.equal(accepted.headers.get("Location"), `${runtime.baseUrl}/app`);
    assert.equal(issuer.authorizationCount, 2); assert.equal(issuer.tokenCount, 1); assert.equal(issuer.profileCount, 1);
    const cookie = accepted.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    const response = await runtime.fetch("/api/session", { headers: { Cookie: cookie } }); assert.equal(response.status, 200);
    const principal = await response.json() as Principal, account = principal.accounts[0]!;
    assert.equal(principal.actor.username, issuer.identity.email); assert.equal(principal.accounts.length, 1); assert.equal(account.role, "owner");
    const linked = (await runtime.database.query<{ accountId: string; providerId: string; emailVerified: boolean }>('SELECT a."accountId",a."providerId",u."emailVerified" FROM public.auth_account a JOIN public.auth_user u ON u.id=a."userId" WHERE a."userId"=$1 AND a."providerId"=$2', [principal.actor.id, "tomato-controlled-idp"]))[0]!;
    assert.equal(linked.accountId, issuer.identity.id); assert.equal(linked.providerId, "tomato-controlled-idp"); assert.equal(linked.emailVerified, true);
    assert.equal((await issuer.replayLastCode()).status, 400); assert.equal((await issuer.replayLastToken()).status, 401);
    const replay = await runtime.fetch(acceptedFlow.callback, { headers: { Cookie: acceptedFlow.cookie }, redirect: "manual" });
    assert(replay.status >= 400 || replay.headers.get("Location")?.includes("error="), "Maintained OAuth state is single-use");
    const target = `${runtime.fixtures.httpUrl}/controlled-oauth-target`;
    const created = await runtime.fetch(`/api/accounts/${account.id}/monitors`, { method: "POST", headers: { Cookie: cookie, Origin: runtime.baseUrl, "Content-Type": "application/json", "X-CSRF-Token": principal.csrfToken }, body: JSON.stringify({ check: { kind: "http", url: target } }) }); assert.equal(created.status, 201);
    const monitor = await created.json() as { monitor: { id: string } };
    let observed = false; const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      const stateResponse = await runtime.fetch(`/api/accounts/${account.id}/state`, { headers: { Cookie: cookie } }); assert.equal(stateResponse.status, 200);
      const state = await stateResponse.json() as { monitors: { id: string; state: string; lastObservedAt: number | null }[] };
      if (state.monitors.some(value => value.id === monitor.monitor.id && value.state === "UP" && value.lastObservedAt !== null)) { observed = true; break; } await delay(25);
    }
    assert(observed, "Verified controlled-provider login must own a usable workspace and reach real UP through production prober");
    assert((runtime.fixtures.hits.get("controlled-oauth-target") ?? 0) > 0);
    const usageResponse = await runtime.fetch(`/api/accounts/${account.id}/usage`, { headers: { Cookie: cookie } }); assert.equal(usageResponse.status, 200);
    const usage = await usageResponse.json() as { mode: string; creditEnforced: boolean; balance: number; grants: unknown[]; usage: number };
    assert.equal(usage.mode, "self-host"); assert.equal(usage.creditEnforced, false); assert.equal(usage.balance, 0); assert.equal(usage.grants.length, 0); assert(usage.usage >= 1);
    const logout = await runtime.fetch("/api/auth/sign-out", { method: "POST", headers: { Origin: runtime.baseUrl, Cookie: cookie, "Content-Type": "application/json" }, body: "{}" }); assert.equal(logout.status, 200);
    assert.equal((await runtime.fetch("/api/session", { headers: { Cookie: cookie } })).status, 401);
  } finally {
    runtime.env.identity = previousService;
    try { await service?.drain(); } finally { try { await issuer.close(); } finally { tls.setDefaultCACertificates(authorities); if (previousNodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previousNodeEnv; } }
  }
}
