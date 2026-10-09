import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { ProvisionInput } from "../src/identity.ts";
import type { Principal, MemberView, WalletView } from "../src/product-types.ts";
import { setTimeout as delay } from "node:timers/promises";
import { createProductionTestRuntime } from "./production-test-runtime.ts";

export async function verifyBootstrapIdentity(): Promise<void> {
  const password = randomBytes(24).toString("hex"), changedPassword = randomBytes(24).toString("hex");
  const initial: ProvisionInput = { id: "bootstrap", name: "Initial Workspace", owner: { email: "bootstrap-a@example.test", name: "Initial Owner", password, emailVerified: true } };
  const runtime = await createProductionTestRuntime({ runtime: { mode: "self-host", owner: initial } });
  const signIn = async (email: string, credential: string) => {
    const response = await runtime.fetch("/api/auth/sign-in/email", { method: "POST", headers: { Origin: runtime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email, password: credential }) }); assert.equal(response.status, 200);
    const token = response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; "), session = await runtime.fetch("/api/session", { headers: { Cookie: token } }); assert.equal(session.status, 200);
    return { cookie: token, principal: await session.json() as Principal };
  };
  const post = async (path: string, session: { cookie: string; principal: Principal }, input: unknown, status = 200) => {
    const response = await runtime.fetch(path, { method: "POST", headers: { Origin: runtime.baseUrl, Cookie: session.cookie, "Content-Type": "application/json", "X-CSRF-Token": session.principal.csrfToken }, body: JSON.stringify(input), redirect: "manual" }); assert.equal(response.status, status); return response;
  };
  try {
    const race: ProvisionInput = { id: "bootstrap-race", name: "Serialized Bootstrap", owner: { email: "bootstrap-race@example.test", name: "Concurrent Owner", password, emailVerified: true } };
    const concurrent = await Promise.all(Array.from({ length: 4 }, () => runtime.env.identity.ensureBootstrapOwner(race)));
    assert(concurrent.every(value => value.owner.id === concurrent[0]!.owner.id));
    assert.equal((await runtime.database.query<{ count: number }>("SELECT COUNT(*)::integer AS count FROM identity.bootstraps WHERE account_id=$1", [race.id]))[0]!.count, 1);
    const recovery: ProvisionInput = { id: "bootstrap-recovery", name: "Prior Provisioning Commit", owner: { email: "bootstrap-recovery@example.test", name: "Recovered Owner", password, emailVerified: true } };
    const provisioned = await runtime.env.identity.provision(recovery), recovered = await runtime.env.identity.ensureBootstrapOwner(recovery); assert.equal(recovered.owner.id, provisioned.owner.id);
    await assert.rejects(runtime.env.identity.ensureBootstrapOwner({ ...recovery, owner: { ...recovery.owner, email: initial.owner.email } }), /bootstrap_identity_conflict/);
    const a = await signIn(initial.owner.email, password);
    const peer = await runtime.env.identity.provision({ id: "bootstrap-peer", name: "Peer Workspace", owner: { email: "bootstrap-b@example.test", name: "Successor Owner", password, emailVerified: true } });
    const b = await signIn("bootstrap-b@example.test", password);
    const invitation = await post("/api/accounts/bootstrap/invitations", a, { username: "bootstrap-b@example.test", role: "owner" }, 201), invite = await invitation.json() as { invitationToken: string };
    await post(`/invite/${invite.invitationToken}`, b, { csrfToken: b.principal.csrfToken }, 303);
    await post(`/api/accounts/bootstrap/members/${a.principal.actor.id}`, b, { role: "viewer" });
    await post("/api/accounts/bootstrap/workspace", b, { name: "Transferred 张 Workspace" });
    await post("/api/auth/password", a, { currentPassword: password, newPassword: changedPassword });
    const changedHash = (await runtime.database.query<{ password: string }>('SELECT password FROM public.auth_account WHERE "userId"=$1 AND "providerId"=\'credential\'', [a.principal.actor.id]))[0]!.password;
    const monitorResponse = await post("/api/accounts/bootstrap/monitors", b, { check: { kind: "http", url: `${runtime.fixtures.httpUrl}/bootstrap-transfer-target` } }, 201), monitor = await monitorResponse.json() as { monitor: { id: string } };
    let up = false; const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      const response = await runtime.fetch("/api/accounts/bootstrap/state", { headers: { Cookie: b.cookie } }); assert.equal(response.status, 200);
      const state = await response.json() as { monitors: { id: string; state: string }[] };
      if (state.monitors.some(value => value.id === monitor.monitor.id && value.state === "UP")) { up = true; break; } await delay(25);
    }
    assert(up); assert((runtime.fixtures.hits.get("bootstrap-transfer-target") ?? 0) > 0);
    const beforeResponse = await runtime.fetch("/api/accounts/bootstrap/usage", { headers: { Cookie: b.cookie } }); assert.equal(beforeResponse.status, 200); const before = await beforeResponse.json() as WalletView;
    const markersBefore = await runtime.database.query<{ account_id: string; original_user_id: string; original_email: string; created_at: number }>("SELECT * FROM identity.bootstraps ORDER BY account_id");
    await runtime.restart();
    assert.equal((await runtime.fetch("/health/ready")).status, 200);
    assert.deepEqual(await runtime.database.query("SELECT * FROM identity.bootstraps ORDER BY account_id"), markersBefore);
    const ensured = await runtime.env.identity.ensureBootstrapOwner(initial); assert.equal(ensured.owner.id, peer.owner.id); assert.equal(ensured.account.name, "Transferred 张 Workspace");
    assert((await runtime.database.query<{ password: string }>('SELECT password FROM public.auth_account WHERE "userId"=$1 AND "providerId"=\'credential\'', [a.principal.actor.id]))[0]!.password === changedHash, "Restart must not reset the changed maintained password");
    const membersResponse = await runtime.fetch("/api/accounts/bootstrap/members", { headers: { Cookie: b.cookie } }); assert.equal(membersResponse.status, 200); const members = await membersResponse.json() as { members: MemberView[] };
    assert.equal(members.members.find(value => value.userId === a.principal.actor.id)?.role, "viewer"); assert.equal(members.members.find(value => value.userId === peer.owner.id)?.role, "owner");
    await post("/api/accounts/bootstrap/monitors", a, { check: { kind: "http", url: `${runtime.fixtures.httpUrl}/bootstrap-viewer-forbidden` } }, 403);
    const oldPassword = await runtime.fetch("/api/auth/sign-in/email", { method: "POST", headers: { Origin: runtime.baseUrl, "Content-Type": "application/json" }, body: JSON.stringify({ email: initial.owner.email, password }) }); assert.equal(oldPassword.status, 401);
    const changed = await signIn(initial.owner.email, changedPassword); assert.equal(changed.principal.actor.id, a.principal.actor.id); assert.equal(changed.principal.accounts.find(value => value.id === initial.id)?.role, "viewer");
    const afterResponse = await runtime.fetch("/api/accounts/bootstrap/usage", { headers: { Cookie: b.cookie } }); assert.equal(afterResponse.status, 200); const after = await afterResponse.json() as WalletView;
    assert.equal(after.mode, "self-host"); assert.equal(after.creditEnforced, false); assert.equal(after.balance, 0); assert.equal(after.grants.length, 0); assert(after.usage >= before.usage);
    const stateResponse = await runtime.fetch("/api/accounts/bootstrap/state", { headers: { Cookie: b.cookie } }); assert.equal(stateResponse.status, 200); const state = await stateResponse.json() as { monitors: { id: string; state: string }[] }; assert(state.monitors.some(value => value.id === monitor.monitor.id && value.state === "UP"));
    await assert.rejects(runtime.env.identity.ensureBootstrapOwner({ ...initial, owner: { ...initial.owner, email: "bootstrap-b@example.test" } }), /bootstrap_identity_conflict/);
  } finally { await runtime.close(); }
}
