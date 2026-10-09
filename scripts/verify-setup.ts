import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { NativeClient } from "./local-client.ts";
import { createProductionTestRuntime, type ProductionTestRuntime } from "./production-test-runtime.ts";
import { frontendAllocationRange, mutablePath, root } from "./selfhost.mjs";

const run = promisify(execFile);
const scratch = await mkdtemp(path.join(os.tmpdir(), "tomato-setup-"));
const directory = path.join(scratch, "independent");
const passwordFile = path.join(scratch, "owner-password");
const password = randomBytes(24).toString("hex");
const bootstrap = fileURLToPath(new URL("./bootstrap.mjs", import.meta.url));
const args = [bootstrap, "--configure-only", "--origin", "https://tomato.localhost", "--owner-email", "setup-owner@example.test", "--owner-name", "Setup fixture owner", "--owner-password-file", passwordFile, "--owner-email-verified", "--account-id", "independent", "--account-name", "Independent self-host", "--state-dir", directory];
const bootstrapOptions = { env: { NODE_ENV: "test" } };
let service: ProductionTestRuntime | undefined;
try {
  for (const target of [
    root, path.join(root, "src"), path.join(root, "public"),
    path.join(root, "src", "setup-rejected"), path.join(root, "research", "setup-rejected"),
    path.join(root, "private"), path.join(root, ".tomato-local", "setup-rejected"),
    path.join(root, ".tomato-dev", "setup-rejected"), path.join(root, ".wrangler", "setup-rejected"),
    path.join(os.homedir(), "Library", "Application Support", "Tomato", "setup-rejected"),
  ]) {
    // The guard is read-only: never launch bootstrap writes at a repository or protected destination.
    await assert.rejects(mutablePath(target), "Mutable setup state must reject repository source and protected destinations before creating any files");
  }
  const protectedFixture = path.join(scratch, "Library", "Application Support", "Tomato");
  await mkdir(protectedFixture, { recursive: true, mode: 0o700 });
  const sentinel = path.join(protectedFixture, "sentinel");
  await writeFile(sentinel, "isolated-path-guard-fixture", { mode: 0o600, flag: "wx" });
  const alias = path.join(scratch, "protected-alias");
  await symlink(protectedFixture, alias, "dir");
  await assert.rejects(mutablePath(protectedFixture));
  await assert.rejects(mutablePath(alias));
  await assert.rejects(mutablePath(path.join(alias, "new-state")), "Symlink ancestors must not bypass protected-target rejection");
  assert.deepEqual(await readdir(protectedFixture), ["sentinel"]);
  assert.equal(await readFile(sentinel, "utf8"), "isolated-path-guard-fixture", "Rejected destinations must remain unmodified");
  console.log("PASS read-only setup guards reject source/private/protected destinations and symlink targets without touching live protected data");
  await writeFile(passwordFile, password, { mode: 0o600, flag: "wx" });
  await run(process.execPath, args, bootstrapOptions);
  async function configurationSnapshot(): Promise<string> {
    const hash = createHash("sha256");
    const visit = async (parent: string): Promise<void> => {
      assert.equal((await stat(parent)).mode & 0o077, 0, "Portable state and credential directories must be private");
      const entries = (await readdir(parent, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
      for (const entry of entries) {
        const file = path.join(parent, entry.name);
        if (entry.isDirectory()) await visit(file);
        else {
          assert(entry.isFile(), "Portable setup must not write symlink credentials");
          assert.equal((await stat(file)).mode & 0o077, 0, "Portable configuration and secret files must be private");
          hash.update(path.relative(directory, file)).update(await readFile(file));
        }
      }
    };
    await visit(directory);
    return hash.digest("hex");
  }
  let before = await configurationSnapshot();
  await run(process.execPath, args, bootstrapOptions);
  assert.equal(await configurationSnapshot(), before, "Repeated portable setup must not rotate operator, authentication, database or owner credentials");
  const configBytes = await readFile(path.join(directory, "config.json"));
  const configured = JSON.parse(configBytes.toString("utf8")) as { mode: "self-host" | "hosted"; accountId: string; accountName: string; ownerEmail: string; ownerName: string; ownerEmailVerified: boolean; frontendSubnet: string; proxyIP: string };
  const allocation = frontendAllocationRange(configured);
  const [poolAddress, poolPrefix] = allocation.split("/");
  assert(poolAddress && poolPrefix);
  const subnetAddress = configured.frontendSubnet.split("/")[0]!;
  const subnetBase = subnetAddress.split(".").reduce((value, octet) => value * 256 + Number(octet), 0);
  const poolBase = poolAddress.split(".").reduce((value, octet) => value * 256 + Number(octet), 0);
  const proxyAddress = configured.proxyIP.split(".").reduce((value, octet) => value * 256 + Number(octet), 0);
  const poolSize = 2 ** (32 - Number(poolPrefix));
  assert.equal(proxyAddress, subnetBase + 2, "The actual proxy must occupy the reserved subnet+2 endpoint");
  assert(poolBase >= subnetBase && poolBase + poolSize <= subnetBase + 16, "Dynamic frontend addresses must stay within the deployment subnet");
  assert(proxyAddress < poolBase || proxyAddress >= poolBase + poolSize, "Dynamic app allocation must exclude the exact reserved proxy endpoint");
  const envPath = path.join(directory, "compose.env");
  const originalEnv = await readFile(envPath, "utf8");
  const allocationLines = originalEnv.split("\n").filter(line => line.startsWith("TOMATO_FRONTEND_IP_RANGE="));
  assert.deepEqual(allocationLines, [`TOMATO_FRONTEND_IP_RANGE='${allocation}'`]);
  const legacyEnv = originalEnv.split("\n").filter(line => !line.startsWith("TOMATO_FRONTEND_IP_RANGE=")).join("\n");
  const secretDirectory = path.join(directory, "secrets");
  const secretNames = (await readdir(secretDirectory)).sort();
  const secretBytes = await Promise.all(secretNames.map(name => readFile(path.join(secretDirectory, name))));
  await writeFile(envPath, legacyEnv, { mode: 0o600 });
  await run(process.execPath, args, bootstrapOptions);
  const upgradedEnv = await readFile(envPath, "utf8");
  assert.equal(upgradedEnv, `${legacyEnv}${legacyEnv.endsWith("\n") ? "" : "\n"}TOMATO_FRONTEND_IP_RANGE='${allocation}'\n`, "Topology upgrade must append only the missing allocation policy without rewriting existing environment bytes");
  assert.deepEqual((await readdir(secretDirectory)).sort(), secretNames);
  assert.deepEqual(await Promise.all(secretNames.map(name => readFile(path.join(secretDirectory, name)))), secretBytes, "Topology upgrade must leave every credential unchanged");
  await run(process.execPath, args, bootstrapOptions);
  assert.equal(await readFile(envPath, "utf8"), upgradedEnv, "Repeated topology upgrades must be byte-identical and append the allocation policy exactly once");
  assert.deepEqual(await readFile(path.join(directory, "config.json")), configBytes, "Allocation migration must not rewrite existing deployment configuration");
  before = await configurationSnapshot();
  console.log("PASS portable topology reserves the exact proxy endpoint and upgrades old allocation configuration append-once without credential rotation");
  const changed = [...args]; changed[changed.indexOf("--origin") + 1] = "https://changed.localhost";
  await assert.rejects(run(process.execPath, changed, bootstrapOptions), "An existing installation must reject changed identity/origin configuration");
  assert.equal(await configurationSnapshot(), before, "Rejected changes must not alter private setup state");
  await chmod(passwordFile, 0o644);
  const unsafe = [...args]; unsafe[unsafe.indexOf("--state-dir") + 1] = path.join(scratch, "insecure-input");
  await assert.rejects(run(process.execPath, unsafe, bootstrapOptions), "World-readable owner password inputs must be rejected");
  await chmod(passwordFile, 0o600);
  console.log("PASS portable setup writes private, repeatable configuration from an explicit attested fixture email and rejects changed/insecure input");

  assert.equal(configured.mode, "self-host", "Portable setup must default to self-host rather than credit enforcement");
  const storedPassword = await readFile(path.join(directory, "secrets", "owner_password"), "utf8");
  assert.equal(storedPassword, password);
  const owner = { id: configured.accountId, name: configured.accountName, owner: { email: configured.ownerEmail, name: configured.ownerName, password: storedPassword, emailVerified: configured.ownerEmailVerified } };
  service = await createProductionTestRuntime({ runtime: { mode: configured.mode, owner } });
  let client = new NativeClient(service.baseUrl);
  await client.login(configured.ownerEmail, storedPassword);
  const session = JSON.parse((await client.request("/api/session", { expected: 200 })).text) as { actor: { id: string }; csrfToken: string };
  const usageBefore = JSON.parse((await client.request("/api/accounts/independent/usage", { expected: 200 })).text) as { mode: string; creditEnforced: boolean; balance: number; grants: unknown[] };
  assert.equal(usageBefore.mode, "self-host"); assert.equal(usageBefore.creditEnforced, false); assert.equal(usageBefore.balance, 0); assert.equal(usageBefore.grants.length, 0);
  await client.request("/app/accounts/independent/settings/workspace", { form: new URLSearchParams({ csrfToken: session.csrfToken, name: "Renamed self-host" }), expected: 303 });
  await service.restart();
  client = new NativeClient(service.baseUrl);
  await client.login(configured.ownerEmail, storedPassword);
  const after = JSON.parse((await client.request("/api/session", { expected: 200 })).text) as { actor: { id: string }; accounts: Array<{ id: string; name: string }> };
  const usageAfter = JSON.parse((await client.request("/api/accounts/independent/usage", { expected: 200 })).text) as { creditEnforced: boolean; balance: number; grants: unknown[] };
  assert.equal(after.actor.id, session.actor.id, "Node restart must preserve the PostgreSQL owner identity");
  assert.equal(after.accounts.find(account => account.id === "independent")?.name, "Renamed self-host", "Idempotent owner bootstrap must not reset managed workspace settings");
  assert.equal(usageAfter.creditEnforced, false); assert.equal(usageAfter.balance, 0); assert.equal(usageAfter.grants.length, 0);
  assert.equal(await configurationSnapshot(), before);
  console.log("PASS generated self-host setup boots and restarts real Node/PostgreSQL with the supplied Better Auth owner and no credit enforcement");
  await service.close(); service = undefined;

  service = await createProductionTestRuntime({ runtime: { mode: "hosted" } });
  const provision = { ...owner, testingCredits: 4321 };
  const created = await service.fetch("/api/operator/accounts", { method: "POST", headers: { Authorization: `Bearer ${service.token}`, "Content-Type": "application/json" }, body: JSON.stringify(provision) });
  assert.equal(created.status, 201);
  await service.restart();
  const repeated = await service.fetch("/api/operator/accounts", { method: "POST", headers: { Authorization: `Bearer ${service.token}`, "Content-Type": "application/json" }, body: JSON.stringify(provision) });
  assert.equal(repeated.status, 409);
  client = new NativeClient(service.baseUrl);
  await client.login(configured.ownerEmail, storedPassword);
  const hostedUsage = JSON.parse((await client.request("/api/accounts/independent/usage", { expected: 200 })).text) as { creditEnforced: boolean; balance: number; grants: unknown[] };
  assert.equal(hostedUsage.creditEnforced, true); assert.equal(hostedUsage.balance, 4321); assert.equal(hostedUsage.grants.length, 1, "Hosted restart/repeated provisioning must not duplicate operator testing grants");
  console.log("PASS hosted Node/PostgreSQL restart retains exactly one auditable testing grant without conflating self-host mode");
} finally {
  await service?.close();
  await rm(scratch, { recursive: true, force: true });
}
