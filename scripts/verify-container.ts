import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { mutablePath } from "./selfhost.mjs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";
import type { Check, ProbeResult } from "../src/types.ts";

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureParent = await mutablePath(path.join(root, "selfhost"), "state");
await mkdir(fixtureParent, { recursive: true, mode: 0o700 });
const scratch = await mkdtemp(path.join(fixtureParent, "container-verification-"));
const scope = `tomato-verification-${process.pid}-${randomBytes(3).toString("hex")}`;
const network = `${scope}-network`, fixture = `${scope}-fixture`, transport = `${scope}-transport`;
const image = process.argv[2] ?? `${scope}-image`;
const ownedImage = process.argv[2] === undefined;
const proberToken = randomBytes(32).toString("hex");
const hostname = "fixture.example.com", wrongHostname = "wrong.fixture.example.com";
// Physically assigned addresses on an isolated Docker network, not a production
// adapter: the unchanged image performs real OS resolution and pinned sockets.
const fixtureAddress = "93.184.215.14";
let passed = 0;
let networkCreated = false, fixtureCreated = false, transportCreated = false, imageCreated = false;
async function command(binary: string, args: string[]): Promise<string> {
  try { return (await run(binary, args, { maxBuffer: 2 * 1024 * 1024, timeout: 120000 })).stdout; }
  catch (error) {
    const diagnostic = error && typeof error === "object" && "stderr" in error && typeof error.stderr === "string" ? error.stderr.split("\n", 1)[0]!.slice(0, 400) : "no safe command diagnostic";
    throw new Error(`Owned ${binary} verification command failed: ${diagnostic}`);
  }
}
function proof(condition: unknown, message: string): asserts condition { if (!condition) throw new Error(message); }
async function scenario(name: string, action: () => Promise<void>): Promise<void> { await action(); passed++; console.log(`PASS ${name}`); }
interface ImageRequest { path: string; method?: string; body?: string; authorization?: string | null }
interface ImageResponse { status: number; body: string }
async function imageRequests(requests: ImageRequest[]): Promise<ImageResponse[]> {
  const program = "import {readFile} from 'node:fs/promises'; const input=JSON.parse(process.argv[1]); const bearer='Bearer '+(await readFile('/fixtures/prober-token','utf8')).trim(); const replies=await Promise.all(input.map(async request=>{const response=await fetch('http://93.184.215.13:8080'+request.path,{method:request.method??'GET',headers:{...(request.authorization===null?{}:{Authorization:request.authorization??bearer}),...(request.body===undefined?{}:{'Content-Type':'application/json'})},...(request.body===undefined?{}:{body:request.body}),signal:AbortSignal.timeout(10000)});return {status:response.status,body:await response.text()};}));console.log(JSON.stringify(replies));";
  return JSON.parse(await command("docker", ["exec", fixture, "node", "--input-type=module", "-e", program, JSON.stringify(requests)])) as ImageResponse[];
}
async function rpc(check: Exclude<Check, { kind: "dns" | "heartbeat" }>, timeoutMs = 5000): Promise<ProbeResult> {
  const [response] = await imageRequests([{ path: "/execute", method: "POST", body: JSON.stringify({ kind: "probe", check, timeoutMs }) }]);
  proof(response && response.status === 200, "Physical image RPC was rejected."); return JSON.parse(response.body) as ProbeResult;
}
async function ready(): Promise<void> {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) { try { const [response] = await imageRequests([{ path: "/ready" }]); if (response?.status === 200 && JSON.parse(response.body).ready === true) return; } catch {} await sleep(100); }
  const containers = JSON.parse(await command("docker", ["inspect", fixture, transport])) as { Name: string; State: { Status: string; ExitCode: number; OOMKilled: boolean; Error: string } }[];
  const diagnostics = containers.map(container => ({ name: container.Name, status: container.State.Status, exitCode: container.State.ExitCode, oomKilled: container.State.OOMKilled, error: container.State.Error.slice(0, 200) }));
  const logs = await Promise.all([fixture, transport].map(async name => { const captured = await run("docker", ["logs", name], { maxBuffer: 8192, timeout: 5000 }); return `${captured.stdout}\n${captured.stderr}`.slice(0, 1000); }));
  throw new Error(`Owned physical image startup failed: ${JSON.stringify({ diagnostics, logs })}`);
}
try {
  if (ownedImage) { await command("docker", ["build", "-f", path.join(root, "Dockerfile.prober"), "-t", image, root]); imageCreated = true; }
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Tomato Docker Verification CA", "-keyout", path.join(scratch, "ca.key"), "-out", path.join(scratch, "ca.pem")]);
  await command("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", `/CN=${hostname}`, "-keyout", path.join(scratch, "server.key"), "-out", path.join(scratch, "server.csr")]);
  await writeFile(path.join(scratch, "server.ext"), `subjectAltName=DNS:${hostname},IP:${fixtureAddress}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n`);
  await command("openssl", ["x509", "-req", "-in", path.join(scratch, "server.csr"), "-CA", path.join(scratch, "ca.pem"), "-CAkey", path.join(scratch, "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", path.join(scratch, "server.ext"), "-out", path.join(scratch, "server.pem")]);
  await writeFile(path.join(scratch, "resolv.conf"), `nameserver ${fixtureAddress}\noptions timeout:1 attempts:1\n`);
  await writeFile(path.join(scratch, "prober-token"), proberToken, { mode: 0o600 });
  const inspected = JSON.parse(await command("docker", ["image", "inspect", image])) as { Architecture: string; Config: { Env: string[]; User: string; Cmd: string[] } }[];
  const daemonArchitecture = (await command("docker", ["info", "--format", "{{.Architecture}}"])).trim();
  const nativeArchitecture = ["aarch64", "arm64"].includes(daemonArchitecture) ? "arm64" : ["x86_64", "amd64"].includes(daemonArchitecture) ? "amd64" : undefined;
  proof(nativeArchitecture && inspected[0]?.Architecture === nativeArchitecture, "Production prober image must match the Docker daemon's native Linux arm64 or amd64 platform.");
  proof(!inspected[0].Config.Env.some(value => /^(?:ENGINE_TOKEN|AUTH_PEPPER|FIXTURE_TOKEN|WEBHOOK_SECRET|NODE_EXTRA_CA_CERTS|TOMATO_TRANSPORT_TEST)=/.test(value)), "Actual image contains private or test-only environment configuration.");
  await command("docker", ["network", "create", "--internal", "--subnet", "93.184.215.0/28", network]); networkCreated = true;
  await command("docker", ["run", "-d", "--name", fixture, "--network", network, "--ip", fixtureAddress, "--user", "0", "--memory", "512m", "--pids-limit", "64", "--volume", `${scratch}:/fixtures:ro`, "--volume", `${path.join(root, "scripts", "container-fixtures.mjs")}:/fixture-server.mjs:ro`, "--entrypoint", "node", image, "/fixture-server.mjs"]); fixtureCreated = true;
  await command("docker", ["run", "-d", "--name", transport, "--network", network, "--ip", "93.184.215.13", "--cpus", "0.0625", "--memory", "256m", "--pids-limit", "64", "--read-only", "--tmpfs", "/run/tomato-secrets:rw,noexec,nosuid,size=1m", "--volume", `${path.join(scratch, "resolv.conf")}:/etc/resolv.conf:ro`, "--volume", `${path.join(scratch, "ca.pem")}:/fixtures/ca.pem:ro`, "--volume", `${path.join(scratch, "prober-token")}:/run/secrets/prober_token:ro`, "--env", "TOMATO_PROBER_TOKEN_FILE=/run/secrets/prober_token", "--env", "NODE_EXTRA_CA_CERTS=/fixtures/ca.pem", image]); transportCreated = true;
  await ready();
  await scenario("actual production image runs non-root with isolated private RPC and no baked secrets", async () => {
    const processEvidence = JSON.parse(await command("docker", ["exec", transport, "node", "--input-type=module", "-e", "import {readFile} from 'node:fs/promises';const status=await readFile('/proc/1/status','utf8');const command=await readFile('/proc/1/cmdline','utf8');console.log(JSON.stringify({uid:status.match(/^Uid:\\s+(.+)$/m)?.[1].trim().split(/\\s+/).map(Number),command,version:process.versions.node,architecture:process.arch}));"])) as { uid: number[]; command: string; version: string; architecture: string };
    proof(processEvidence.uid.length === 4 && processEvidence.uid.every(uid => uid === 1000), "Actual PID1 did not drop every UID to the node user.");
    proof(processEvidence.command.split("\0")[0] === "node" && Number(processEvidence.version.split(".")[0]) === 24, "Actual persistent PID1 is not the Node24 prober.");
    proof(processEvidence.architecture === (nativeArchitecture === "arm64" ? "arm64" : "x64"), "Actual runtime is not native to the Docker daemon.");
    const settings = JSON.parse(await command("docker", ["inspect", transport])) as { HostConfig: { NanoCpus: number; Memory: number; PidsLimit: number; PortBindings: Record<string, { HostIp: string }[]> } }[];
    proof(settings[0]?.HostConfig.NanoCpus === 62500000 && settings[0].HostConfig.Memory === 268435456 && settings[0].HostConfig.PidsLimit === 64, "Actual local image was not constrained to lite-equivalent CPU, memory and process bounds.");
    proof(Object.keys(settings[0].HostConfig.PortBindings ?? {}).length === 0, "Owned private image unexpectedly published host ports.");
    const [response, proxy, oversized] = await imageRequests([{ path: "/execute" }, { path: "/proxy?url=http://127.0.0.1/", method: "POST" }, { path: "/execute", method: "POST", body: "x".repeat(65537) }]);
    proof(response?.status === 404 && proxy?.status === 404 && oversized?.status === 413, "Actual private image method, path or byte boundaries failed.");
    const unauthenticated = await imageRequests([{ path: "/ready", authorization: null }, { path: "/execute", method: "POST", body: "{}", authorization: "Bearer invalid" }]);
    proof(unauthenticated.every(response => response.status === 401 && JSON.parse(response.body).code === "unauthorized"), "Actual private image accepted a missing or wrong bearer token.");
  });
  await scenario("unchanged production image denies private, mapped and metadata addresses before any target contact", async () => {
    for (const url of ["http://127.0.0.1/", "http://169.254.169.254/", "http://[::ffff:127.0.0.1]/"]) {
      const result = await rpc({ kind: "http", url }); proof(result.outcome === "unknown" && result.code === "blocked_destination", "Production image did not reject a disallowed target as free UNKNOWN.");
    }
  });
  await scenario("production image rejects request-supplied loopback adapters and unrelated secrets", async () => {
    for (const extra of [{ allowLoopback: true }, { test: { allowedPorts: [8081] } }, { DATABASE_URL: "postgres://synthetic" }, { AUTH_SECRET: "synthetic" }]) {
      const [response] = await imageRequests([{ path: "/execute", method: "POST", body: JSON.stringify({ kind: "probe", check: { kind: "http", url: "http://127.0.0.1:8081/health" }, timeoutMs: 1000, ...extra }) }]);
      proof(response?.status === 200 && JSON.parse(response.body).outcome === "unknown" && JSON.parse(response.body).code === "invalid_request", "Production image accepted an extra RPC secret or test adapter.");
    }
  });
  await scenario("actual production startup fails closed on test flags and unrelated secret configuration", async () => {
    for (const forbidden of ["TOMATO_TRANSPORT_TEST=1", "TEST_MODE=true", "DATABASE_URL=postgresql://synthetic", "AUTH_SECRET=synthetic", "TOMATO_DB_PASSWORD_FILE=/no-unrelated-path-read"]) {
      const args = ["run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/run/tomato-secrets:rw,noexec,nosuid,size=1m", "--volume", `${path.join(scratch, "prober-token")}:/run/secrets/prober_token:ro`, "--env", "TOMATO_PROBER_TOKEN_FILE=/run/secrets/prober_token", "--env", forbidden, image];
      let rejected = false;
      try { await run("docker", args, { timeout: 10000, maxBuffer: 8192 }); }
      catch (error) { rejected = error !== null && typeof error === "object" && "code" in error && error.code === 1 && "stderr" in error && typeof error.stderr === "string" && error.stderr.includes("prober_forbidden_configuration"); }
      proof(rejected, "Actual production startup accepted unrelated secrets/test flags or failed for an unrelated reason.");
    }
  });
  await scenario("actual HTTP, WebSocket and TCP cross real production pins to controlled physical endpoints", async () => {
    for (const check of [
      { kind: "http", url: `http://${hostname}:8081/health`, contains: "TOMATOOK", maxBodyBytes: 8 },
      { kind: "websocket", url: `ws://${hostname}:8081/ws`, send: "PING", expect: "TOMATOOK", maxMessageBytes: 8 },
      { kind: "tcp", hostname, port: 9001, send: "PING", expect: "TOMATOOK", maxResponseBytes: 8 },
    ] satisfies Exclude<Check, { kind: "dns" | "heartbeat" }>[]) proof((await rpc(check)).outcome === "success", "Actual image did not reach its controlled physical endpoint.");
  });
  await scenario("actual HTTPS and TLS preserve original Host/SNI and reject a trusted wrong identity", async () => {
    const httpsResult = await rpc({ kind: "http", url: `https://${hostname}:8443/health`, contains: "TOMATOOK" });
    proof(httpsResult.outcome === "success", `Actual image HTTPS identity failed: ${httpsResult.outcome}/${httpsResult.code}; ${httpsResult.latencyMs}ms.`);
    const tlsResult = await rpc({ kind: "tls", hostname, port: 9443, send: "PING", expect: "TOMATOOK", maxResponseBytes: 8 });
    proof(tlsResult.outcome === "success", `Actual image TLS identity failed: ${tlsResult.outcome}/${tlsResult.code}; ${tlsResult.latencyMs}ms.`);
    const wrong = await rpc({ kind: "tls", hostname: wrongHostname, port: 9443, send: "PING", expect: "TOMATOOK" }); proof(wrong.outcome === "failure" && wrong.code === "tls_validation", "Actual production image did not reject the original hostname mismatch.");
    await rpc({ kind: "http", url: `http://${hostname}:8081/observations`, maxBodyBytes: 4096 });
    // The prober intentionally never returns arbitrary response bodies. Query
    // only the isolated fixture directly from its own container for metadata.
    const observed = JSON.parse(await command("docker", ["exec", fixture, "node", "--input-type=module", "-e", "console.log(JSON.stringify(await (await fetch('http://127.0.0.1:8081/observations')).json()))"])) as { dnsQueries: { name: string; type: number }[]; httpHosts: string[]; tlsServerNames: string[]; websocketHosts: string[]; tcpRequests: number; tlsRequests: number };
    proof(observed.dnsQueries.some(query => query.name === hostname && query.type === 1) && observed.httpHosts.includes(`${hostname}:8443`) && observed.tlsServerNames.includes(hostname) && observed.websocketHosts.includes(`${hostname}:8081`) && observed.tcpRequests > 0 && observed.tlsRequests > 0, "Controlled physical fixture did not observe real DNS and original transport identities.");
  });
  await scenario("actual image redirect revalidation never connects a private next hop", async () => {
    const result = await rpc({ kind: "http", url: `http://${hostname}:8081/redirect-private` }); proof(result.outcome === "failure" && result.code === "blocked_destination", "Actual image did not fail closed after its public redirect.");
  });
  await scenario("actual image rejects fifth concurrent RPC under fixed lite resource bounds", async () => {
    const replies = await imageRequests(Array.from({ length: 5 }, () => ({ path: "/execute", method: "POST", body: JSON.stringify({ kind: "probe", check: { kind: "http", url: `http://${hostname}:8081/slow`, contains: "TOMATOOK" }, timeoutMs: 5000 }) })));
    proof(replies.filter(response => response.status === 429).length === 1 && replies.filter(response => response.status === 200).length === 4, "Actual private image admission did not enforce exactly four concurrent requests.");
    for (const response of replies) { const data = JSON.parse(response.body) as { outcome?: string }; if (response.status === 200) proof(data.outcome === "success", "Accepted bounded image request failed."); }
  });
  await scenario("actual target deadline is bounded and frees private image admission", async () => {
    const started = Date.now();
    const result = await rpc({ kind: "http", url: `http://${hostname}:8081/slow` }, 100);
    proof(result.outcome === "failure" && result.code === "timeout" && result.latencyMs >= 100 && Date.now() - started < 3000, "Actual target timeout escaped its bound or classification.");
    proof((await rpc({ kind: "http", url: `http://${hostname}:8081/health` })).outcome === "success", "Private image admission did not recover after timeout.");
  });
  await scenario("actual incomplete authenticated upload expires and frees a private image slot", async () => {
    const program = "import {request} from 'node:http';import {readFile} from 'node:fs/promises';const token=(await readFile('/fixtures/prober-token','utf8')).trim();const started=Date.now();const completed=Promise.withResolvers();const req=request({hostname:'93.184.215.13',port:8080,path:'/execute',method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'}},response=>{response.resume();response.on('end',completed.resolve);});const timer=setTimeout(()=>{req.destroy();completed.reject(new Error('input_deadline_exceeded'));},6500);req.once('error',completed.resolve);req.write('{');try{await completed.promise;}finally{clearTimeout(timer);req.destroy();}console.log(JSON.stringify({elapsed:Date.now()-started}));";
    const measured = JSON.parse(await command("docker", ["exec", fixture, "node", "--input-type=module", "-e", program])) as { elapsed: number };
    proof(measured.elapsed >= 4000 && measured.elapsed < 6500, "Actual image input deadline was not exercised.");
    proof((await rpc({ kind: "http", url: `http://${hostname}:8081/health` })).outcome === "success", "Private image upload admission was not released.");
  });
  const metrics = (await command("docker", ["stats", "--no-stream", "--format", "{{json .}}", transport])).trim();
  const measured = JSON.parse(metrics) as { MemUsage: string; CPUPerc: string; PIDs: string };
  await scenario("actual Linux PID1 exits gracefully with code zero after SIGTERM", async () => {
    await command("docker", ["kill", "--signal", "SIGTERM", transport]);
    const { stdout } = await run("docker", ["wait", transport], { maxBuffer: 4096, timeout: 5000 });
    proof(stdout.trim() === "0", "Actual image did not drain and exit cleanly after SIGTERM.");
  });
  console.log(`PASS physical image verification: ${passed} scenarios; observed memory ${measured.MemUsage}, CPU snapshot ${measured.CPUPerc}, processes ${measured.PIDs}; 1/16CPU+256MiB configured; isolated local image measurement, not production capacity claim.`);
} finally {
  const cleanupFailures: string[] = [];
  if (transportCreated) { try { await command("docker", ["rm", "-f", transport]); } catch { cleanupFailures.push("transport"); } }
  if (fixtureCreated) { try { await command("docker", ["rm", "-f", fixture]); } catch { cleanupFailures.push("fixture"); } }
  if (networkCreated) { try { await command("docker", ["network", "rm", network]); } catch { cleanupFailures.push("network"); } }
  if (imageCreated) { try { await command("docker", ["image", "rm", image]); } catch { cleanupFailures.push("image"); } }
  await rm(scratch, { recursive: true, force: true });
  if (cleanupFailures.length) throw new Error(`Owned Docker cleanup failed for ${cleanupFailures.join(", ")}; no unrelated resources were targeted.`);
}
