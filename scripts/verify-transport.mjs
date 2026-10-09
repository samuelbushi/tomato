import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib';
import { createSocket } from 'node:dgram';
import * as dnsPacket from 'dns-packet';
import { createServer as createTcpServer } from 'node:net';
import { createServer as createTlsServer } from 'node:tls';
import { createHmac, randomBytes, X509Certificate } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { runProbe, dispatchWebhook } from '../src/probes.ts';
import { monitorInput, monitorView } from '../src/validation.ts';
import { createProber } from '../src/egress.ts';
import { createProductionTestRuntime } from './production-test-runtime.ts';
import { dispatchOutbox } from '../src/worker.ts';
import { setTimeout as sleep } from 'node:timers/promises';

// Every result comes from a separately running Node prober over authenticated
// private HTTP. Only owned DNS configuration and pin-to-fixture resolution vary;
// all HTTP, TLS, WS and banner traffic uses ordinary Node sockets.
assert(Number(process.versions.node.split('.')[0]) >= 24, 'Node 24+ is required');
const MAX_REQUEST_BYTES = 65_536;
const token = randomBytes(32).toString('hex');
const run = promisify(execFile);
const PUBLIC = '93.184.216.34';
const hits = [];
let scratch, leafEvidence, longLeafEvidence, plain, secure, longSecure, ws, wss;
let privateChild, untrustedChild, productionChild, untrustedPort, productionPort;
let dns, dnsPort, dnsResolve = async () => [PUBLIC];
const dnsQueries = [];
let httpPort, httpsPort, longHttpsPort, privatePort;
let tcp, tls, tcpPort, tlsPort;
const socketHits = [];
const sockets = new Set();
function listen(server) {
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}
async function execute(input, extra = {}) {
  dnsResolve = extra.resolve ?? (async () => [PUBLIC]);
  const port = Object.hasOwn(extra, 'ca') && extra.ca === undefined ? untrustedPort : privatePort;
  const response = await fetch(`http://127.0.0.1:${port}/execute`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(input), signal: AbortSignal.timeout(35_000),
  });
  assert.equal(response.status, 200);
  return response.json();
}
function probe(check, extra = {}, timeoutMs = 1000) { return execute({ kind: 'probe', check, timeoutMs }, extra); }
async function child(trusted, production = false) {
  const bootstrap = `
    import { createEgressServer } from ${JSON.stringify(new URL('../container/server.mjs', import.meta.url).href)};
    import { readFile } from 'node:fs/promises';
    import { Resolver } from 'node:dns/promises';
    const config = JSON.parse(process.argv[1]);
    const resolve = async (hostname, signal) => {
      const resolver = new Resolver({timeout:1000,tries:1});
      resolver.setServers(['127.0.0.1:' + config.dnsPort]);
      const abort = () => resolver.cancel();
      signal.addEventListener('abort', abort, {once:true});
      try {
        const replies = await Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]);
        const addresses = [];
        for (const reply of replies) {
          if (reply.status === 'fulfilled') addresses.push(...reply.value);
          else if (!['ENODATA','ENOTFOUND'].includes(reply.reason?.code)) throw reply.reason;
        }
        return addresses;
      } finally { signal.removeEventListener('abort', abort); resolver.cancel(); }
    };
    const token = (await readFile(config.tokenFile,'utf8')).trim();
    const test = config.production ? undefined : {
      resolve, allowedPorts:config.ports,
      connectAddress: address => address === ${JSON.stringify(PUBLIC)} ? '127.0.0.1' : address,
      ...(config.trusted ? {ca:await readFile(config.caFile)} : {})
    };
    const server = createEgressServer({token,test});
    process.once('SIGTERM', () => {server.close(() => process.exit(0));server.closeAllConnections();});
    server.listen(0,'127.0.0.1',() => process.stdout.write(JSON.stringify({port:server.address().port})+'\\n'));
  `;
  const processChild = spawn(process.execPath, ['--input-type=module', '-e', bootstrap, JSON.stringify({
    dnsPort, tokenFile: join(scratch, 'prober-token'), caFile: join(scratch, 'ca.pem'), trusted, production,
    ports: [httpPort, httpsPort, longHttpsPort, tcpPort, tlsPort],
  })], { env: { PATH: process.env.PATH, NODE_ENV: production ? 'production' : 'test', ...(production ? {} : { TOMATO_TRANSPORT_TEST: '1' }) }, stdio: ['ignore', 'pipe', 'pipe'] });
  let diagnostics = '';
  processChild.stderr.on('data', chunk => { diagnostics = (diagnostics + chunk).slice(-2048); });
  const port = await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => { processChild.kill(); reject(new Error(`Child startup deadline: ${diagnostics}`)); }, 10_000);
    processChild.once('exit', code => { clearTimeout(deadline); reject(new Error(`Child exited ${code}: ${diagnostics}`)); });
    processChild.stdout.once('data', chunk => { clearTimeout(deadline); resolve(JSON.parse(chunk.toString()).port); });
  });
  assert.equal((await fetch(`http://127.0.0.1:${port}/ready`, { headers: { Authorization: `Bearer ${token}` } })).status, 200);
  return { process: processChild, port };
}
async function stopChild(owned) {
  if (!owned || owned.process.exitCode !== null) return;
  const exit = once(owned.process, 'exit');
  owned.process.kill('SIGTERM');
  const watchdog = setTimeout(() => owned.process.kill('SIGKILL'), 5000);
  const [code] = await exit;
  clearTimeout(watchdog);
  assert.equal(code, 0, 'Owned prober must shut down cleanly');
}
function httpCheck(path, extra = {}) { return { kind: 'http', url: `http://fixture.example.com:${httpPort}${path}`, ...extra }; }
function httpsCheck(path, extra = {}) { return { kind: 'http', url: `https://fixture.example.com:${httpsPort}${path}`, ...extra }; }
function resultIs(result, outcome, code) { assert.equal(result.outcome, outcome); assert.equal(result.code, code); }
function handler(request, response) {
  const path = new URL(request.url, 'http://fixture').pathname;
  const hit = { path, host: request.headers.host, headers: request.headers, sni: request.socket.servername, method: request.method, body: '' };
  hits.push(hit);
  request.on('data', chunk => { hit.body += chunk.toString(); });
  request.on('end', () => {
    if (path === '/stall') return;
    if (path === '/same') { response.writeHead(302, { location: '/ok' }); response.end(); return; }
    if (path === '/cross') { response.writeHead(302, { location: `http://second.example.com:${httpPort}/ok` }); response.end(); return; }
    if (path === '/secure-long') { response.writeHead(302, { location: `https://second.example.com:${longHttpsPort}/ok` }); response.end(); return; }
    if (path === '/secure-short') { response.writeHead(302, { location: `https://fixture.example.com:${httpsPort}/ok` }); response.end(); return; }
    if (path === '/loop') { response.writeHead(302, { location: '/loop' }); response.end(); return; }
    if (path === '/private') { response.writeHead(302, { location: 'http://169.254.169.254/latest' }); response.end(); return; }
    if (path === '/downgrade') { response.writeHead(302, { location: `http://fixture.example.com:${httpPort}/ok` }); response.end(); return; }
    if (path === '/credential') { response.writeHead(302, { location: `http://user:secret@fixture.example.com:${httpPort}/ok` }); response.end(); return; }
    if (path === '/large') { response.end('x'.repeat(4096)); return; }
    if (path === '/chunked') { response.write('x'.repeat(32)); response.end('x'.repeat(128)); return; }
    if (path === '/compressed') { response.writeHead(200, { 'content-encoding': 'gzip' }); response.end(gzipSync('x'.repeat(4096))); return; }
    if (path === '/deflate') { response.writeHead(200, { 'content-encoding': 'deflate' }); response.end(deflateSync('x'.repeat(4096))); return; }
    if (path === '/brotli') { response.writeHead(200, { 'content-encoding': 'br' }); response.end(brotliCompressSync('x'.repeat(4096))); return; }
    if (path === '/gzip-ok') { response.writeHead(200, { 'content-encoding': 'gzip' }); response.end(gzipSync('TOMATO_OK')); return; }
    if (path === '/webhook-redirect') { response.writeHead(307, { location: '/webhook' }); response.end('secret-response'); return; }
    if (path === '/webhook') { response.writeHead(202); response.end('synthetic-private-response'.repeat(20_000)); return; }
    if (path === '/status') { response.writeHead(418); response.end('TOMATO_OK'); return; }
    response.end('TOMATO_OK');
  });
}
function socketHandler(socket) {
  socket.on('error', () => {});
  socketHits.push({ sni: socket.servername });
  socket.on('data', data => {
    const command = data.toString();
    if (command === 'STALL') return;
    if (command === 'LARGE') { socket.end('x'.repeat(100)); return; }
    if (command === 'WRONG') { socket.end('WRONG'); return; }
    if (command === 'SHORT') { socket.end('TOMATO_'); return; }
    socket.write('TOMATO_');
    setImmediate(() => { if (!socket.destroyed) socket.end('OKsuffix'); });
  });
}
before(async () => {
  scratch = await mkdtemp(join(tmpdir(), 'tomato-transport-'));
  const path = name => join(scratch, name);
  await writeFile(path('server.ext'), `subjectAltName=DNS:fixture.example.com,DNS:second.example.com,IP:${PUBLIC}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n`);
  await run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=Tomato Transport Test CA', '-keyout', path('ca.key'), '-out', path('ca.pem')]);
  await run('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=fixture.example.com', '-keyout', path('server.key'), '-out', path('server.csr')]);
  await run('openssl', ['x509', '-req', '-in', path('server.csr'), '-CA', path('ca.pem'), '-CAkey', path('ca.key'), '-CAcreateserial', '-days', '2', '-extfile', path('server.ext'), '-out', path('server.pem')]);
  await run('openssl', ['x509', '-req', '-in', path('server.csr'), '-CA', path('ca.pem'), '-CAkey', path('ca.key'), '-CAcreateserial', '-days', '20', '-extfile', path('server.ext'), '-out', path('long-server.pem')]);
  const leaf = new X509Certificate(await readFile(path('server.pem')));
  leafEvidence = { validFrom: Date.parse(leaf.validFrom), validTo: Date.parse(leaf.validTo) };
  const longLeaf = new X509Certificate(await readFile(path('long-server.pem')));
  longLeafEvidence = { validFrom: Date.parse(longLeaf.validFrom), validTo: Date.parse(longLeaf.validTo) };
  plain = createHttpServer(handler);
  secure = createHttpsServer({ key: await readFile(path('server.key')), cert: await readFile(path('server.pem')) }, handler);
  httpPort = await listen(plain); httpsPort = await listen(secure);
  longSecure = createHttpsServer({ key: await readFile(path('server.key')), cert: await readFile(path('long-server.pem')) }, handler);
  longHttpsPort = await listen(longSecure);
  tcp = createTcpServer(socketHandler);
  tls = createTlsServer({ key: await readFile(path('server.key')), cert: await readFile(path('server.pem')) }, socketHandler);
  tcpPort = await listen(tcp); tlsPort = await listen(tls);
  ws = new WebSocketServer({ server: plain, perMessageDeflate: false });
  wss = new WebSocketServer({ server: secure, perMessageDeflate: false });
  for (const server of [ws, wss]) server.on('connection', (socket, request) => {
    hits.push({ path: request.url, host: request.headers.host, headers: request.headers, sni: request.socket.servername });
    socket.on('error', () => {});
    socket.on('message', data => {
      if (request.url === '/ws-stall') return;
      socket.send(request.url === '/ws-large' ? 'x'.repeat(100) : request.url === '/ws-wrong' ? 'wrong' : data);
    });
  });
  await writeFile(path('prober-token'), token, { mode: 0o600 });
  dns = createSocket('udp4');
  dns.on('message', async (message, remote) => {
    const query = dnsPacket.decode(message), question = query.questions[0];
    dnsQueries.push({ name: question.name, type: question.type });
    const addresses = await dnsResolve(question.name, question.type);
    if (addresses === null) return;
    const answers = addresses.filter(address => question.type === (address.includes(':') ? 'AAAA' : 'A')).map(address => ({
      name: question.name, type: question.type, class: 'IN', ttl: 0, data: address,
    }));
    const answer = dnsPacket.encode({ type: 'response', id: query.id, flags: dnsPacket.AUTHORITATIVE_ANSWER | dnsPacket.RECURSION_AVAILABLE, questions: query.questions, answers });
    dns.send(answer, remote.port, remote.address);
  });
  await new Promise(resolve => dns.bind(0, '127.0.0.1', resolve));
  dnsPort = dns.address().port;
  privateChild = await child(true); privatePort = privateChild.port;
  untrustedChild = await child(false); untrustedPort = untrustedChild.port;
  productionChild = await child(false, true); productionPort = productionChild.port;
});
after(async () => {
  for (const server of [ws, wss].filter(Boolean)) for (const socket of server.clients) socket.terminate();
  for (const socket of sockets) socket.destroy();
  await Promise.all([privateChild, untrustedChild, productionChild].map(stopChild));
  await Promise.all([plain, secure, longSecure, tcp, tls].filter(Boolean).map(server => new Promise(resolve => server.close(resolve))));
  if (dns) await new Promise(resolve => dns.close(resolve));
  if (scratch) await rm(scratch, { recursive: true, force: true });
});

test('real DNS rebinding after A/AAAA validation never causes a second socket resolution', async () => {
  let aQueries = 0;
  const beforeQueries = dnsQueries.length;
  const resolve = async (_hostname, type) => type === 'AAAA' ? [] : [++aQueries === 1 ? PUBLIC : '127.0.0.1'];
  resultIs(await probe(httpCheck('/ok', { contains: 'TOMATO_OK' }), { resolve }), 'success', 'http_ok');
  assert.equal(aQueries, 1);
  assert.deepEqual(dnsQueries.slice(beforeQueries).map(query => query.type).sort(), ['A', 'AAAA']);
  assert.equal(hits.at(-1).host, `fixture.example.com:${httpPort}`);
  const beforeHits = hits.length;
  resultIs(await probe(httpCheck('/ok'), { resolve }), 'unknown', 'blocked_destination');
  assert.equal(aQueries, 2); assert.equal(hits.length, beforeHits);
});
test('each redirect revalidates DNS and a changed private answer never connects', async () => {
  let count = 0;
  const beforeHits = hits.length;
  const result = await probe(httpCheck('/same'), { resolve: async (_hostname, type) => type === 'AAAA' ? [] : ++count === 1 ? [PUBLIC] : ['10.0.0.1'] });
  resultIs(result, 'failure', 'blocked_destination'); assert.equal(count, 2); assert.equal(hits.length, beforeHits + 1);
});
test('real TLS preserves Host and SNI while validating the original identity', async () => {
  resultIs(await probe(httpsCheck('/ok')), 'success', 'http_ok');
  assert.equal(hits.at(-1).host, `fixture.example.com:${httpsPort}`); assert.equal(hits.at(-1).sni, 'fixture.example.com');
  resultIs(await probe({ ...httpsCheck('/ok'), url: `https://wrong.example.com:${httpsPort}/ok` }), 'failure', 'tls_validation');
  resultIs(await probe(httpsCheck('/ok'), { ca: undefined }), 'failure', 'tls_validation');
});
test('HTTPS redirects retain the earliest-expiring authorized leaf in either direction', async () => {
  assert(leafEvidence.validTo < longLeafEvidence.validTo);
  const longCheck = path => ({ kind: 'http', url: `https://second.example.com:${longHttpsPort}${path}` });
  const directLong = await probe(longCheck('/ok'));
  resultIs(directLong, 'success', 'http_ok');
  assert.deepEqual(directLong.evidence.certificate, longLeafEvidence);
  assert((longLeafEvidence.validTo - directLong.finishedAt) / 86_400_000 > 14);
  const directShort = await probe(httpsCheck('/ok'));
  resultIs(directShort, 'success', 'http_ok');
  assert.deepEqual(directShort.evidence.certificate, leafEvidence);
  for (const check of [httpsCheck('/secure-long'), longCheck('/secure-short')]) {
    const result = await probe(check);
    resultIs(result, 'success', 'http_ok');
    assert.deepEqual(result.evidence.certificate, leafEvidence);
    assert((result.evidence.certificate.validTo - result.finishedAt) / 86_400_000 < 14);
  }
});
test('canonical export/import preserves nondefault and disabled certificate warnings through trusted TLS and signed delivery', async () => {
  const runtime = await createProductionTestRuntime({ background: false });
  const secret = 'controlled-certificate-policy-signing-secret';
  const webhook = { url: `https://fixture.example.com:${httpsPort}/webhook`, secret };
  try {
    runtime.env.PROBER = createProber(`http://127.0.0.1:${privatePort}/execute`, token);
    dnsResolve = async () => [PUBLIC];
    async function account(name, path, method = 'GET', value) {
      const response = await runtime.internalFetch(name, path, { method, headers: { 'Content-Type': 'application/json' }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
      assert(response.ok, `${path}: ${response.status}`);
      return response.json();
    }
    const policies = [
      { id: 'nondefault', certificateExpiryDays: 45, check: { kind: 'http', url: `https://second.example.com:${longHttpsPort}/ok` } },
      { id: 'disabled', certificateExpiryDays: 0, check: httpsCheck('/ok') },
    ];
    for (const policy of policies) await account('original', '/monitors', 'POST', { ...policy, paused: true, webhook, intervalMs: 60000, timeoutMs: 1000, executionWindowMs: 10000 });
    const exported = await account('original', '/export');
    assert.deepEqual(exported.monitors.map(monitor => [monitor.id, monitor.certificateExpiryDays]).sort(), [['disabled', 0], ['nondefault', 45]]);
    assert(!JSON.stringify(exported).includes(secret));
    await account('imported', '/monitors/import', 'POST', { ...exported, monitors: exported.monitors.map(monitor => ({ ...monitor, webhookMode: 'replace', webhook })) });
    const deliveredIds = [];
    for (const name of ['original', 'imported']) {
      await account(name, '/credits/initial', 'PUT', { credits: 4 });
      for (const policy of policies) {
        await account(name, `/monitors/${policy.id}/resume`, 'POST', { revision: 1 });
        await account(name, '/tick', 'POST', {});
        const snapshot = await account(name, '/state');
        const job = snapshot.jobs.find(job => job.monitorId === policy.id && job.role === 'primary' && job.status === 'pending'); assert(job);
        const { claim } = await account(name, '/claim', 'POST', { jobId: job.id }); assert(claim);
        const observation = await probe(claim.check); resultIs(observation, 'success', 'http_ok');
        assert.deepEqual(observation.evidence.certificate, policy.id === 'nondefault' ? longLeafEvidence : leafEvidence);
        assert.equal((await account(name, '/complete', 'POST', { jobId: job.id, leaseToken: claim.leaseToken, result: observation })).accepted, true);
      }
    }
    // Delivery claims and real signed HTTPS requests are the production Postgres
    // outbox dispatcher; the fixture validates its bytes independently.
    await dispatchOutbox(runtime.database, runtime.env, 4);
    for (const name of ['original', 'imported']) {
      const deadline = Date.now() + 10000;
      let snapshot;
      do {
        snapshot = await account(name, '/state');
        if (snapshot.notifications.some(delivery => delivery.status === 'delivered')) break;
        assert(Date.now() < deadline, 'Signed certificate warning delivery must complete');
        await dispatchOutbox(runtime.database, runtime.env, 4);
        await sleep(50);
      } while (true);
      assert.equal(snapshot.notifications.length, 1);
      const delivery = snapshot.notifications[0];
      assert.equal(delivery.type, 'certificate'); assert.equal(delivery.monitorId, 'nondefault'); assert.equal(delivery.status, 'delivered');
      const hit = hits.find(hit => hit.path === '/webhook' && hit.headers['idempotency-key'] === delivery.id); assert(hit);
      assert.equal(hit.headers['x-tomato-signature'], createHmac('sha256', secret).update(`${hit.headers['x-tomato-timestamp']}.${hit.body}`).digest('hex'));
      assert.equal(JSON.parse(hit.body).type, 'certificate'); deliveredIds.push(delivery.id);
      const warning = snapshot.monitors.find(monitor => monitor.id === 'nondefault'), disabled = snapshot.monitors.find(monitor => monitor.id === 'disabled');
      assert.equal(warning.certificate.thresholdDays, 45); assert.equal(warning.certificate.status, 'expiring');
      assert.equal(disabled.certificate.thresholdDays, 0); assert.equal(disabled.certificate.status, 'valid');
      assert.equal(snapshot.usage, 2); assert.equal(snapshot.reserved, 0);
      for (const policy of policies) await account(name, `/monitors/${policy.id}/pause`, 'POST', { revision: 2 });
    }
    assert.equal(new Set(deliveredIds).size, 2, 'Original and imported warning deliveries retain separate account identities');
  } finally { await runtime.close(); }
});
test('real DNS preparation timeout is UNKNOWN/free while target timeouts and trusted successes charge exactly once in Postgres', async () => {
  const runtime = await createProductionTestRuntime({ background: false });
  async function account(path, method = 'GET', value) {
    const response = await runtime.internalFetch('budget', path, { method, headers: { 'Content-Type': 'application/json' }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
    assert(response.ok, `${path}: ${response.status}`); return response.json();
  }
  try {
    await account('/credits/initial', 'PUT', { credits: 10 });
    let paid = 0;
    const cases = [
      ['http', httpCheck('/ok')], ['https', httpsCheck('/ok')],
      ['wss', {kind:'websocket',url:`wss://fixture.example.com:${httpsPort}/ws`,send:'TOMATO_OK',expect:'TOMATO_OK'}],
      ['tcp', {kind:'tcp',hostname:'fixture.example.com',port:tcpPort,send:'PING',expect:'TOMATO_OK'}],
      ['tls', {kind:'tls',hostname:'fixture.example.com',port:tlsPort,send:'PING',expect:'TOMATO_OK'}],
    ];
    for (const [id, check] of cases) {
      await account('/monitors', 'POST', {id,check,intervalMs:60000,timeoutMs:100,executionWindowMs:10000});
      await account('/tick', 'POST', {});
      const job = (await account('/state')).jobs.find(job => job.monitorId === id && job.status === 'pending'); assert(job);
      const {claim} = await account('/claim','POST',{jobId:job.id}); assert(claim);
      const beforeHits = hits.length, beforeSockets = socketHits.length;
      const unknown = await probe(claim.check, {resolve:async () => null}, 100);
      resultIs(unknown,'unknown','timeout');
      assert.equal(hits.length,beforeHits); assert.equal(socketHits.length,beforeSockets);
      assert.equal((await account('/complete','POST',{jobId:job.id,leaseToken:claim.leaseToken,result:unknown})).accepted,true);
      let snapshot = await account('/state');
      assert.equal(snapshot.usage,paid); assert.equal(snapshot.balance,10-paid); assert.equal(snapshot.reserved,0);
      assert.equal(snapshot.monitors.find(monitor => monitor.id === id).state,'UNKNOWN');
      assert.equal(snapshot.incidents.length,0); assert.equal(snapshot.notifications.length,0);
      const manual = await account(`/monitors/${id}/check-now`,'POST',{revision:1});
      const genuine = (await account('/claim','POST',{jobId:manual.jobId})).claim; assert(genuine);
      const healthy = await probe(genuine.check, {}, 1000);
      resultIs(healthy,'success',check.kind === 'http' ? 'http_ok' : check.kind === 'websocket' ? 'websocket_ok' : `${check.kind}_ok`);
      assert.equal((await account('/complete','POST',{jobId:manual.jobId,leaseToken:genuine.leaseToken,result:healthy})).accepted,true);
      paid++; snapshot = await account('/state');
      assert.equal(snapshot.usage,paid); assert.equal(snapshot.balance,10-paid); assert.equal(snapshot.reserved,0);
      assert.equal(snapshot.monitors.find(monitor => monitor.id === id).state,'UP');
      await account(`/monitors/${id}/pause`,'POST',{revision:1});
    }
    await account('/monitors','POST',{id:'target-stall',check:httpsCheck('/stall'),intervalMs:60000,timeoutMs:100,executionWindowMs:10000});
    await account('/tick','POST',{});
    const job = (await account('/state')).jobs.find(job => job.monitorId === 'target-stall' && job.status === 'pending'); assert(job);
    const {claim} = await account('/claim','POST',{jobId:job.id}); assert(claim);
    const failure = await probe(claim.check, {}, 100); resultIs(failure,'failure','timeout');
    assert(hits.some(hit => hit.path === '/stall'));
    assert.equal((await account('/complete','POST',{jobId:job.id,leaseToken:claim.leaseToken,result:failure})).accepted,true);
    const snapshot = await account('/state');
    assert.equal(snapshot.usage,paid+1); assert.equal(snapshot.balance,9-paid); assert.equal(snapshot.reserved,0);
    assert.equal(snapshot.monitors.find(monitor => monitor.id === 'target-stall').state,'SUSPECT');
  } finally { await runtime.close(); }
});
test('trusted leaf expiry is independent of HTTP availability and contains only bounded dates', async () => {
  const healthy = await probe(httpsCheck('/ok'));
  resultIs(healthy, 'success', 'http_ok');
  assert.deepEqual(healthy.evidence.certificate, leafEvidence);
  assert(leafEvidence.validFrom <= healthy.finishedAt);
  assert(leafEvidence.validTo > healthy.finishedAt);
  assert((leafEvidence.validTo - healthy.finishedAt) / 86_400_000 < 14);
  const config = monitorInput({ id: 'certificate-fixture', check: httpsCheck('/ok'), intervalMs: 60_000 }, {});
  assert.equal(config.certificateExpiryDays, 14);
  const monitor = {
    ...config, revision: 1, state: 'UP', nextDueAt: healthy.finishedAt + config.intervalMs,
    lastObservedAt: healthy.finishedAt, lastSlotAt: healthy.startedAt,
    candidateJobId: null, candidateSuccess: null, incidentId: null,
    certificate: { ...healthy.evidence.certificate, observedAt: healthy.finishedAt },
  };
  const warning = monitorView(monitor, healthy.finishedAt);
  const valid = monitorView({ ...monitor, certificateExpiryDays: 1 }, healthy.finishedAt);
  assert.equal(warning.certificate.status, 'expiring');
  assert.equal(valid.certificate.status, 'valid');
  assert.equal(warning.certificate.thresholdDays, 14);
  assert.equal(valid.certificate.thresholdDays, 1);
  assert.deepEqual({ validFrom: warning.certificate.validFrom, validTo: warning.certificate.validTo }, leafEvidence);
  assert.equal(warning.certificate.observedAt, healthy.finishedAt);
  assert(warning.certificate.daysRemaining > 1 && warning.certificate.daysRemaining <= 2);
  assert.equal(warning.state, 'UP'); assert.equal(valid.state, 'UP');
  assert.equal(warning.effectiveState, 'UP'); assert.equal(valid.effectiveState, 'UP');
  assert.equal(warning.certificate.stale, false);
  const staleAt = healthy.finishedAt + config.intervalMs + config.executionWindowMs + 1;
  const stale = monitorView(monitor, staleAt);
  assert.equal(stale.certificate.stale, true);
  assert.equal(stale.certificate.status, 'expiring');
  assert.equal(stale.state, 'UP'); assert.equal(stale.effectiveState, 'UNKNOWN');
  assert.equal(monitorView(monitor, leafEvidence.validTo).certificate.status, 'expired');
  for (const [check, code, timeout] of [
    [httpsCheck('/status'), 'http_status', 1000],
    [httpsCheck('/ok', { contains: 'missing' }), 'http_content', 1000],
    [httpsCheck('/large', { maxBodyBytes: 64 }), 'response_too_large', 1000],
    [httpsCheck('/stall'), 'timeout', 100],
  ]) {
    const result = await probe(check, {}, timeout);
    resultIs(result, 'failure', code);
    assert.deepEqual(result.evidence.certificate, leafEvidence);
  }
  assert.equal((await probe(httpCheck('/ok'))).evidence.certificate, undefined);
  for (const [check, extra] of [
    [httpsCheck('/ok'), { ca: undefined }],
    [{ ...httpsCheck('/ok'), url: `https://wrong.example.com:${httpsPort}/ok` }, {}],
  ]) {
    const result = await probe(check, extra);
    resultIs(result, 'failure', 'tls_validation');
    assert.equal(result.evidence?.certificate, undefined);
  }
});
test('cross-origin redirect drops ALL custom headers; same-origin retains them', async () => {
  const headers = { Authorization: 'Bearer synthetic-test-only', Cookie: 'fixture=synthetic', 'X-Private': 'synthetic' };
  resultIs(await probe(httpCheck('/same', { headers })), 'success', 'http_ok');
  assert.equal(hits.at(-1).headers.authorization, headers.Authorization);
  resultIs(await probe(httpCheck('/cross', { headers })), 'success', 'http_ok');
  for (const name of ['authorization', 'cookie', 'x-private']) assert.equal(hits.at(-1).headers[name], undefined);
  assert.equal(hits.at(-1).host, `second.example.com:${httpPort}`);
});
test('redirect limits, private destinations, credential URLs and HTTPS downgrade fail closed', async () => {
  const beforeHits = hits.length;
  resultIs(await probe(httpCheck('/loop', { maxRedirects: 2 })), 'failure', 'redirect_limit');
  assert.equal(hits.length - beforeHits, 3);
  for (const path of ['/private', '/credential']) resultIs(await probe(httpCheck(path)), 'failure', 'blocked_destination');
  resultIs(await probe(httpsCheck('/downgrade')), 'failure', 'blocked_destination');
  const beforeCredential = hits.length;
  resultIs(await probe({ kind: 'http', url: `http://user:secret@fixture.example.com:${httpPort}/ok` }), 'unknown', 'invalid_url');
  assert.equal(hits.length, beforeCredential);
});
test('literal, mapped IPv4, IPv6 special and mixed DNS answers are rejected before connection', async () => {
  const beforeContact = hits.length;
  for (const address of ['0.0.0.0','10.0.0.1','127.0.0.1','100.64.0.1','169.254.169.254','192.0.0.8','198.18.0.1','224.0.0.1','::1','::ffff:127.0.0.1','fe80::1','fc00::1','2001:db8::1','2001:20::1','2002::1','3fff::1','4000::1']) {
    const host = address.includes(':') ? `[${address}]` : address;
    resultIs(await probe({kind:'http',url:`http://${host}:${httpPort}/ok`}), 'unknown', 'blocked_destination');
  }
  for (const answers of [[PUBLIC,'192.168.1.1'], [PUBLIC,'::1'], ['192.168.1.1',PUBLIC], ['2606:4700:4700::1111','fc00::1']]) {
    resultIs(await probe(httpCheck('/ok'), {resolve:async () => answers}), 'unknown', 'blocked_destination');
  }
  assert.equal(hits.length, beforeContact);
  const beforeHits = hits.length;
  resultIs(await execute({ kind: 'probe', check: { kind: 'http', url: 'http://127.0.0.1/' }, timeoutMs: 1000 }), 'unknown', 'blocked_destination');
  resultIs(await probe(httpCheck('/ok'), { resolve: async () => [PUBLIC, '192.168.1.1'] }), 'unknown', 'blocked_destination');
  assert.equal(hits.length, beforeHits);
});
test('bounded HTTP wire/decoded bodies and status/content semantics', async () => {
  for (const path of ['/large', '/chunked', '/compressed', '/deflate', '/brotli']) resultIs(await probe(httpCheck(path, { maxBodyBytes: 64 })), 'failure', 'response_too_large');
  resultIs(await probe(httpCheck('/gzip-ok', {contains:'TOMATO_OK',maxBodyBytes:64})), 'success', 'http_ok');
  resultIs(await probe(httpCheck('/status')), 'failure', 'http_status');
  resultIs(await probe(httpCheck('/status', { status: [418], contains: 'TOMATO_OK' })), 'success', 'http_ok');
  resultIs(await probe(httpCheck('/ok', { contains: 'missing' })), 'failure', 'http_content');
  resultIs(await probe(httpCheck('/ok', { method: 'HEAD' })), 'success', 'http_ok');
});
test('real WS and WSS use pins, disable compression and enforce message limits', async () => {
  for (const [scheme, port] of [['ws', httpPort], ['wss', httpsPort]]) {
    const beforeQueries = dnsQueries.length;
    resultIs(await probe({ kind: 'websocket', url: `${scheme}://fixture.example.com:${port}/ws`, send: 'TOMATO_OK', expect: 'TOMATO_OK' }), 'success', 'websocket_ok');
    assert.deepEqual(dnsQueries.slice(beforeQueries).map(query => query.type).sort(), ['A','AAAA']);
    assert.equal(hits.at(-1).headers['sec-websocket-extensions'], undefined);
    if (scheme === 'wss') assert.equal(hits.at(-1).sni, 'fixture.example.com');
  }
  resultIs(await probe({ kind: 'websocket', url: `ws://fixture.example.com:${httpPort}/ws-large`, send: 'go', expect: 'ok', maxMessageBytes: 8 }), 'failure', 'response_too_large');
  resultIs(await probe({ kind: 'websocket', url: `ws://fixture.example.com:${httpPort}/ws-wrong`, send: 'go', expect: 'ok' }), 'failure', 'websocket_message');
  const beforeHits = hits.length;
  resultIs(await probe({ kind: 'websocket', url: `ws://fixture.example.com:${httpPort}/ws`, send: 'x'.repeat(20), maxMessageBytes: 8 }), 'unknown', 'invalid_websocket_message');
  assert.equal(hits.length, beforeHits);
});
test('HTTP/WS timeouts are failures only after target start; DNS timeout is free UNKNOWN', async () => {
  resultIs(await probe(httpCheck('/stall'), {}, 100), 'failure', 'timeout');
  resultIs(await probe({ kind: 'websocket', url: `ws://fixture.example.com:${httpPort}/ws-stall`, send: 'go', expect: 'ok' }, {}, 100), 'failure', 'timeout');
  resultIs(await probe(httpCheck('/ok'), { resolve: async () => null }, 100), 'unknown', 'timeout');
});
test('real TCP/TLS pin directly and bound prefix, send, response and timeout behavior', async () => {
  for (const [kind, port] of [['tcp', tcpPort], ['tls', tlsPort]]) {
    const beforeQueries = dnsQueries.length;
    const check = { kind, hostname: 'fixture.example.com', port, send: 'HELLO', expect: 'TOMATO_OK' };
    resultIs(await probe(check), 'success', `${kind}_ok`);
    assert.deepEqual(dnsQueries.slice(beforeQueries).map(query => query.type).sort(), ['A','AAAA']);
    if (kind === 'tls') assert.equal(socketHits.at(-1).sni, 'fixture.example.com');
    resultIs(await probe({ ...check, send: 'WRONG' }), 'failure', 'socket_banner');
    resultIs(await probe({ ...check, send: 'SHORT' }), 'failure', 'socket_banner');
    resultIs(await probe({ ...check, send: 'LARGE', maxResponseBytes: 16 }), 'failure', 'response_too_large');
    resultIs(await probe({ ...check, send: 'STALL' }, {}, 100), 'failure', 'timeout');
    resultIs(await probe({ ...check, send: 'x'.repeat(4097) }), 'unknown', 'invalid_check_literal');
    resultIs(await probe({ ...check, hostname: '192.168.1.1' }), 'unknown', 'blocked_destination');
    resultIs(await probe({ ...check, expect: 'x'.repeat(20), maxResponseBytes: 8 }), 'unknown', 'invalid_socket_message');
    resultIs(await probe({ ...check, expect: undefined, send: undefined }), 'success', `${kind}_ok`);
  }
});
test('TLS validates original DNS/IP identity and omits SNI for IP literals', async () => {
  resultIs(await probe({ kind: 'tls', hostname: PUBLIC, port: tlsPort, send: 'HELLO', expect: 'TOMATO_OK' }), 'success', 'tls_ok');
  assert.equal(socketHits.at(-1).sni, false);
  resultIs(await probe({ kind: 'tls', hostname: 'wrong.example.com', port: tlsPort }), 'failure', 'tls_validation');
  resultIs(await probe({ kind: 'tls', hostname: 'fixture.example.com', port: tlsPort }, { ca: undefined }), 'failure', 'tls_validation');
});
test('real TLS leaf metadata survives application failure but never failed authentication', async () => {
  const check = { kind: 'tls', hostname: 'fixture.example.com', port: tlsPort };
  const healthy = await probe(check);
  resultIs(healthy, 'success', 'tls_ok');
  assert.deepEqual(healthy.evidence.certificate, leafEvidence);
  for (const [send, code, timeout] of [['WRONG', 'socket_banner', 1000], ['STALL', 'timeout', 100]]) {
    const result = await probe({ ...check, send, expect: 'TOMATO_OK' }, {}, timeout);
    resultIs(result, 'failure', code);
    assert.deepEqual(result.evidence.certificate, leafEvidence);
  }
  const invalid = await probe(check, { ca: undefined });
  resultIs(invalid, 'failure', 'tls_validation');
  assert.equal(invalid.evidence?.certificate, undefined);
});
test('custom HTTP headers reject identity, hop-by-hop, framing and proxy controls', async () => {
  const beforeHits = hits.length;
  for (const name of ['Host', 'Connection', 'Upgrade', 'Content-Length', 'Transfer-Encoding', 'Proxy-Authorization', 'Sec-Fetch-Site', 'Trailer', 'TE', 'Keep-Alive']) {
    resultIs(await probe(httpCheck('/ok', { headers: { [name]: 'synthetic' } })), 'unknown', 'invalid_http_headers');
  }
  resultIs(await probe(httpCheck('/ok', { headers: { 'X-Private': 'bad\r\nvalue' } })), 'unknown', 'invalid_http_headers');
  assert.equal(hits.length, beforeHits);
});
test('valid Latin1 and HTAB header values reach the real wire; illegal controls and higher Unicode never execute', async () => {
  const value = 'prefix\t\x80é\xffsuffix';
  resultIs(await probe(httpCheck('/header-values', { headers: { 'X-Audit': value } })), 'success', 'http_ok');
  assert.equal(hits.at(-1).path, '/header-values'); assert.equal(hits.at(-1).headers['x-audit'], value);
  const beforeHits = hits.length;
  for (const invalid of ['\u0001', '\u001f', '\u007f', '\u0100', '\u2028']) {
    resultIs(await probe(httpCheck('/header-values', { headers: { 'X-Audit': invalid } })), 'unknown', 'invalid_http_headers');
  }
  assert.equal(hits.length, beforeHits, 'Rejected characters must not be stripped and sent or become queued executor failures');
});
test('webhook uses HTTPS POST pins, actual status only, bounded JSON and no redirects', async () => {
  const eventId = `${'account'.padEnd(64, 'a')}:${'monitor'.padEnd(64, 'm')}:1:1700000000000:primary:incident:down`;
  const payload = JSON.stringify({ id: eventId, type: 'down' });
  const headers = { 'Content-Type': 'application/json', 'X-Tomato-Signature': 'a'.repeat(64), 'X-Tomato-Timestamp': '1234567890', 'Idempotency-Key': eventId };
  const input = { kind: 'webhook', url: `https://fixture.example.com:${httpsPort}/webhook`, timeoutMs: 1000, payload, headers };
  const beforeQueries = dnsQueries.length;
  assert.deepEqual(await execute(input), { status: 202, code: 'webhook_response' });
  assert.deepEqual(dnsQueries.slice(beforeQueries).map(query => query.type).sort(), ['A','AAAA']);
  assert.equal(hits.at(-1).method, 'POST'); assert.equal(hits.at(-1).body, payload);
  assert.equal(hits.at(-1).headers['idempotency-key'], eventId);
  const beforeHits = hits.length;
  assert.deepEqual(await execute({ ...input, url: `https://fixture.example.com:${httpsPort}/webhook-redirect` }), { status: 307, code: 'webhook_redirect' });
  assert.equal(hits.length, beforeHits + 1);
  assert.deepEqual(await execute({ ...input, url: `http://fixture.example.com:${httpPort}/webhook` }), { status: 0, code: 'blocked_destination' });
  assert.equal((await execute({ ...input, payload: 'x'.repeat(16_385) })).code, 'request_too_large');
  assert.equal((await execute({ ...input, headers: { ...headers, Authorization: 'synthetic' } })).code, 'invalid_http_headers');
  const beforeOversizedKey = hits.length;
  assert.equal((await execute({ ...input, headers: { ...headers, 'Idempotency-Key': 'x'.repeat(257) } })).code, 'invalid_http_headers');
  assert.equal(hits.length, beforeOversizedKey);
});
test('production child rejects loopback and request-supplied test or secret configuration', async () => {
  const beforeHits = hits.length;
  for (const extra of [{}, {allowLoopback:true}, {test:{allowedPorts:[httpPort]}}, {DATABASE_URL:'postgres://synthetic'}, {AUTH_SECRET:'synthetic'}]) {
    const response = await fetch(`http://127.0.0.1:${productionPort}/execute`, {method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({kind:'probe',check:{kind:'http',url:`http://127.0.0.1:${httpPort}/ok`},timeoutMs:1000,...extra})});
    assert.equal(response.status,200);
    resultIs(await response.json(),'unknown',Object.keys(extra).length ? 'invalid_request' : 'blocked_destination');
  }
  assert.equal(hits.length,beforeHits);
  const rejected = await run(process.execPath,['--input-type=module','-e',`import {createEgressServer} from ${JSON.stringify(new URL('../container/server.mjs',import.meta.url).href)}; import {readFile} from 'node:fs/promises'; createEgressServer({token:(await readFile(${JSON.stringify(join(scratch,'prober-token'))},'utf8')).trim(),test:{allowedPorts:[${httpPort}]}});`],{env:{NODE_ENV:'production',TOMATO_TRANSPORT_TEST:'1'}}).then(() => false,error => /test_transport_disabled/.test(error.stderr));
  assert.equal(rejected,true);
});
test('production missing private RPC is UNKNOWN/free and webhook not configured', async () => {
  const policy = { allowLoopback: false, resolverUrl: 'https://cloudflare-dns.com/dns-query' };
  resultIs(await runProbe(httpCheck('/ok'), 1000, policy), 'unknown', 'egress_not_configured');
  resultIs(await runProbe({ kind: 'websocket', url: `ws://fixture.example.com:${httpPort}/ws` }, 1000, policy), 'unknown', 'egress_not_configured');
  for (const kind of ['tcp', 'tls']) resultIs(await runProbe({ kind, hostname: 'fixture.example.com', port: tcpPort }, 1000, policy), 'unknown', 'egress_not_configured');
  assert.deepEqual(await dispatchWebhook(`https://fixture.example.com:${httpsPort}/webhook`, '{}', {}, 1000, policy), { status: 0, code: 'egress_not_configured' });
});
test('authenticated private RPC preserves actual protocol results and rejects unauthenticated callers', async () => {
  const policy = {allowLoopback:false,resolverUrl:'https://cloudflare-dns.com/dns-query',egress:createProber(`http://127.0.0.1:${privatePort}/execute`,token)};
  dnsResolve = async () => [PUBLIC];
  for (const check of [httpCheck('/ok'),httpsCheck('/ok'),{kind:'websocket',url:`ws://fixture.example.com:${httpPort}/ws`,send:'ok',expect:'ok'},{kind:'tcp',hostname:'fixture.example.com',port:tcpPort,send:'HELLO',expect:'TOMATO_OK'},{kind:'tls',hostname:'fixture.example.com',port:tlsPort,send:'HELLO',expect:'TOMATO_OK'}]) {
    const result = await runProbe(check,1000,policy);
    assert.equal(result.outcome,'success');
    if (check.kind === 'tls' || check.url?.startsWith('https:')) assert.deepEqual(result.evidence.certificate,leafEvidence);
  }
  for (const authorization of [undefined,'Bearer wrong-token',`Basic ${token}`]) {
    const response = await fetch(`http://127.0.0.1:${privatePort}/ready`,{headers:authorization ? {Authorization:authorization} : {}});
    assert.equal(response.status,401); assert.deepEqual(await response.json(),{code:'unauthorized'});
  }
  resultIs(await runProbe(httpCheck('/ok'),1000,{...policy,egress:createProber(`http://127.0.0.1:${privatePort}/execute`,'x'.repeat(32))}),'unknown','egress_unavailable');
});
test('private child bounds authenticated input JSON and rejects unknown paths/methods', async () => {
  const base = `http://127.0.0.1:${privatePort}`;
  const auth = {Authorization:`Bearer ${token}`}, json = {...auth,'Content-Type':'application/json'};
  assert.equal((await fetch(`${base}/ready`,{headers:auth})).status,200);
  assert.equal((await fetch(`${base}/proxy?url=https://example.com`,{headers:auth})).status,404);
  assert.equal((await fetch(`${base}/execute`,{headers:auth})).status,404);
  assert.equal((await fetch(`${base}/execute`,{method:'POST',headers:auth,body:'{}'})).status,415);
  assert.equal((await fetch(`${base}/execute`,{method:'POST',headers:json,body:'x'.repeat(MAX_REQUEST_BYTES+1)})).status,413);
  assert.equal((await fetch(`${base}/execute`,{method:'POST',headers:json,body:'{'})).status,400);
  for (const timeoutMs of [0,99,30001,Infinity]) {
    resultIs(await execute({kind:'probe',timeoutMs,check:httpCheck('/ok')}),'unknown','invalid_check_bounds');
  }
});
test('private child admits four real stalled targets, rejects overflow and releases every slot at deadline', async () => {
  dnsResolve = async () => [PUBLIC];
  const beforeHits = hits.length;
  const pending = Array.from({length:4},() => fetch(`http://127.0.0.1:${privatePort}/execute`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({kind:'probe',check:httpCheck('/stall'),timeoutMs:1500})}));
  const deadline = Date.now()+1000;
  while (hits.slice(beforeHits).filter(hit => hit.path === '/stall').length < 4) {
    assert(Date.now()<deadline,'Four actual target requests must arrive');
    await new Promise(resolve => setTimeout(resolve,10));
  }
  const overflow = await fetch(`http://127.0.0.1:${privatePort}/execute`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:'{}'});
  assert.equal(overflow.status,429); assert.deepEqual(await overflow.json(),{code:'egress_overloaded'});
  for (const response of await Promise.all(pending)) {assert.equal(response.status,200);resultIs(await response.json(),'failure','timeout');}
  resultIs(await probe(httpCheck('/ok')),'success','http_ok');
});
test('private child terminates incomplete authenticated uploads within its input deadline and frees admission', async () => {
  const completed = Promise.withResolvers();
  const request = httpRequest({host:'127.0.0.1',port:privatePort,path:'/execute',method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'}},response => {response.resume();response.once('end',completed.resolve);});
  request.once('error',completed.resolve); request.write('{');
  const watchdog = setTimeout(() => {request.destroy();completed.reject(new Error('Private input deadline exceeded'));},6500);
  const started = Date.now();
  try {await completed.promise;assert(Date.now()-started<6500);resultIs(await probe(httpCheck('/ok')),'success','http_ok');}
  finally {clearTimeout(watchdog);request.destroy();}
});
test('late DNS completion cannot start a target after the deadline or corrupt the next request', async () => {
  const beforeHits = hits.length;
  resultIs(await probe(httpCheck('/ok'), {resolve:async () => {await sleep(250);return [PUBLIC];}},100),'unknown','timeout');
  await sleep(300);
  assert.equal(hits.length,beforeHits);
  resultIs(await probe(httpCheck('/ok')),'success','http_ok');
});
test('mapped fixture pins cannot reach a port outside the exact owned allowlist', async () => {
  const denied = createHttpServer(handler), port = await listen(denied);
  const beforeHits = hits.length;
  try {
    resultIs(await probe({kind:'http',url:`http://fixture.example.com:${port}/ok`}),'unknown','blocked_destination');
    assert.equal(hits.length,beforeHits);
  } finally {await new Promise(resolve => denied.close(resolve));}
});
test('strict protocol and numeric bounds are enforced through actual authenticated request results', async () => {
  const beforeHits = hits.length;
  for (const check of [
    {kind:'http',url:'file:///etc/passwd'},
    {kind:'http',url:`ftp://fixture.example.com:${httpPort}/ok`},
    {kind:'http',url:`http://fixture.example.com:${httpPort}/ok#fragment`},
    {kind:'websocket',url:`http://fixture.example.com:${httpPort}/ws`},
    httpCheck('/ok',{method:'POST'}),httpCheck('/ok',{maxRedirects:6}),
    httpCheck('/ok',{maxBodyBytes:262145}),httpCheck('/ok',{method:'HEAD',contains:'x'}),
    {kind:'tcp',hostname:'fixture.example.com',port:0},
    {kind:'tls',hostname:'fixture.example.com',port:tlsPort,maxResponseBytes:65537},
  ]) {
    const result = await probe(check);
    assert.equal(result.outcome,'unknown'); assert.match(result.code,/^invalid_/);
  }
  assert.equal(hits.length,beforeHits);
});
test('real authenticated admission hop stays outside every target protocol deadline', async () => {
  dnsResolve = async () => [PUBLIC];
  const bridge = createHttpServer(async (request,response) => {
    if (request.headers.authorization !== `Bearer ${token}`) {response.writeHead(401);response.end();return;}
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    await sleep(250);
    const upstream = await fetch(`http://127.0.0.1:${privatePort}/execute`, {
      method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:Buffer.concat(chunks),signal:AbortSignal.timeout(2000),
    });
    response.writeHead(upstream.status,{'Content-Type':'application/json'});
    response.end(Buffer.from(await upstream.arrayBuffer()));
  });
  const port = await listen(bridge);
  const policy = {allowLoopback:false,resolverUrl:'https://cloudflare-dns.com/dns-query',egress:createProber(`http://127.0.0.1:${port}/execute`,token)};
  try {
    for (const check of [httpCheck('/ok'),httpsCheck('/ok'),{kind:'websocket',url:`wss://fixture.example.com:${httpsPort}/ws`,send:'ok',expect:'ok'},{kind:'tcp',hostname:'fixture.example.com',port:tcpPort,send:'HELLO',expect:'TOMATO_OK'},{kind:'tls',hostname:'fixture.example.com',port:tlsPort,send:'HELLO',expect:'TOMATO_OK'}]) {
      const started = Date.now();
      assert.equal((await runProbe(check,100,policy)).outcome,'success');
      assert(Date.now()-started>=250,'Real admission delay must be exercised separately from the target budget');
    }
  } finally {bridge.closeAllConnections();await new Promise(resolve => bridge.close(resolve));}
});
