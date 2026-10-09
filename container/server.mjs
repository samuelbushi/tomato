import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { execute, MAX_REQUEST_BYTES } from './transport.mjs';

const MAX_CONCURRENCY = 4;
let active = 0;
function respond(response, status, value) {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', connection: 'close' });
  response.end(JSON.stringify(value));
}
// No state store, database/admin credentials, proxy, or target request logging.
export function createEgressServer({ token, test } = {}) {
  if (typeof token !== 'string' || token.length < 32) throw new Error('prober_auth_not_configured');
  if (test && (process.env.TOMATO_TRANSPORT_TEST !== '1' || process.env.NODE_ENV !== 'test')) throw new Error('test_transport_disabled');
  const expected = Buffer.from(`Bearer ${token}`);
  const server = createServer({ maxHeaderSize: 4096 }, async (request, response) => {
    response.once('finish', () => request.destroy());
    const received = Buffer.from(request.headers.authorization ?? '');
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) { respond(response, 401, { code: 'unauthorized' }); return; }
    if (request.method === 'GET' && request.url === '/ready') { respond(response, 200, { ready: true }); return; }
    if (request.method !== 'POST' || request.url !== '/execute') { respond(response, 404, { code: 'not_found' }); return; }
    if (request.headers['content-type'] !== 'application/json') { respond(response, 415, { code: 'invalid_request' }); return; }
    if (active >= MAX_CONCURRENCY) { respond(response, 429, { code: 'egress_overloaded' }); return; }
    if (Number(request.headers['content-length']) > MAX_REQUEST_BYTES) { respond(response, 413, { code: 'request_too_large' }); return; }
    active++;
    const inputDeadline = setTimeout(() => request.destroy(), 5000);
    try {
      const chunks = [];
      let bytes = 0;
      for await (const chunk of request) {
        bytes += chunk.length;
        if (bytes > MAX_REQUEST_BYTES) {
          respond(response, 413, { code: 'request_too_large' }); return;
        }
        chunks.push(chunk);
      }
      clearTimeout(inputDeadline);
      let input;
      try { input = JSON.parse(Buffer.concat(chunks, bytes).toString('utf8')); }
      catch { respond(response, 400, { code: 'invalid_request' }); return; }
      respond(response, 200, await execute(input, test));
    } catch {
      if (!response.headersSent && !response.destroyed) respond(response, 400, { code: 'invalid_request' });
    } finally { clearTimeout(inputDeadline); active--; }
  });
  server.requestTimeout = 35_000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.maxRequestsPerSocket = 1;
  return server;
}

if (process.env.TOMATO_CONTAINER_SERVER === '1') {
  if (process.env.NODE_ENV !== 'production' || process.env.TEST_MODE || process.env.TOMATO_TRANSPORT_TEST ||
      Object.keys(process.env).some(key => /^(?:DATABASE_URL|POSTGRES_|PG(?:HOST|USER|PASSWORD|DATABASE|PORT)|DATA_KEY|AUTH_SECRET|AUTH_PEPPER|ENGINE_TOKEN|TOMATO_(?:DB_|AUTH_|ENGINE_|OWNER_|SMTP_|GITHUB_|GOOGLE_|LEGACY_))/.test(key))) {
    throw new Error('prober_forbidden_configuration');
  }
  const token = readFileSync(process.env.TOMATO_PROBER_TOKEN_FILE ?? '/run/secrets/prober_token', 'utf8').trim();
  const server = createEgressServer({ token });
  process.once('SIGTERM', () => server.close(() => process.exit(0)));
  server.listen(8080, '0.0.0.0');
}
