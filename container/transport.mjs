import { Resolver } from 'node:dns/promises';
import { randomInt } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, connect as connectTcp } from 'node:net';
import { checkServerIdentity, connect as connectTls } from 'node:tls';
import { createGunzip, createInflate, createBrotliDecompress } from 'node:zlib';
import ipaddr from 'ipaddr.js';
import WebSocket from 'ws';
import dnsPacket from 'dns-packet';

export const MAX_REQUEST_BYTES = 65_536;
const MAX_BODY = 262_144;
const MAX_LITERAL = 4096;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const forbiddenV4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'].map(ipaddr.parseCIDR);
const forbiddenV6 = ['2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20'].map(ipaddr.parseCIDR);

class Fault extends Error {
  constructor(code, outcome = 'unknown') { super(code); this.code = code; this.outcome = outcome; }
}
function fail(code, outcome) { throw new Fault(code, outcome); }
function integer(value, fallback, min, max) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('invalid_check_bounds');
  return value;
}
function literal(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || Buffer.byteLength(value) > MAX_LITERAL) fail('invalid_check_literal');
  return value;
}
function object(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !fields.includes(key))) fail('invalid_request');
}
export function publicAddress(value, allowLoopback = false) {
  if (typeof value !== 'string' || value.includes('%') || !ipaddr.isValid(value)) fail('destination_disallowed');
  const address = ipaddr.process(value);
  if (allowLoopback && address.range() === 'loopback') return address.toString();
  if (address.range() !== 'unicast') fail('destination_disallowed');
  if (address.kind() === 'ipv4' ? forbiddenV4.some(range => address.match(range)) :
      !address.match(ipaddr.parse('2000::'), 3) || forbiddenV6.some(range => address.match(range))) fail('destination_disallowed');
  return address.toString();
}
function hostnameSyntax(value, test) {
  if (typeof value !== 'string' || !value || value.length > 253 || /[\s/@?#\\%]/.test(value)) fail('invalid_hostname');
  const name = value.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (ipaddr.isValid(name)) publicAddress(name, test?.allowLoopback);
  else if (!name.includes('.') || !name.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
    /(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|onion)$/.test(name)) fail('destination_disallowed');
  return name;
}
function urlSyntax(value, websocket = false, test) {
  if (typeof value !== 'string' || value.length > 4096 || /[\u0000-\u0020\u007f\\]/.test(value)) fail('invalid_url');
  let url;
  try { url = new URL(value); } catch { fail('invalid_url'); }
  if (!(websocket ? ['ws:', 'wss:'] : ['http:', 'https:']).includes(url.protocol) || url.username || url.password || url.hash || !url.hostname) fail('invalid_url');
  hostnameSyntax(url.hostname, test);
  return url;
}
function headers(input, webhook = false) {
  if (input === undefined) return {};
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length > 32) fail('invalid_http_headers');
  const result = Object.create(null);
  let bytes = 0;
  for (const [name, value] of Object.entries(input)) {
    const key = name.toLowerCase();
    if (name.length > 128 || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || typeof value !== 'string' || /[^\t\x20-\x7e\x80-\xff]/.test(value) ||
      /^(?:host|connection|upgrade|content-length|transfer-encoding|proxy-.*|sec-.*|trailer|te|keep-alive)$/i.test(name) || Object.hasOwn(result, key)) fail('invalid_http_headers');
    if (webhook && !['content-type', 'idempotency-key', 'x-tomato-signature', 'x-tomato-timestamp'].includes(key)) fail('invalid_http_headers');
    bytes += Buffer.byteLength(name + value);
    if (bytes > 8192) fail('invalid_http_headers');
    result[key] = value;
  }
  return result;
}
export function validateRequest(input, test) {
  object(input, ['kind', 'check', 'timeoutMs', 'url', 'payload', 'headers']);
  const timeoutMs = integer(input.timeoutMs, undefined, 100, 30_000);
  if (timeoutMs === undefined) fail('invalid_timeout');
  if (input.kind === 'webhook') {
    if (input.check !== undefined) fail('invalid_request');
    const url = urlSyntax(input.url, false, test);
    if (url.protocol !== 'https:' && !(test?.allowLoopback && url.protocol === 'http:')) fail('destination_disallowed');
    if (typeof input.payload !== 'string' || Buffer.byteLength(input.payload) > 16_384) fail('request_too_large');
    try { const value = JSON.parse(input.payload); if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_payload'); } catch { fail('invalid_payload'); }
    const checkedHeaders = headers(input.headers, true);
    if (checkedHeaders['content-type'] !== 'application/json' || !/^[a-f0-9]{64}$/.test(checkedHeaders['x-tomato-signature'] ?? '')) fail('invalid_http_headers');
    if (!/^\d{1,16}$/.test(checkedHeaders['x-tomato-timestamp'] ?? '') ||
        !/^[A-Za-z0-9_:-]{1,256}$/.test(checkedHeaders['idempotency-key'] ?? '')) fail('invalid_http_headers');
    return { kind: 'webhook', url, payload: input.payload, headers: checkedHeaders, timeoutMs };
  }
  if (input.kind !== 'probe' || input.url !== undefined || input.payload !== undefined || input.headers !== undefined) fail('invalid_request');
  const check = input.check;
  if (check?.kind === 'dns') {
    object(check, ['kind', 'name', 'recordType', 'expected', 'resolverUrl']);
    if (!['A','AAAA','MX','TXT','NS','CNAME'].includes(check.recordType)) fail('invalid_dns_type');
    const name = dnsName(check.name);
    const resolverUrl = test?.resolverUrl ?? process.env.TOMATO_DNS_RESOLVER_URL ?? 'https://cloudflare-dns.com/dns-query';
    if (check.resolverUrl !== undefined && check.resolverUrl !== resolverUrl) fail('untrusted_resolver');
    let expected;
    if (check.expected !== undefined) {
      if (!Array.isArray(check.expected) || check.expected.length > 32 || check.expected.some(value => typeof value !== 'string' || Buffer.byteLength(value) > 1024)) fail('invalid_dns_expected');
      expected = [...new Set(check.expected.map(value => dnsValue(check.recordType,value)))].sort();
    }
    return {kind:'dns',name,recordType:check.recordType,expected,resolverUrl,timeoutMs};
  }
  if (check?.kind === 'http') {
    object(check, ['kind', 'url', 'method', 'headers', 'status', 'contains', 'maxBodyBytes', 'maxRedirects']);
    const url = urlSyntax(check.url, false, test);
    if (check.method !== undefined && !['GET', 'HEAD'].includes(check.method)) fail('invalid_http_method');
    if (check.status !== undefined && (!Array.isArray(check.status) || !check.status.length || check.status.length > 100 || check.status.some(code => !Number.isInteger(code) || code < 100 || code > 599))) fail('invalid_http_status');
    const maxBodyBytes = integer(check.maxBodyBytes, 65_536, 1, MAX_BODY);
    const contains = literal(check.contains);
    if (contains !== undefined && (check.method === 'HEAD' || Buffer.byteLength(contains) > maxBodyBytes)) fail('invalid_http_content');
    return { kind: 'http', url, method: check.method ?? 'GET', headers: headers(check.headers), status: check.status, contains, maxBodyBytes,
      maxRedirects: integer(check.maxRedirects, 3, 0, 5), timeoutMs };
  }
  if (check?.kind === 'websocket') {
    object(check, ['kind', 'url', 'send', 'expect', 'maxMessageBytes']);
    const maxMessageBytes = integer(check.maxMessageBytes, 16_384, 1, 65_536);
    const send = literal(check.send), expect = literal(check.expect);
    if ([send, expect].some(value => value !== undefined && Buffer.byteLength(value) > maxMessageBytes)) fail('invalid_websocket_message');
    return { kind: 'websocket', url: urlSyntax(check.url, true, test), send, expect, maxMessageBytes, timeoutMs };
  }
  if (check?.kind === 'tcp' || check?.kind === 'tls') {
    object(check, ['kind', 'hostname', 'port', 'send', 'expect', 'maxResponseBytes']);
    const hostname = hostnameSyntax(check.hostname, test);
    const port = integer(check.port, undefined, 1, 65535);
    if (port === undefined) fail('invalid_check_bounds');
    const send = literal(check.send), expect = literal(check.expect);
    const maxResponseBytes = integer(check.maxResponseBytes, 16_384, 1, 65_536);
    if (expect !== undefined && Buffer.byteLength(expect) > maxResponseBytes) fail('invalid_socket_message');
    return { kind: check.kind, hostname, port, send, expect, maxResponseBytes, timeoutMs };
  }
  fail('invalid_probe_kind');
}
async function systemResolve(hostname, signal) {
  const resolver = new Resolver({ timeout: 1000, tries: 1 });
  const abort = () => resolver.cancel();
  signal.addEventListener('abort', abort, { once: true });
  try {
    signal.throwIfAborted();
    const results = await Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]);
    const addresses = [];
    for (const result of results) {
      if (result.status === 'fulfilled') addresses.push(...result.value);
      else if (!['ENODATA', 'ENOTFOUND'].includes(result.reason?.code)) fail('resolver_unavailable');
    }
    return addresses;
  } finally { signal.removeEventListener('abort', abort); resolver.cancel(); }
}
function deadlineRace(promise, signal) {
  if (signal.aborted) { promise.catch(() => {}); return Promise.reject(signal.reason); }
  const aborted = Promise.withResolvers();
  const listener = () => aborted.reject(signal.reason);
  signal.addEventListener('abort', listener, { once: true });
  return Promise.race([promise, aborted.promise]).finally(() => signal.removeEventListener('abort', listener));
}
async function pin(url, signal, test) {
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const literalIp = isIP(hostname);
  if (test?.allowLoopback) {
    const port = Number(url.port || (url.protocol === 'https:' || url.protocol === 'wss:' ? 443 : 80));
    if (!literalIp || ipaddr.process(hostname).range() !== 'loopback' || !test.allowedPorts.includes(port)) fail('destination_disallowed');
  }
  const candidates = literalIp ? [hostname] : await deadlineRace((test?.resolve ?? systemResolve)(hostname, signal), signal);
  if (!Array.isArray(candidates) || candidates.length === 0) fail('dns_resolution_failed', 'failure');
  if (candidates.length > 64) fail('resolver_invalid_response');
  const address = candidates.map(value => publicAddress(value, test?.allowLoopback))[0];
  // The adapter is inaccessible from JSON and disabled in production. It maps a
  // validated pin onto a real fixture; lookup NEVER consults the resolver again.
  const networkAddress = test?.connectAddress ? test.connectAddress(address) : address;
  if (test?.connectAddress && typeof networkAddress === 'string' && ipaddr.isValid(networkAddress) && ipaddr.process(networkAddress).range() === 'loopback') {
    const port = Number(url.port || (url.protocol === 'https:' || url.protocol === 'wss:' ? 443 : 80));
    if (!Array.isArray(test.allowedPorts) || !test.allowedPorts.includes(port)) fail('destination_disallowed');
  }
  if (test?.onPin) test.onPin({ hostname, address, networkAddress });
  const lookup = (_host, options, callback) => {
    test?.onLookup?.(address);
    if (options?.all) callback(null, [{ address: networkAddress, family: isIP(networkAddress) }]);
    else callback(null, networkAddress, isIP(networkAddress));
  };
  return { hostname, address, networkAddress, lookup, literalIp };
}
function transportError(error, signal, started) {
  if (signal.aborted) return signal.reason instanceof Fault ? signal.reason : new Fault('timeout', started ? 'failure' : 'unknown');
  if (error instanceof Fault) return error;
  const code = String(error?.code ?? '');
  if (/CERT|TLS|SSL|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER/.test(code)) return new Fault('tls_validation', 'failure');
  if (/^E(?:CONN|HOST|NET|PIPE|TIMEDOUT|NOTFOUND)/.test(code)) return new Fault('connection_failed', 'failure');
  if (code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH') return new Fault('response_too_large', 'failure');
  return new Fault('internal_error');
}
// Only a successfully authorized TLS socket can contribute leaf metadata. Never
// serialize the peer certificate itself (which includes raw DER and key data).
function certificateEvidence(socket) {
  if (!socket?.authorized || typeof socket.getPeerCertificate !== 'function') return undefined;
  const leaf = socket.getPeerCertificate();
  const validFrom = Date.parse(leaf.valid_from), validTo = Date.parse(leaf.valid_to);
  if (![validFrom, validTo].every(value => Number.isSafeInteger(value) && value >= 0 && value <= 8_640_000_000_000_000) ||
      validFrom > validTo) return undefined;
  return { validFrom, validTo };
}
async function exchange(url, pinned, init, limit, signal, begin, test, observeCertificate) {
  const completed = Promise.withResolvers();
  const chunks = [];
  let size = 0;
  let decoder;
  signal.throwIfAborted();
  const secure = url.protocol === 'https:';
  const request = (secure ? httpsRequest : httpRequest)(url, {
    method: init.method, headers: init.headers, agent: false, lookup: pinned.lookup,
    // IP literals skip DNS lookup by Node design but are validated and used directly.
    ...(pinned.literalIp && test?.connectAddress ? { hostname: pinned.networkAddress, headers: { ...init.headers, host: url.host } } : {}),
    rejectUnauthorized: true, servername: isIP(pinned.hostname) ? undefined : pinned.hostname,
    checkServerIdentity: (_hostname, certificate) => checkServerIdentity(pinned.hostname, certificate),
    ...(test?.ca ? { ca: test.ca } : {}), signal, maxHeaderSize: 16_384,
  }, response => {
    const status = response.statusCode ?? 0;
    // Webhook delivery needs the actual status only. Destroy immediately rather
    // than buffering or returning any untrusted response body (including secrets).
    if (init.payload !== undefined && !init.readResponse) {
      completed.resolve({ status, body: Buffer.alloc(0) }); response.destroy(); return;
    }
    if (REDIRECTS.has(status)) {
      completed.resolve({ status, location: response.headers.location, body: Buffer.alloc(0) });
      response.destroy(); return;
    }
    if (Number(response.headers['content-length']) > limit) {
      completed.reject(new Fault('response_too_large', 'failure')); response.destroy(); return;
    }
    const encoding = response.headers['content-encoding']?.toLowerCase();
    decoder = encoding === 'gzip' ? createGunzip() : encoding === 'deflate' ? createInflate() :
      encoding === 'br' ? createBrotliDecompress() : undefined;
    if (encoding && encoding !== 'identity' && !decoder) {
      completed.reject(new Fault('response_encoding', 'failure')); response.destroy(); return;
    }
    let wireBytes = 0;
    response.on('data', chunk => {
      wireBytes += chunk.length;
      if (wireBytes > limit) { completed.reject(new Fault('response_too_large', 'failure')); response.destroy(); decoder?.destroy(); }
    });
    const stream = decoder ? response.pipe(decoder) : response;
    stream.on('data', chunk => {
      size += chunk.length;
      if (size > limit) { completed.reject(new Fault('response_too_large', 'failure')); response.destroy(); decoder?.destroy(); }
      else chunks.push(chunk);
    });
    stream.on('end', () => completed.resolve({ status, body: Buffer.concat(chunks, size), contentType: response.headers['content-type'] }));
    stream.on('error', () => completed.reject(new Fault('response_encoding', 'failure')));
    response.on('error', completed.reject);
    response.on('aborted', () => completed.reject(new Fault('connection_failed', 'failure')));
  });
  if (secure && observeCertificate) request.on('socket', socket => {
    socket.once('secureConnect', () => observeCertificate(certificateEvidence(socket)));
  });
  request.on('error', completed.reject);
  if (begin()) { if (init.payload !== undefined) request.end(init.payload); else request.end(); }
  try { return await deadlineRace(completed.promise, signal); }
  finally { request.destroy(); decoder?.destroy(); }
}
async function http(check, signal, begin, test, observeCertificate) {
  let url = check.url;
  let requestHeaders = check.headers;
  for (let hop = 0; ; hop++) {
    let pinned;
    try { pinned = await pin(url, signal, test); }
    catch (error) { if (hop && error instanceof Fault && error.code === 'destination_disallowed') fail('blocked_destination', 'failure'); throw error; }
    const result = await exchange(url, pinned, { method: check.method, headers: requestHeaders }, check.maxBodyBytes, signal, begin, test, observeCertificate);
    if (REDIRECTS.has(result.status)) {
      if (hop >= check.maxRedirects) fail('redirect_limit', 'failure');
      if (!result.location) fail('redirect_invalid', 'failure');
      let next;
      try { next = urlSyntax(new URL(result.location, url).href, false, test); } catch { fail('blocked_destination', 'failure'); }
      if (url.protocol === 'https:' && next.protocol !== 'https:') fail('blocked_destination', 'failure');
      if (next.origin !== url.origin) requestHeaders = {};
      url = next; continue;
    }
    const evidence = { status: result.status, bytes: result.body.length };
    if (check.status ? !check.status.includes(result.status) : result.status < 200 || result.status > 299) return { outcome: 'failure', code: 'http_status', evidence };
    if (check.contains !== undefined && !result.body.toString('utf8').includes(check.contains)) return { outcome: 'failure', code: 'http_content', evidence };
    return { outcome: 'success', code: 'http_ok', evidence };
  }
}
async function websocket(check, signal, begin, test) {
  const pinned = await pin(check.url, signal, test);
  signal.throwIfAborted();
  const result = Promise.withResolvers();
  const socket = new WebSocket(check.url, {
    lookup: pinned.lookup, agent: false, rejectUnauthorized: true,
    servername: isIP(pinned.hostname) ? undefined : pinned.hostname,
    checkServerIdentity: (_hostname, certificate) => checkServerIdentity(pinned.hostname, certificate),
    ...(test?.ca ? { ca: test.ca } : {}), followRedirects: false,
    perMessageDeflate: false, maxPayload: check.maxMessageBytes, handshakeTimeout: check.timeoutMs, maxHeaderSize: 16_384,
  });
  const abort = () => { result.reject(signal.reason); socket.terminate(); };
  signal.addEventListener('abort', abort, { once: true });
  socket.on('error', result.reject);
  socket.on('unexpected-response', (_request, response) => {
    result.resolve({ outcome: 'failure', code: 'websocket_handshake', evidence: { status: response.statusCode ?? 0 } });
    response.destroy(); socket.terminate();
  });
  socket.on('close', () => result.reject(new Fault('websocket_closed', 'failure')));
  socket.on('message', data => {
    const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (bytes.length > check.maxMessageBytes) result.reject(new Fault('response_too_large', 'failure'));
    else if (check.expect !== undefined && bytes.toString('utf8') !== check.expect) result.reject(new Fault('websocket_message', 'failure'));
    else if (check.expect !== undefined) result.resolve({ outcome: 'success', code: 'websocket_ok', evidence: { status: 101, bytes: bytes.length } });
  });
  socket.on('open', () => {
    if (signal.aborted) return abort();
    const sent = error => {
      if (error) result.reject(error);
      else if (check.expect === undefined) result.resolve({ outcome: 'success', code: 'websocket_ok', evidence: { status: 101, bytes: 0 } });
    };
    if (check.send !== undefined) socket.send(check.send, sent); else sent();
  });
  begin();
  try { return await result.promise; }
  finally { signal.removeEventListener('abort', abort); socket.terminate(); }
}
async function socketProbe(check, signal, begin, test, observeCertificate) {
  const pinned = await pin({ hostname: check.hostname, port: check.port }, signal, test);
  signal.throwIfAborted();
  const completed = Promise.withResolvers();
  const expected = check.expect === undefined ? undefined : Buffer.from(check.expect);
  let bytes = 0;
  let connected = false;
  // Direct validated IP connection: no secondary resolver lookup is possible.
  const options = { host: pinned.networkAddress, port: check.port };
  const socket = check.kind === 'tls' ? connectTls({
    ...options, rejectUnauthorized: true,
    servername: isIP(check.hostname) ? undefined : check.hostname,
    checkServerIdentity: (_hostname, certificate) => checkServerIdentity(check.hostname, certificate),
    ...(test?.ca ? { ca: test.ca } : {}),
  }) : connectTcp(options);
  const abort = () => { completed.reject(signal.reason); socket.destroy(); };
  signal.addEventListener('abort', abort, { once: true });
  socket.on('error', completed.reject);
  socket.on('close', () => completed.reject(new Fault(connected ? 'socket_closed' : 'connection_failed', 'failure')));
  socket.on(check.kind === 'tls' ? 'secureConnect' : 'connect', () => {
    connected = true;
    if (check.kind === 'tls') observeCertificate(certificateEvidence(socket));
    if (signal.aborted) return abort();
    const sent = error => {
      if (error) completed.reject(error);
      else if (expected === undefined || expected.length === 0) completed.resolve(0);
    };
    if (check.send !== undefined) socket.write(check.send, sent); else sent();
  });
  socket.on('data', chunk => {
    const previous = bytes;
    bytes += chunk.length;
    if (bytes > check.maxResponseBytes) { completed.reject(new Fault('response_too_large', 'failure')); socket.destroy(); return; }
    if (expected === undefined) return;
    const length = Math.min(chunk.length, Math.max(0, expected.length - previous));
    for (let i = 0; i < length; i++) {
      if (chunk[i] !== expected[previous + i]) { completed.reject(new Fault('socket_banner', 'failure')); socket.destroy(); return; }
    }
    if (bytes >= expected.length) completed.resolve(bytes);
  });
  socket.on('end', () => { if (expected !== undefined) completed.reject(new Fault('socket_banner', 'failure')); });
  begin();
  try {
    return { outcome: 'success', code: check.kind === 'tls' ? 'tls_ok' : 'tcp_ok', evidence: { bytes: await completed.promise } };
  } finally { signal.removeEventListener('abort', abort); socket.destroy(); }
}

function dnsName(value) {
  if (typeof value !== 'string' || !value || value.length > 253) fail('invalid_dns_name');
  const name = value.toLowerCase().replace(/\.$/,'');
  if (!name.split('.').every(label => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label))) fail('invalid_dns_name');
  return name;
}
function dnsValue(type, value) {
  if (type === 'A' || type === 'AAAA') {
    if (!ipaddr.isValid(value)) fail('invalid_dns_answer');
    const address = ipaddr.parse(value);
    if (address.kind() !== (type === 'A' ? 'ipv4' : 'ipv6')) fail('invalid_dns_answer');
    return address.toString();
  }
  if (type === 'NS' || type === 'CNAME') return dnsName(value);
  if (type === 'MX') {
    const match = /^(\d{1,5})\s+(\S+)$/.exec(value);
    if (!match || Number(match[1]) > 65535) fail('invalid_dns_answer');
    return `${Number(match[1])} ${dnsName(match[2])}`;
  }
  return value;
}
async function dns(check, signal, test) {
  const resolver = urlSyntax(check.resolverUrl, false, test);
  if (resolver.protocol !== 'https:' && !(test?.allowLoopback && resolver.protocol === 'http:')) fail('resolver_configuration_invalid');
  const id = randomInt(65536);
  const payload = dnsPacket.encode({type:'query',id,flags:dnsPacket.RECURSION_DESIRED,questions:[{name:check.name,type:check.recordType,class:'IN'}]});
  let response;
  try {
    const pinned = await pin(resolver,signal,test);
    response = await exchange(resolver,pinned,{method:'POST',headers:{'content-type':'application/dns-message',accept:'application/dns-message'},payload,readResponse:true},16384,signal,()=>!signal.aborted,test);
  } catch (error) { if (signal.aborted) throw error; fail('resolver_unavailable'); }
  if (response.status !== 200 || response.contentType?.split(';')[0]?.trim().toLowerCase() !== 'application/dns-message') fail('resolver_invalid_response');
  let packet;
  try { packet = dnsPacket.decode(response.body); } catch { fail('resolver_invalid_response'); }
  if (packet.type !== 'response' || packet.id !== id || packet.flag_tc || packet.questions?.length !== 1 || packet.questions[0].type !== check.recordType || packet.questions[0].name.toLowerCase().replace(/\.$/,'') !== check.name || (packet.questions[0].class ?? 'IN') !== 'IN' || [...(packet.answers??[]),...(packet.authorities??[]),...(packet.additionals??[])].length > 64) fail('resolver_invalid_response');
  const rcode = (packet.flags??0)&15;
  if (rcode !== 0) return {outcome:'failure',code:rcode===3?'dns_nxdomain':'dns_rcode',evidence:{answers:[]}};
  const chain = new Set([check.name]);
  for (let hop=0; hop<8; hop++) {
    let changed=false;
    for (const answer of packet.answers??[]) {
      if (answer.type==='CNAME' && chain.has(dnsName(answer.name)) && !chain.has(dnsName(answer.data))) {chain.add(dnsName(answer.data));changed=true;}
    }
    if (!changed) break;
    if (hop===7) fail('resolver_alias_limit');
  }
  const values=[];
  for (const answer of packet.answers??[]) {
    if (answer.type!==check.recordType || !chain.has(dnsName(answer.name))) continue;
    const raw=answer.type==='MX'?`${answer.data.preference??0} ${answer.data.exchange}`:answer.type==='TXT'?(Array.isArray(answer.data)?answer.data:[answer.data]).map(chunk=>typeof chunk==='string'?chunk:Buffer.from(chunk).toString('utf8')).join(''):answer.data;
    const value=dnsValue(check.recordType,raw);
    if (Buffer.byteLength(value)>1024 || values.length>=32) fail('dns_answers_too_large','failure');
    values.push(value);
  }
  const answers=[...new Set(values)].sort();
  const matches=check.expected?answers.length===check.expected.length&&answers.every((value,index)=>value===check.expected[index]):answers.length>0;
  return {outcome:matches?'success':'failure',code:matches?'dns_ok':'dns_answers',evidence:{answers}};
}

export async function execute(input, test) {
  if (test && (process.env.TOMATO_TRANSPORT_TEST !== '1' || process.env.NODE_ENV !== 'test')) throw new Error('test_adapter_disabled');
  if (test?.allowLoopback && (process.env.NODE_ENV !== 'test' || !Array.isArray(test.allowedPorts) || test.allowedPorts.length === 0 ||
      test.allowedPorts.some(port => !Number.isInteger(port) || port < 1 || port > 65535) || test.connectAddress || test.resolve)) throw new Error('invalid_loopback_fixture_config');
  const startedAt = Date.now();
  const controller = new AbortController();
  let started = false;
  let timer;
  let result;
  let certificate;
  // Preserve the earliest-expiring verified leaf across every HTTPS redirect
  // hop; a healthy destination must not hide an expiring prerequisite.
  const observeCertificate = value => {
    if (value && (!certificate || value.validTo < certificate.validTo)) certificate = value;
  };
  let webhook = input?.kind === 'webhook';
  try {
    const check = validateRequest(input, test);
    webhook = check.kind === 'webhook';
    const deadline = startedAt + check.timeoutMs;
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Fault('timeout', 'unknown');
    timer = setTimeout(() => controller.abort(new Fault('timeout', started ? 'failure' : 'unknown')), remaining);
    const begin = () => {
      // Synchronous socket/request construction can exhaust the budget before
      // timers run. That is executor-local UNKNOWN, not a target outage.
      if (Date.now() >= deadline) { controller.abort(new Fault('timeout', 'unknown')); return false; }
      if (controller.signal.aborted) return false;
      started = true;
      return true;
    };
    if (webhook) {
      const pinned = await pin(check.url, controller.signal, test);
      const response = await exchange(check.url, pinned, { method: 'POST', headers: check.headers, payload: check.payload }, 16_384, controller.signal, begin, test);
      result = { status: response.status, code: REDIRECTS.has(response.status) ? 'webhook_redirect' : 'webhook_response' };
    } else result = check.kind === 'http' ? await http(check, controller.signal, begin, test, observeCertificate) :
      check.kind === 'dns' ? await dns(check, controller.signal, test) :
      check.kind === 'websocket' ? await websocket(check, controller.signal, begin, test) : await socketProbe(check, controller.signal, begin, test, observeCertificate);
  } catch (error) {
    const fault = transportError(error, controller.signal, started);
    const code = fault.code === 'destination_disallowed' ? 'blocked_destination' : fault.code;
    result = webhook ? { status: 0, code } : { outcome: fault.code === 'destination_disallowed' ? (started ? 'failure' : 'unknown') : fault.outcome, code };
  } finally { clearTimeout(timer); controller.abort(); }
  if (webhook) return result;
  if (certificate) result.evidence = { ...result.evidence, certificate };
  const finishedAt = Date.now();
  return { ...result, startedAt, finishedAt, latencyMs: Math.max(0, finishedAt - startedAt) };
}
