import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
const require = createRequire('/app/package.json');
const { WebSocketServer } = require('ws');
const [key, cert] = await Promise.all([readFile('/fixtures/server.key'), readFile('/fixtures/server.pem')]);
const observations = { dnsQueries: [], httpHosts: [], websocketHosts: [], tlsServerNames: [], tcpRequests: 0, tlsRequests: 0 };
const dns = dgram.createSocket('udp4');
dns.on('message', (packet, peer) => {
  if (packet.length < 17 || packet.readUInt16BE(4) !== 1) return;
  let offset = 12;
  const labels = [];
  while (offset < packet.length && packet[offset] !== 0) {
    const length = packet[offset++];
    if (length > 63 || offset + length >= packet.length) return;
    labels.push(packet.toString('ascii', offset, offset + length)); offset += length;
  }
  offset++;
  if (offset + 4 > packet.length) return;
  const name = labels.join('.').toLowerCase(), type = packet.readUInt16BE(offset);
  const known = name === 'fixture.example.com' || name === 'wrong.fixture.example.com';
  const answer = known && type === 1;
  observations.dnsQueries.push({ name, type });
  const header = Buffer.alloc(12);
  header.writeUInt16BE(packet.readUInt16BE(0), 0);
  header.writeUInt16BE(0x8400 | (packet.readUInt16BE(2) & 0x0100) | (known ? 0 : 3), 2);
  header.writeUInt16BE(1, 4); header.writeUInt16BE(answer ? 1 : 0, 6);
  const record = answer ? Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 215, 14]) : Buffer.alloc(0);
  dns.send(Buffer.concat([header, packet.subarray(12, offset + 4), record]), peer.port, peer.address);
});
const dnsReady = Promise.withResolvers(); dns.once('error', dnsReady.reject); dns.bind(53, '0.0.0.0', dnsReady.resolve); await dnsReady.promise;
const handler = (request, response) => {
  if (request.url === '/observations') { response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(observations)); return; }
  observations.httpHosts.push(request.headers.host);
  if (request.url === '/redirect-private') { response.writeHead(302, { Location: 'http://127.0.0.1/metadata' }); response.end(); return; }
  const send = () => { response.setHeader('Content-Type', 'text/plain'); response.end('TOMATOOK'); };
  if (request.url === '/slow') setTimeout(send, 1000); else send();
};
const clear = http.createServer(handler);
const secure = https.createServer({ key, cert }, handler);
secure.on('secureConnection', socket => observations.tlsServerNames.push(socket.servername));
const websockets = new WebSocketServer({ server: clear, path: '/ws', perMessageDeflate: false });
websockets.on('connection', (socket, request) => { socket.on('error', () => {}); observations.websocketHosts.push(request.headers.host); socket.once('message', () => socket.send('TOMATOOK')); });
const tcp = net.createServer(socket => { socket.on('error', () => {}); socket.once('data', () => { observations.tcpRequests++; socket.end('TOMATOOK'); }); });
const encrypted = tls.createServer({ key, cert }, socket => { socket.on('error', () => {}); observations.tlsServerNames.push(socket.servername); socket.once('data', () => { observations.tlsRequests++; socket.end('TOMATOOK'); }); });
for (const [server, port] of [[clear, 8081], [secure, 8443], [tcp, 9001], [encrypted, 9443]]) {
  const ready = Promise.withResolvers(); server.once('error', ready.reject); server.listen(port, '0.0.0.0', ready.resolve); await ready.promise;
}
console.log('Tomato controlled Docker fixture ready');
