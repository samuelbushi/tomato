import { randomBytes, scryptSync, createCipheriv } from 'node:crypto';
import { readFile, readdir, appendFile, unlink } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { join } from 'node:path';
import { options, safePath, mutablePath, privateInput, compose, run } from './selfhost.mjs';

const args = options(process.argv.slice(2));
let output;
try {
  if (Object.keys(args).some(key => !['state-dir', 'output', 'passphrase-file'].includes(key)) || typeof args.output !== 'string' || typeof args['passphrase-file'] !== 'string') throw new Error('requires_output_and_passphrase_file');
  const state = await safePath(args['state-dir'] ?? 'selfhost');
  output = await mutablePath(args.output, 'file');
  const passphrase = await privateInput(args['passphrase-file']);
  if (passphrase.length < 16) throw new Error('backup_passphrase_requires_16_bytes');
  const stack = await compose(state);
  const secrets = {};
  for (const name of await readdir(await safePath(join(state, 'secrets')))) {
    if (!['postgres_password', 'db_password', 'auth_secret', 'data_key', 'engine_token', 'prober_token', 'owner_password', ...Object.values(stack.config.optionalSecrets)].includes(name)) throw new Error('unknown_backup_secret');
    secrets[name] = (await privateInput(join(state, 'secrets', name))).toString('base64');
  }
  const caddy = run('docker', [...stack.args, 'exec', '-T', 'https', 'tar', '-czf', '-', '-C', '/data', '.'], { stdio: ['ignore', 'pipe', 'ignore'] });
  const chunks = [];
  let size = 0;
  for await (const chunk of caddy.child.stdout) { size += chunk.length; if (size > 16_777_216) { caddy.child.kill(); throw new Error('https_state_too_large'); } chunks.push(chunk); }
  await caddy.done;
  const metadata = Buffer.from(JSON.stringify({ version: 1, createdAt: new Date().toISOString(), config: stack.config, secrets, caddyData: Buffer.concat(chunks, size).toString('base64') }));
  if (metadata.length > 33_554_432) throw new Error('backup_metadata_too_large');
  const salt = randomBytes(16), iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', scryptSync(passphrase, salt, 32, { N: 32768, maxmem: 67_108_864 }), iv);
  const header = Buffer.concat([Buffer.from('TOMATOB1'), salt, iv]);
  cipher.setAAD(header);
  const target = createWriteStream(output, { flags: 'wx', mode: 0o600 });
  let created = false;
  target.once('open', () => { created = true; });
  target.write(header);
  const length = Buffer.alloc(4); length.writeUInt32BE(metadata.length);
  cipher.write(length); cipher.write(metadata);
  const dump = run('docker', [...stack.args, 'exec', '-T', 'postgres', 'pg_dump', '-U', 'postgres', '-d', 'tomato', '--format=custom', '--no-owner', '--no-acl'], { stdio: ['ignore', 'pipe', 'ignore'] });
  try { await Promise.all([pipeline(dump.child.stdout, cipher, target), dump.done]); await appendFile(output, cipher.getAuthTag()); }
  catch (error) { dump.child.kill(); if (created) await unlink(output).catch(() => {}); throw error; }
  console.log('tomato_encrypted_backup_complete');
} catch (error) { console.error(error.message); process.exitCode = 1; }
