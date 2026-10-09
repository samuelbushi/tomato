import { createDecipheriv, scryptSync } from 'node:crypto';
import { open, stat, mkdtemp, rm, readdir } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { options, safePath, mutablePath, privateInput, compose, run, startStack, deploymentIdentity } from './selfhost.mjs';
import { writeConfiguration } from './bootstrap.mjs';

const args = options(process.argv.slice(2));
let scratch;
try {
  if (Object.keys(args).some(key => !['state-dir', 'input', 'passphrase-file', 'confirm-empty-target', 'no-start'].includes(key)) || args['confirm-empty-target'] !== true || typeof args.input !== 'string' || typeof args['state-dir'] !== 'string' || typeof args['passphrase-file'] !== 'string') throw new Error('requires_input_passphrase_file_new_state_dir_and_confirm_empty_target');
  const state = await mutablePath(args['state-dir'], 'state');
  try { if ((await readdir(state)).length) throw new Error('restore_target_directory_must_be_empty'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const input = await safePath(args.input);
  const passphrase = await privateInput(args['passphrase-file']);
  if (passphrase.length < 16) throw new Error('backup_passphrase_requires_16_bytes');
  const size = (await stat(input)).size;
  if (size < 60) throw new Error('invalid_backup');
  const source = await open(input, 'r');
  const header = Buffer.alloc(36), tag = Buffer.alloc(16);
  try { await source.read(header, 0, 36, 0); await source.read(tag, 0, 16, size - 16); } finally { await source.close(); }
  if (header.subarray(0, 8).toString() !== 'TOMATOB1') throw new Error('invalid_backup_version');
  const decipher = createDecipheriv('aes-256-gcm', scryptSync(passphrase, header.subarray(8, 24), 32, { N: 32768, maxmem: 67_108_864 }), header.subarray(24, 36));
  decipher.setAAD(header); decipher.setAuthTag(tag);
  scratch = await mkdtemp(join(tmpdir(), 'tomato-restore-'));
  const plaintext = join(scratch, 'verified.backup');
  // Authenticate the complete ciphertext before any config, SQL or TLS restore.
  await pipeline(createReadStream(input, { start: 36, end: size - 17 }), decipher, createWriteStream(plaintext, { flags: 'wx', mode: 0o600 }));
  const verified = await open(plaintext, 'r');
  const length = Buffer.alloc(4);
  let metadata;
  let offset;
  try {
    await verified.read(length, 0, 4, 0);
    const bytes = length.readUInt32BE();
    if (bytes > 33_554_432 || bytes < 2) throw new Error('invalid_backup_metadata');
    const data = Buffer.alloc(bytes);
    const result = await verified.read(data, 0, bytes, 4);
    if (result.bytesRead !== bytes) throw new Error('invalid_backup_metadata');
    metadata = JSON.parse(data.toString()); offset = bytes + 4;
  } finally { await verified.close(); }
  if (metadata.version !== 1 || metadata.config.version !== 1 || !metadata.secrets || typeof metadata.caddyData !== 'string') throw new Error('invalid_backup_metadata');
  const config = { ...metadata.config, ...deploymentIdentity(state) };
  const secrets = {};
  const allowedSecrets = new Set(['postgres_password', 'db_password', 'auth_secret', 'data_key', 'engine_token', 'prober_token', 'owner_password', 'smtp_password', 'smtp_ca', 'github_client_secret', 'google_client_secret', 'legacy_pepper']);
  for (const [name, value] of Object.entries(metadata.secrets)) {
    if (!allowedSecrets.has(name) || typeof value !== 'string') throw new Error('invalid_backup_secret');
    secrets[name] = Buffer.from(value, 'base64');
  }
  for (const name of ['postgres_password', 'db_password', 'auth_secret', 'data_key', 'engine_token', 'prober_token', 'owner_password']) if (!secrets[name]?.length) throw new Error('missing_backup_secret');
  await writeConfiguration(state, config, secrets);
  const stack = await compose(state);
  await run('docker', [...stack.args, 'up', '--detach', '--wait', 'postgres']).done;
  const check = run('docker', [...stack.args, 'exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'tomato', '-At', '-c', "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p')"], { stdio: ['ignore', 'pipe', 'ignore'] });
  let tableCount = '';
  for await (const bytes of check.child.stdout) tableCount += bytes.toString();
  await check.done;
  if (tableCount.trim() !== '0') throw new Error('restore_database_must_be_empty');
  const restore = run('docker', [...stack.args, 'exec', '-T', 'postgres', 'pg_restore', '-U', 'postgres', '-d', 'tomato', '--no-owner', '--no-acl', '--exit-on-error', '--single-transaction'], { stdio: ['pipe', 'ignore', 'ignore'] });
  await Promise.all([pipeline(createReadStream(plaintext, { start: offset }), restore.child.stdin), restore.done]);
  const tls = run('docker', [...stack.args, 'run', '--rm', '--no-deps', '-T', '--entrypoint', 'sh', 'https', '-c', 'tar -xzf - -C /data'], { stdio: ['pipe', 'ignore', 'ignore'] });
  tls.child.stdin.end(Buffer.from(metadata.caddyData, 'base64'));
  await tls.done;
  await run('docker', [...stack.args, 'run', '--rm', '--build', 'migrate']).done;
  if (!args['no-start']) await startStack(stack);
  console.log('tomato_full_state_restore_complete');
} catch (error) { console.error(error.message); process.exitCode = 1; }
finally { if (scratch) await rm(scratch, { recursive: true, force: true }); }
