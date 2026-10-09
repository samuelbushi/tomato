import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve, dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lstat, realpath, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export function deploymentIdentity(state) {
  const hash = createHash('sha256').update(state).digest('hex');
  const third = Number.parseInt(hash.slice(0, 2), 16);
  const fourth = Number.parseInt(hash.slice(2, 4), 16) & 0xf0;
  return { project: `tomato-${hash.slice(0, 10)}`, frontendSubnet: `172.28.${third}.${fourth}/28`, proxyIP: `172.28.${third}.${fourth + 2}` };
}
export function frontendAllocationRange(config) {
  const subnet = config.frontendSubnet;
  const match = /^172\.28\.(\d{1,3})\.(\d{1,3})\/28$/.exec(subnet);
  if (!match || Number(match[1]) > 255 || Number(match[2]) > 240 || Number(match[2]) % 16 !== 0) throw new Error('invalid_frontend_subnet');
  // Reserve the lower half for fixed endpoints, including proxy subnet+2.
  return `172.28.${match[1]}.${Number(match[2]) + 8}/29`;
}
export function options(argv) {
  const value = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (!key.startsWith('--') || Object.hasOwn(value, key.slice(2))) throw new Error('invalid_or_duplicate_argument');
    value[key.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
  }
  return value;
}
export async function safePath(input) {
  const path = resolve(input);
  const forbidden = /(?:^|[/\\])(?:\.tomato-local|\.tomato-dev|\.wrangler|Library[/\\]Application Support[/\\]Tomato)(?:[/\\]|$)/i;
  const protectedRoots = [join(root, 'private'), join(homedir(), 'Library', 'Application Support', 'Tomato')];
  if (forbidden.test(path) || protectedRoots.some(dir => path === dir || path.startsWith(`${dir}${sep}`))) throw new Error('protected_path_not_allowed');
  let cursor = path;
  let canonical;
  while (true) {
    try {
      const info = await lstat(cursor);
      if (info.isSymbolicLink() && (cursor === path || cursor.startsWith(`${root}${sep}`))) throw new Error('symlink_path_not_allowed');
      const actual = await realpath(cursor);
      if (forbidden.test(actual) || protectedRoots.some(dir => actual === dir || actual.startsWith(`${dir}${sep}`))) throw new Error('protected_path_not_allowed');
      canonical ??= join(actual, relative(cursor, path));
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(cursor) === cursor) break;
    cursor = dirname(cursor);
  }
  return canonical ?? path;
}
export async function mutablePath(input, purpose = 'state') {
  const path = await safePath(input);
  if (path === root || path === homedir() || path === dirname(path)) throw new Error('unsafe_mutable_destination');
  if (path.startsWith(`${root}${sep}`) && !['selfhost', '.tomato-production', '.tomato-backups', 'backups'].includes(relative(root, path).split(sep)[0])) throw new Error('mutable_repository_path_not_allowed');
  try {
    const info = await lstat(path);
    if (purpose === 'state' && (!info.isDirectory() || (info.mode & 0o077) !== 0 || process.getuid && info.uid !== process.getuid())) throw new Error('state_requires_private_owned_directory');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return path;
}
export function run(command, args, { stdio = 'inherit', env = process.env } = {}) {
  const child = spawn(command, args, { cwd: root, env, stdio });
  const done = new Promise((resolveDone, reject) => {
    child.once('error', reject);
    child.once('exit', code => code === 0 ? resolveDone() : reject(new Error('operation_failed')));
  });
  return { child, done };
}
export async function compose(state) {
  const config = JSON.parse(await readFile(await safePath(join(state, 'config.json')), 'utf8'));
  const args = ['compose', '--env-file', join(state, 'compose.env'), '-f', join(root, 'compose.yaml'), '-f', join(state, 'compose.override.json')];
  return { config, args, state };
}
export async function startStack(stack) {
  await run('docker', [...stack.args, 'up', '--build', '--detach', '--wait', '--wait-timeout', '180', 'app']).done;
  // A network-policy change may leave an old stopped proxy container without
  // its declared static address. Recreate only that owned edge, never the DB.
  await run('docker', [...stack.args, 'up', '--detach', '--no-deps', '--force-recreate', '--wait', '--wait-timeout', '180', 'https']).done;
}
export async function privateInput(path) {
  const source = await safePath(path);
  const info = await lstat(source);
  if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > 16_384) throw new Error('secret_input_requires_private_file');
  const bytes = await readFile(source);
  if (!bytes.length) throw new Error('empty_secret_input');
  return bytes;
}
