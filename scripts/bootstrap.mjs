import { randomBytes } from 'node:crypto';
import { mkdir, writeFile, readFile, chmod, appendFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { options, safePath, mutablePath, privateInput, compose, startStack, deploymentIdentity, frontendAllocationRange } from './selfhost.mjs';

export async function writeConfiguration(state, config, secrets) {
  state = await mutablePath(state, 'state');
  await mkdir(state, { recursive: true, mode: 0o700 });
  await chmod(state, 0o700);
  await mkdir(join(state, 'secrets'), { mode: 0o700 });
  await chmod(join(state, 'secrets'), 0o700);
  for (const [name, bytes] of Object.entries(secrets)) await writeFile(join(state, 'secrets', name), bytes, { mode: 0o600, flag: 'wx' });
  const env = { TOMATO_STATE_DIR: state, TOMATO_PROJECT_NAME: config.project, TOMATO_ORIGIN: config.origin, TOMATO_MODE: config.mode,
    TOMATO_OWNER_EMAIL: config.ownerEmail, TOMATO_OWNER_NAME: config.ownerName, TOMATO_OWNER_EMAIL_VERIFIED: String(config.ownerEmailVerified),
    TOMATO_ACCOUNT_ID: config.accountId, TOMATO_ACCOUNT_NAME: config.accountName, TOMATO_HTTPS_BIND: config.bind,
    TOMATO_FRONTEND_SUBNET: config.frontendSubnet, TOMATO_FRONTEND_IP_RANGE: frontendAllocationRange(config), TOMATO_PROXY_IP: config.proxyIP, ...config.settings };
  for (const value of Object.values(env)) if (/[\r\n\0]/.test(String(value))) throw new Error('invalid_configuration_value');
  await writeFile(join(state, 'compose.env'), Object.entries(env).map(([key, value]) => `${key}='${String(value).replace(/'/g, "\\'")}'`).join('\n') + '\n', { mode: 0o600, flag: 'wx' });
  const overrides = { services: { app: { secrets: [], environment: {} } }, secrets: {} };
  for (const [key, name] of Object.entries(config.optionalSecrets)) {
    overrides.secrets[name] = { file: join(state, 'secrets', name) };
    overrides.services.app.secrets.push(name);
    overrides.services.app.environment[key] = `/run/secrets/${name}`;
  }
  await writeFile(join(state, 'compose.override.json'), JSON.stringify(overrides, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  const localTLS = new URL(config.origin).hostname.endsWith('.localhost') || new URL(config.origin).hostname === 'localhost';
  await writeFile(join(state, 'Caddyfile'), `${config.origin} {\n${localTLS ? '  tls internal\n' : ''}  reverse_proxy app:3000 {\n    header_up X-Tomato-Client-IP {remote_host}\n  }\n}\n`, { mode: 0o600, flag: 'wx' });
  await writeFile(join(state, 'config.json'), JSON.stringify(config, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
}

export async function bootstrap(argv) {
  const args = options(argv);
  const allowed = ['origin', 'owner-email', 'owner-name', 'owner-password-file', 'owner-email-verified', 'account-id', 'account-name', 'mode', 'state-dir', 'configure-only', 'https-bind'];
  if (Object.keys(args).some(key => !allowed.includes(key))) throw new Error('unknown_argument');
  for (const key of ['origin', 'owner-email', 'owner-name', 'owner-password-file']) if (typeof args[key] !== 'string') throw new Error(`required_${key}`);
  const origin = new URL(args.origin);
  if (origin.protocol !== 'https:' || origin.origin !== args.origin || origin.username || origin.password || origin.port && origin.port !== '443') throw new Error('origin_requires_canonical_https');
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(args['owner-email']) || args['owner-email'].length > 254 || args['owner-name'].length > 120) throw new Error('invalid_owner');
  const mode = args.mode ?? 'self-host';
  if (!['self-host', 'hosted'].includes(mode)) throw new Error('invalid_mode');
  const state = await mutablePath(args['state-dir'] ?? join('selfhost'), 'state');
  const password = await privateInput(args['owner-password-file']);
  const passwordText = password.toString('utf8').replace(/\r?\n$/, '');
  if (passwordText.length < 14 || passwordText.length > 256) throw new Error('owner_password_requires_14_to_256_characters');
  const settings = {};
  for (const key of ['TOMATO_SMTP_HOST', 'TOMATO_SMTP_PORT', 'TOMATO_SMTP_SECURE', 'TOMATO_SMTP_USER', 'TOMATO_EMAIL_FROM', 'TOMATO_GITHUB_CLIENT_ID', 'TOMATO_GOOGLE_CLIENT_ID', 'TOMATO_SIGNUP_ENABLED', 'TOMATO_LEGACY_CUTOVER_EXPIRES_AT']) {
    if (process.env[key]) settings[key] = process.env[key];
  }
  if (!settings.TOMATO_SMTP_HOST && args['owner-email-verified'] !== true) throw new Error('without_smtp_explicit_owner_email_verified_attestation_required');
  const optionalSecrets = {};
  const supplied = {};
  for (const [key, name] of Object.entries({ TOMATO_SMTP_PASSWORD_FILE: 'smtp_password', TOMATO_SMTP_CA_FILE: 'smtp_ca', TOMATO_GITHUB_CLIENT_SECRET_FILE: 'github_client_secret', TOMATO_GOOGLE_CLIENT_SECRET_FILE: 'google_client_secret', TOMATO_LEGACY_PEPPER_FILE: 'legacy_pepper' })) {
    if (process.env[key]) { optionalSecrets[key] = name; supplied[name] = await privateInput(process.env[key]); }
  }
  if (settings.TOMATO_SMTP_HOST && !settings.TOMATO_EMAIL_FROM || settings.TOMATO_SMTP_USER && !supplied.smtp_password) throw new Error('incomplete_smtp_configuration');
  for (const provider of ['GITHUB', 'GOOGLE']) if (Boolean(settings[`TOMATO_${provider}_CLIENT_ID`]) !== Boolean(optionalSecrets[`TOMATO_${provider}_CLIENT_SECRET_FILE`])) throw new Error('incomplete_oauth_configuration');
  if (Boolean(settings.TOMATO_LEGACY_CUTOVER_EXPIRES_AT) !== Boolean(supplied.legacy_pepper)) throw new Error('incomplete_legacy_cutover_configuration');
  const config = { version: 1, ...deploymentIdentity(state), origin: args.origin, mode,
    ownerEmail: args['owner-email'], ownerName: args['owner-name'], ownerEmailVerified: args['owner-email-verified'] === true,
    accountId: args['account-id'] ?? 'main', accountName: args['account-name'] ?? 'Tomato', bind: args['https-bind'] ?? (origin.hostname.endsWith('.localhost') ? '127.0.0.1' : '0.0.0.0'), settings, optionalSecrets };
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(config.accountId) || !/^(?:127\.0\.0\.1|0\.0\.0\.0)$/.test(config.bind) || !config.accountName || config.accountName.length > 120) throw new Error('invalid_account_or_bind');
  let existing;
  try { existing = JSON.parse(await readFile(await safePath(join(state, 'config.json')), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (existing) {
    if (JSON.stringify(existing) !== JSON.stringify(config)) throw new Error('existing_configuration_differs');
    const original = (await privateInput(join(state, 'secrets', 'owner_password'))).toString('utf8');
    if (original !== passwordText) throw new Error('bootstrap_does_not_reset_owner_password');
    for (const [name, bytes] of Object.entries(supplied)) if (!(await privateInput(join(state, 'secrets', name))).equals(bytes)) throw new Error('existing_secret_differs');
    const envPath = await safePath(join(state, 'compose.env'));
    const envText = (await privateInput(envPath)).toString('utf8');
    const allocationLine = `TOMATO_FRONTEND_IP_RANGE='${frontendAllocationRange(config)}'`;
    const currentLine = envText.split('\n').find(line => line.startsWith('TOMATO_FRONTEND_IP_RANGE='));
    if (currentLine && currentLine !== allocationLine) throw new Error('existing_network_configuration_differs');
    if (!currentLine) await appendFile(envPath, `${envText.endsWith('\n') ? '' : '\n'}${allocationLine}\n`);
  } else {
    const secrets = { ...supplied, owner_password: passwordText };
    for (const name of ['postgres_password', 'db_password', 'auth_secret', 'engine_token', 'prober_token']) secrets[name] = randomBytes(48).toString('base64url');
    secrets.data_key = randomBytes(32).toString('base64');
    await writeConfiguration(state, config, secrets);
  }
  if (!args['configure-only']) {
    const stack = await compose(state);
    await startStack(stack);
  }
  console.log(`tomato_${args['configure-only'] ? 'configured' : 'ready'} origin=${config.origin} mode=${mode}`);
  if (origin.hostname.endsWith('.localhost')) console.log('Local HTTPS uses the persistent Caddy internal CA; trust its public root certificate on each client. No system trust settings are changed automatically.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) bootstrap(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
