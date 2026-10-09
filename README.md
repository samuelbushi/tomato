# Tomato

Tomato is an Apache-2.0 monitoring product built with TypeScript, Node.js, PostgreSQL and Better Auth. The open-source self-hosted distribution and hosted mode use the same monitoring engine, permissions, native web interface, API and MCP management tools.

Self-hosting does **not** require a Cloudflare/Appwrite account, remote activation, a paid license or purchased Tomato credits. Infrastructure, domain and optional mail/OAuth providers are chosen and operated by you.

## Release and hosted-service status

This source tree contains the new portable Node/PostgreSQL runtime. It does not automatically deploy, migrate or replace an existing service. The existing hosted service at <https://tomato.objectivecompany.workers.dev/> still runs the previous Cloudflare release; no portable hosted cutover has occurred.

As of 2026-10-09, an immutable Linux/amd64 package is staged on the authorized host with private HTTPS, no published host ports and monitoring workloads disabled. Real PostgreSQL/HTTP/SMTP acceptance and native no-JavaScript login/enrollment rendering have been exercised. One explicitly authorized mail canary was SMTP-provider-accepted; inbox receipt was not observed. The new public hostname/tunnel is not active and no existing customer state has been imported. Live replacement remains withheld until actual pre-patch external writes/deliveries are settled or fenced; deployment percentage or a claimed zero-in-flight count is not that proof.

Commercial signup and payment processing are not enabled by this release. Hosted mode has the shared monitoring product and an enforced eligible-work credit ledger, not a simulated checkout or an approved retail offering. A commercial launch still needs an authorized host/domain/cutover, approved sender and OAuth applications where used, merchant/payment configuration, prices and applicable legal policies. No price, SLA, geographic independence, measured production capacity or lowest-cost claim is made here.

## Monitoring and management

- **HTTP/HTTPS:** GET/HEAD checks with status and bounded literal-body assertions, private request headers, bounded redirects and authenticated HTTPS certificate evidence.
- **DNS:** bounded record assertions through a DNS-over-HTTPS resolver.
- **WebSocket:** real handshakes and optional bounded send/expect assertions.
- **TCP and TLS:** real socket connections and optional bounded send/expect assertions; TLS authenticates the peer certificate.
- **Heartbeat:** a private job-pulse endpoint with explicit deadlines and idempotency; a missing pulse is not fabricated success.
- Durable incidents and recovery, temporal confirmation, evidence freshness, maintenance windows, acknowledgement, coverage and duration-based availability reports.
- Configurable signed webhooks and email alerts, explicit real delivery tests, bounded retries and retained delivery outcomes.
- Multiple workspaces, owner/editor/viewer roles, email-bound invitations, expiring account-bound API keys and revocable delegation chains.
- Opt-in public status pages expose selected components only. Revision-fenced editing and unpublish tombstones reject stale editors, including deletion/recreation races.
- Server-rendered, square grey/blue, old-Windows-style UI. Core native forms work without optional JavaScript; the optional monitor filter is an enhancement.
- The same authoritative operations are available through the JSON API and MCP. Read/write/manage key scope never substitutes for current workspace membership or owner permission.

New or stale unsupported evidence is `UNKNOWN`, never assumed healthy. Confirmation is temporal, not a second geographic location. The public status page shares the deployment's infrastructure; it is not independent disaster coverage.

Production outbound probe connection destinations, including resolved addresses and redirects, must be permitted **public IPs**. Private, loopback, link-local and internal destinations are rejected before connection; neither self-hosted nor hosted mode provides a private-LAN monitoring exception. Controlled private acceptance fixtures are not a production network-policy bypass.

## Self-hosted versus hosted usage

In **self-host** mode, eligible usage is recorded for visibility but there is no paid credit balance, depletion cutoff or mandatory purchase. The engine rejects credit deposits in this mode. The complete monitoring and management feature set remains available.

In **hosted** mode, one credit is consumed for each accepted eligible primary target observation, including a target failure or timeout, and each unique accepted heartbeat pulse. Confirmation, unknown/internal outcomes, cancelled work, missed slots and alert delivery retries consume none. An operator-issued testing grant is auditable; it is not a customer payment. Payment processing and retail pricing are separate launch prerequisites, not implied by the meter.

## Requirements

The supported packaged setup uses:

- Node.js **24 or later** and npm for the operator scripts;
- Docker Engine with a working Docker Compose plugin;
- the supplied Node application/prober images, **PostgreSQL 18** and Caddy;
- an owned writable private state directory and ports 80/443 on the chosen bind address;
- for a public domain, correct DNS and reachable TLS issuance ports;
- only the optional providers you actually configure.

The application database, internal RPC and trusted HTTPS proxy are private container networks. Only Caddy publishes HTTP/HTTPS ports. The production Node entrypoint requires the explicit trusted proxy and rejects test mode; do not expose the internal application or prober listener directly.

A local Docker VM must be able to mount your chosen state directory. Docker credential helpers and Compose/build plugins are prerequisites of your Docker installation, not credentials Tomato should copy or rewrite. No global Docker, OS certificate-trust or browser-profile settings are changed automatically.

### Native Node service contract

The same source can run as native Node services: `npm ci`, then `npm run migrate` for schema/role initialization and `npm start` for the application. This is an advanced operator-managed path, not an automatic public-host deployment. Provide an existing dedicated PostgreSQL database, a real HTTPS reverse proxy, isolated prober service and process supervision; do not expose an application HTTP listener or prober RPC to the public network. The secure automated install/upgrade/full-backup commands below manage the supplied Compose package, not arbitrary independently supervised native services.

The native application configuration is read by [`src/config.ts`](src/config.ts) and [`src/server.ts`](src/server.ts):

- PostgreSQL: `PGHOST`, `PGPORT`, `PGDATABASE`; the application uses the fixed non-bypass `tomato_app` role with `TOMATO_DB_PASSWORD_FILE`. Migration additionally uses `PGADMIN_USER` and `POSTGRES_PASSWORD_FILE`, creates that role if absent and applies the tracked migrations/grants. Stop on a migration error. Do not give the running application the administrator password.
- Database TLS: `PGSSLMODE=verify-full` (default), optionally `PGSSL_CA_FILE`. `disable` is accepted only for explicit private/local `postgres`/`localhost`/loopback hosts; a remote database requires verified TLS.
- Private regular secret files: `TOMATO_AUTH_SECRET_FILE`, `DATA_KEY_FILE`, `TOMATO_ENGINE_TOKEN_FILE` and `TOMATO_PROBER_TOKEN_FILE`, containing independently generated strong secrets (a 32-byte hex data key). Keep file/directory permissions at `0600`/`0700`, outside source control.
- Canonical HTTPS and proxy: `TOMATO_ORIGIN`, `TOMATO_HTTPS_PROXY=true`, exact comma-separated `TOMATO_TRUSTED_PROXY_IPS`, and a private `TOMATO_BIND_HOST` (default `127.0.0.1`) / `PORT` (default `3000`). Public HTTP binding is rejected; `0.0.0.0` is accepted only with explicit `TOMATO_INTERNAL_NETWORK=true` in an isolated network. The reverse proxy must retain the canonical Host and set the genuine `X-Tomato-Client-IP`; arbitrary forwarded headers are discarded.
- Mode and first owner: `TOMATO_MODE=self-host` (default) or `hosted`; `TOMATO_OWNER_EMAIL`, `TOMATO_OWNER_NAME`, `TOMATO_OWNER_PASSWORD_FILE`, optional `TOMATO_ACCOUNT_ID`/`TOMATO_ACCOUNT_NAME`, and the intentional `TOMATO_OWNER_EMAIL_VERIFIED=true` attestation only when appropriate. Retain those inputs through upgrades; the durable completion marker is not an owner-reset mechanism.
- Prober: set the application's private `TOMATO_PROBER_URL` to its `/execute` endpoint. Run `node container/server.mjs` separately with `NODE_ENV=production`, `TOMATO_CONTAINER_SERVER=1` and only its private `TOMATO_PROBER_TOKEN_FILE`. That service listens on port 8080; isolate it with the operator's network/firewall policy. Do not pass database, identity, owner, mail, OAuth or engine credentials to that process; its production guard rejects them. Never enable `TEST_MODE` or test-transport flags in production.
- Optional SMTP, signup and OAuth use the settings below.
- Optional authenticated legacy transport: `TOMATO_GATEWAY_SOURCE_ORIGIN`, `TOMATO_GATEWAY_KEY_ID` and a private `TOMATO_GATEWAY_KEY_FILE` containing a canonical base64url 32-byte key. Configure the reviewed source gateway separately and invoke it only after a persisted single-owner cutover. Native ingress verifies the trusted proxy, signed request bytes/context, 30-second freshness and PostgreSQL replay admission before ordinary API/MCP authentication. Invalid or unconfigured attestations never fall back to direct ingress; duplicate critical headers are rejected. Keep the original operator token when preserving existing operator clients. This transport key grants no user/operator authority and is independent of temporary migration-control expiry. Revoke or rotate it explicitly; Worker-origin callers share an opaque address, not attributed visitor IPs.

Native Node/PostgreSQL operation is exercised with controlled disposable endpoints. The supplied production entrypoints are also exercised in Linux containers. A separately supervised native public Linux host, its firewall/TLS issuance and an operator-specific native recovery procedure have not been deployed or accepted here.

## Secure first run

Obtain this source checkout, enter its directory and install its locked dependencies:

```sh
npm ci
```

Create a private password file using your password manager or another secure local method. It must be a regular private file (mode `0600`), contain a password of at least 14 characters, be at most 256 UTF-8 bytes, and not live in a protected pilot configuration path. Do not put the password in a URL, command-line argument, public issue or repository.

Use your actual owner email and name. For an isolated local deployment:

```sh
npm run bootstrap -- \
  --origin https://tomato.localhost \
  --owner-email owner@example.org \
  --owner-name "Your actual name" \
  --owner-password-file /absolute/private/owner-password \
  --owner-email-verified \
  --state-dir /absolute/private/tomato-state \
  --mode self-host \
  --https-bind 127.0.0.1
```

Replace the example email and paths. `--owner-email-verified` is an explicit operator attestation, not proof that mail was sent. Without SMTP, that attestation is required for the initial owner; email signup, verification and password reset remain unavailable. With an approved configured SMTP sender, omit the attestation if the owner should complete real email verification.

Bootstrap generates private deployment secrets, a 32-byte data-encryption key, private configuration, an isolated Compose project, the database role/schema, the initial owner and workspace, and starts the actual services. State/secrets directories are `0700`; generated secret/configuration files are `0600`. It does not create a paid wallet for self-hosting, reset an existing owner's password, or automatically enable customer signup. `--configure-only` prepares configuration without starting services.

For `localhost`/`.localhost`, Caddy uses a persistent internal CA. Trust **only its public root certificate** on the intended client through your normal certificate-trust process before using local HTTPS. Do not export or share its private keys. Public-domain deployments use Caddy's normal TLS issuance path; use an authorized domain and bind address, not another party's host. Actual public-domain issuance and hosted cutover have not been exercised as part of the local acceptance.

After the ready message, open your configured origin and sign in. Add an HTTP URL directly or use Advanced setup for all six protocol families. A monitor begins `UNKNOWN` until a real observation or job pulse is accepted. Configure alerts only when you intend an external send; the test button sends a real alert to the configured destination.

## Optional email, signup and OAuth

Configure approved providers **before the initial bootstrap**, using environment settings and private input files. No provider account is created, OAuth app registered, mail sent to an unapproved recipient or merchant product created automatically.

| Capability | Bootstrap environment |
| --- | --- |
| SMTP | `TOMATO_SMTP_HOST`, `TOMATO_SMTP_PORT`, `TOMATO_SMTP_SECURE`, optional `TOMATO_SMTP_USER`, `TOMATO_SMTP_PASSWORD_FILE`, approved `TOMATO_EMAIL_FROM` |
| Scoped SMTP CA | Optional `TOMATO_SMTP_CA_FILE`; a private input file for that configured connection, not a global TLS bypass |
| Shared SMTP attempt budget | Optional paired `TOMATO_SMTP_DAILY_LIMIT` / `TOMATO_SMTP_HOURLY_LIMIT`; durable UTC day/hour admission shared by auth and alerts, not a provider-enforced sender restriction or a feature paywall |
| Email signup | `TOMATO_SIGNUP_ENABLED=true`, plus working SMTP; verification completes before normal email login |
| GitHub OAuth | `TOMATO_GITHUB_CLIENT_ID` and `TOMATO_GITHUB_CLIENT_SECRET_FILE` |
| Google OAuth | `TOMATO_GOOGLE_CLIENT_ID` and `TOMATO_GOOGLE_CLIENT_SECRET_FILE` |

Register exact callback URLs for the configured canonical origin: `/api/auth/callback/github` and `/api/auth/callback/google`. Use the intended approved provider account, application and scopes. Missing or incomplete provider configuration does not become a fake successful login. Auth uses Better Auth's real email/password and OAuth implementations; native signup, verification, reset and logout are not mock forms.

Without those paired limits, self-hosted mail is not quota-gated by Tomato. An operator sharing a provider account must explicitly allocate a conservative portion of its account-wide quota; other applications' sends are not visible to Tomato. Each real one-recipient SMTP envelope reserves a durable slot before delivery, and failures consume it because acceptance may be ambiguous. Exhausted global budgets and unavailable SMTP fail uniformly before reset/resend account lookup.

An accepted public password-recovery request always gives a neutral receipt: it confirms neither account existence nor email delivery. A message-specific rejection or concurrent budget race is privately logged by the maintained callback, consumes its actual reserved slot, and does not make known contacts distinguishable from unknown contacts. Credential-proved enrollment and owner-authorized invitation registration instead observe actual callback failure through a request-scoped wrapper, fail honestly and never mark an undelivered enrollment candidate sent. Alert failures retain their real durable delivery outcome and ordinary configured retry policy.

An invitation whose first verification email fails retains its unverified identity and original password. Reopening that same invitation exposes a resend form; use the original password, not a replacement. Membership is granted only after actual email verification and acceptance under the invitation's current role. SMTP admission uses an independently committed, one-connection pool with the deployment's actual database credentials, so a maintained signup transaction can hold the last main connection without starving mail admission.

The CLI copies optional secret files into the private state directory. Do not commit them. A subsequent bootstrap rejects configuration/secret drift rather than silently rewriting an existing installation. Keep the original invocation and provider settings in private operator notes; plan any intentional configuration change with a backup and review.

## Permissions, API and MCP

Owners control membership and public publication; editors operate monitors; viewers read. The last owner cannot be removed or demoted. Native sessions use Secure, HttpOnly, SameSite=Lax, host-only cookies in production HTTPS and CSRF/origin checks for mutations. The observed Better Auth cookie uses the `__Secure-` prefix; no `__Host-` prefix guarantee is claimed.

The deployment data key authenticated-encrypts monitoring HTTP request headers, webhook signing secrets, account-default delivery configuration and retained delivery intents. API and heartbeat tokens are stored as hashes; Better Auth maintains password hashes separately. This is not a generic secret vault: target URLs, TCP/TLS send data and assertion fields are not covered by that encryption claim, so do not embed credentials there. Saved header/signing values are not redisplayed by monitor forms, management reads or public pages; one-time issued credentials must be stored privately. Keep the data key with the full encrypted backup: a configuration-only export cannot restore it.

Create an API key from the workspace's API keys page, choose the narrowest scope and expiry, and store its one-time value privately. Keys are account-bound. Descendants cannot exceed their source's authority or lifetime; revoking an ancestor revokes descendants. `manage` includes sensitive personal security operations but does not grant another user's account or owner role.

Authenticated API documentation is available at `/app/accounts/<accountId>/api-docs`. Examples of the real JSON routes are:

```text
GET  /api/session
GET  /api/capabilities
GET  /api/accounts/<accountId>/state
GET  /api/accounts/<accountId>/usage
POST /api/accounts/<accountId>/monitors
POST /api/accounts/<accountId>/monitors/<monitorId>/check-now
GET  /api/accounts/<accountId>/export
POST /api/accounts/<accountId>/monitors/import
```

API-key clients use `Authorization: Bearer <private key>`. Native-cookie mutations require the session CSRF token and correct origin. Monitor, maintenance and publication mutations require their current revisions; do not discard conflict errors. Configuration export is redacted, and importing a heartbeat configuration issues a new pulse token; neither is a full recovery backup.

MCP is served at `/mcp` using Streamable HTTP. Supported revisions are `2026-07-28` and `2025-11-25`; discover the actual authorized tools/schemas rather than inventing tool names. The installed SDK's real HTTP and stdio lifecycle is exercised by `verify:mcp`.

For an MCP client that requires stdio, use a source checkout with **`npm ci` including development dependencies** (the MCP SDK is required by the bridge). Create a private regular `0600` environment file containing `TOMATO_MCP_URL` (your configured HTTPS origin plus `/mcp`) and `TOMATO_API_KEY` (the privately issued account key). Supply those values through a secure local editor/client setting, not an inline shell command or checked-in file.

```sh
node --env-file=/absolute/private/tomato-agent.env scripts/agent-stdio.ts
```

The bridge permits HTTP only for loopback development; a non-loopback endpoint requires HTTPS. This is a source-checkout command, not a claimed command inside the application image. If you use the local internal CA, trust its public root in that task/client process; do not disable certificate verification or change a shared browser profile.

## Upgrade without resetting identity

Make and verify a full encrypted backup before upgrading. Retain the original private bootstrap inputs/settings and obtain the intended reviewed source version. Run `npm ci`, then re-run the original bootstrap command with the same configuration and secret inputs.

The startup path rebuilds the application/prober and applies checksum-tracked SQL migrations before the application starts, then recreates only the owned HTTPS edge when needed to re-establish its exact trusted address. PostgreSQL is not force-recreated. The durable bootstrap-completion marker preserves legitimate subsequent owner transfers, password/name changes and membership changes; rerunning bootstrap is not a password reset or re-promotion of the initial owner.

Keep state paths, secrets and volumes. Do not use `down --volumes`, delete the state directory, replace the data key or restore over an existing database as an upgrade shortcut. Database migration failures and checksum conflicts are release failures to resolve, not warnings to suppress.

## Full encrypted backup and restore

Choose a new output path and a private passphrase file containing at least 16 bytes. Keep the passphrase separately from the archive. While the source stack is available:

```sh
npm run backup -- \
  --state-dir /absolute/private/tomato-state \
  --output /absolute/private/backups/tomato.tomato-backup \
  --passphrase-file /absolute/private/backup-passphrase
```

The `TOMATOB1` archive contains an actual PostgreSQL custom-format dump, deployment configuration/secrets including the data key, and persistent Caddy HTTPS state. It uses scrypt-derived AES-256-GCM authenticated encryption and a new private `0600` output file. It is not just a monitor configuration export. Treat the archive/passphrase as sensitive recovery material even when encrypted, and maintain off-host retention and tested recovery procedures.

Restore into a **new empty private state directory and empty database**, never the existing source. If source and destination use the same host ports, stop only the source's own Compose project first, retaining its volumes and backup.

```sh
npm run restore -- \
  --input /absolute/private/backups/tomato.tomato-backup \
  --passphrase-file /absolute/private/backup-passphrase \
  --state-dir /absolute/private/tomato-restored \
  --confirm-empty-target
```

Restore authenticates the complete archive before writing target configuration or starting database/TLS recovery, assigns a new isolated project identity, checks the target database is empty, restores the complete dump and HTTPS state, applies migrations and starts the actual stack. `--no-start` stops short of starting the application; it is not end-to-end recovery proof.

A successful restore must include actual login/permissions, preserved usage/history/keys, and real monitoring/alert delivery from restored stored secrets. Keep the original stopped source until the recovered instance has been accepted; do not run two copies accidentally against the same workload or ports.

## Data-preserving legacy cutover

The previous username-only pilot uses peppered scrypt credentials. An approved private identity/engine export and private verifier/pepper custody are still required, but an advance contact CSV is **not**. Optional `--email-map` entries must be actual approved contacts. Unmapped usernames import into stable product identities, not fabricated or nullable Better Auth users. An append-only migration atomically backfills existing modern IDs and retargets membership, API-key and MCP foreign keys to those product identities.

Stage `npm run identity:import` before `npm run engine:import` while the destination application is stopped. Both consume private approved `--export` files and enforce an empty target; engine import additionally requires `--confirm-empty-target`. Identity import requires `--pepper-file`, an explicit `--expires-at` timestamp initially at most 30 days ahead, and `--acknowledge-session-invalidation`. Original cookie sessions are invalidated; stable user/account IDs, current roles, existing key hashes and delegation parents remain intact. Engine import preserves monitors, wallet/usage/reservations, retained history/archive bytes and encrypted account secrets; no counter or empty replacement workspace is fabricated.

Two deliberately different credential boundaries apply:

- **Mapped full-login compatibility:** old credentials in Better Auth can authorize maintained login only before the approved absolute bridge deadline. Success rehashes them. Expiry never prevents healthy modern startup, monitoring/API work or ordinary verified-email recovery. Do not arbitrarily extend this full-login deadline.
- **Unmapped restricted enrollment:** `/enroll` accepts the original username/password only as proof for a rate-limited, 30-minute claim cookie. It cannot open an app session, mint keys/credits or access workspace data. This restricted proof remains available after the mapped bridge expires so an infrequent user with no registered contact is not orphaned on day 31. The user provides an actual maintained-schema email, receives a genuine SMTP verification link and confirms it in the original claim browser. Expired claims require fresh proof, not a password reset.

Successful contact verification atomically creates a normal verified Better Auth credential user at the **original ID**, hashes the **unchanged original password** using Better Auth (including previously valid shorter passwords), and deletes the old verifier and every outstanding claim. Memberships, API-key lineage, workspace ownership, monitor history and balance are unchanged. Existing-email collisions fail rather than merging identities; automatic OAuth linking remains disabled. A subsequent deliberate maintained password reset retains its normal session/key revocation policy.

Unmapped invitations preserve the original invitation ID, token hash, targeted username, role, status and expiry. An existing legacy username still requires its own original password proof. For an invitation-only unregistered target, possession of its unchanged active token authorizes only new-user contact enrollment for that exact target. Real email verification and the original claim context consume that invitation and join exactly its workspace/current role; no blank personal workspace or replacement invitation is created. Revoked, expired, wrong-target, existing-email and replay attempts fail.

The custody tradeoff is explicit: until an unmapped identity enrolls or its proof authority is deliberately retired, its legacy verifier and the original separate pepper remain private migration material. Tokens are stored as hashes; the short-lived claim stores only a maintained password hash, never plaintext credentials. Keep databases/backups private and the pepper in its approved secret file. `identity:import -- --finalize` refuses to retire the legacy bridge while any imported legacy credential or unmapped credential proof remains. Invitation-only claims need no pepper. Do not invent contacts, reset original credentials, expose exports or substitute synthetic acceptance data for the live dataset.

For safe staging, `TOMATO_WORKLOADS_ENABLED=false` leaves monitoring configuration/revisions/paused flags intact while disabling scheduler/outbox execution, engine writes, incoming heartbeat debits and manual checks/alerts; read-only engine requests do not advance maintenance state. Normal operation defaults to enabled. This is **not** a read-only identity service: stage only a separate owned synthetic database, never a mutable preliminary copy of real customer state. The advanced imported-owner runtime can start without owner-bootstrap variables; the secure first-run self-host CLI still requires its genuine initial owner. Keep staging restricted until the approved final empty-target import and activation.

An authorized live migration must quiesce **all source writes** and drain in-flight work before its final snapshot/export: identity/domain mutations, cron/alarms, queues, completions and outbox/dispatch, not merely the cron trigger. Do not start destination workloads while any source engine can still check, debit or deliver. A preliminary copy taken while source work continues is not the final cutover dataset. Verify the deployed source's actual export/quiesce capabilities and retain its version, bindings and encrypted rollback material before any source change; the offline import commands do not themselves provide those missing source capabilities.

These commands do not authorize or perform a live protected export, a new host deployment, email mapping, DNS change, customer charge or production cutover. During an approved final-snapshot/cutover plan, only the read-only old portal may remain available while its scheduler and outbox/dispatch stay quiesced; do not keep the old engine executing or charging alongside destination workloads. Retain the source data and rollback material until complete destination acceptance succeeds.

## Development and acceptance

Use a new disposable local PostgreSQL database/role and controlled synthetic accounts/endpoints. The Node/PostgreSQL suites create their own non-bypass roles and never reset a shared database. Real TLS acceptance fixtures also require an available `openssl` executable; `verify:container` requires working Docker. Configure `TEST_DATABASE_ADMIN_URL` and the required local PostgreSQL credentials privately; do not embed a password in a published connection URL. Then use the applicable scripts:

```sh
npm run typecheck
npm run verify:engine
npm run verify:product
npm run verify:management
npm run verify:auth
npm run verify:enrollment
npm run verify:staging
node --import tsx scripts/verify-auth-expired.ts
npm run verify:app
npm run verify:mcp
npm run verify:setup
npm run verify:ux
npm run verify:transport
npm run verify:container
```

Acceptance has exercised actual Node/PostgreSQL protocol work, email-bound auth with controlled TLS SMTP/IdP fixtures, permissions/delegation and native no-JavaScript forms in normal Chrome at desktop and 390px widths. Separately, the packaged Linux ARM64 Node 24/PostgreSQL 18 deployment has exercised bootstrap/restart, full encrypted backup/restore, original scoped TLS trust, preserved identities/ledger/keys and real restored encrypted-header checks plus independently HMAC-validated durable webhook receipts. Controlled fixtures are not proof of approved production OAuth/email/merchant configuration, physical keyboard/clipboard access, a public Linux hosted deployment or an SLA.

## License and contributions

Original Tomato source is licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) for retained third-party attribution/terms and [CONTRIBUTING.md](CONTRIBUTING.md) for provenance, security, acceptance and publication requirements. Dependencies and the separately distributed Node/Debian/PostgreSQL/Caddy components retain their own licenses. Operator/customer data and private operational history are not published or automatically relicensed as source.
