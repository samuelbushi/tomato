# Changelog

## Unreleased — portable Node/PostgreSQL product

- Move the shared monitoring product to TypeScript/Node.js 24, PostgreSQL and Better Auth, with real HTTP(S), heartbeat, DNS/DoH, WebSocket, TCP and TLS execution, durable evidence, incidents/recovery and configured alerts.
- Keep the square grey/blue old-Windows native interface, workspace roles, public status, scoped REST/MCP management and revocable key delegation. Core native forms support operation without optional JavaScript.
- Provide complete self-hosted monitoring without a mandatory provider account, license activation or purchased Tomato credits. Hosted mode uses the same engine and exact eligible-primary credit ledger; retail payments/prices are not fabricated by that meter.
- Keep hosted operator provisioning unfunded when `testingCredits` is omitted or explicitly zero. Validate explicitly supplied amounts before creating an identity/workspace; positive operator testing grants are audit-tagged and idempotent, not customer payments or implied welcome credits.
- Add secure owner bootstrap, explicit HTTPS/prober/database isolation, tracked migrations, identity-preserving restart/upgrade and authenticated full encrypted backup/restore for the supplied Docker Compose package.
- Exercise native Node/PostgreSQL workflows in controlled endpoints and normal Chrome desktop/390px views, and the actual Linux ARM64/PostgreSQL 18 package through first-run, restart, full restore, restored stored-secret checks and HMAC-validated webhook delivery.
- Prepare Apache-2.0 source licensing, retained third-party notices and contributor/security guidance. Dependencies and upstream runtime/database/proxy components retain their own licenses.

The existing Cloudflare-hosted service remains on its previous release. This source change does not perform a live migration, public-host cutover, commercial signup/payment launch or new provider approval. Authorized deployment, real legacy-email/export mapping, approved mail/OAuth and merchant/pricing/legal decisions remain separate commercial prerequisites. See [README.md](README.md) for actual commands, supported packaging, operational limitations and launch status.
