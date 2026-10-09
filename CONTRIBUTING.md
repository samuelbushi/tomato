# Contributing to Tomato

Tomato is an Apache-2.0 monitoring product with a provider-independent self-hosted distribution and a hosted mode using the same engine. A commercial hosted launch has separate deployment, mail/OAuth and merchant prerequisites; it is not implied by publication of the source. Self-hosting must not require a cloud account, remote activation, paid license or purchased Tomato credits. Hosted usage metering is not a reason to withhold monitoring, roles, UI, API or MCP features from the open-source distribution.

## License and provenance

Original Tomato project source is licensed under the [Apache License, Version 2.0](LICENSE). Contributions intentionally submitted for inclusion are provided under that license, as described in section 5. Contributors retain their copyright; this document does not assign copyright or claim an unverified company is the copyright owner. Submit only work you have the right to contribute. Preserve existing copyright, patent, trademark, attribution and third-party license notices, and identify any copied/adapted material and its origin in the change description.

The license does not grant rights to upstream or Tomato trademarks. Dependencies, separately licensed third-party code and operator/customer data retain their own applicable terms. Do not copy competitor assets, demo monitoring history or unrelated proprietary code into this repository. A dependency's availability from npm is not proof that its redistribution obligations have been satisfied.

## Engineering contract

- Prefer boring, maintainable TypeScript/Node.js and PostgreSQL designs. Keep one shared engine and authoritative validation/accounting/security rules across hosted and self-hosted modes.
- Retain all six protocol families and existing incident, evidence, maintenance, role, key-lineage, API/MCP and public-status boundaries. Unknown infrastructure outcomes must not become false green status or a paid target observation.
- Preserve the deliberately old-Windows square grey/blue interface and useful server-rendered semantic HTML. Native forms must remain usable without optional JavaScript where that workflow supports it.
- Do not expose saved monitor header values, signing secrets, passwords, API tokens or private target/evidence details in forms, errors, logs or public status pages. New secrets need explicit secure storage and backup handling.
- Explain schema changes and provide data-preserving migrations and upgrade/restore instructions. Configuration export alone is not a database backup.
- Do not invent email delivery, payment success, OAuth authorization, geographic coverage, capacity, prices or SLA evidence. Optional providers must have real configuration and truthful unconfigured behavior.

## Change descriptions and checks

Describe the intended behavior, affected modes and user-visible impact; include migrations/configuration changes, actual checks performed and any provider prerequisite that prevented a real flow. Use new synthetic accounts, controlled protocol endpoints and a separate disposable PostgreSQL database for acceptance. Never use production credentials or a pre-existing customer's monitor as a test fixture.

Use the commands documented in the current README and package scripts for the runtime you are changing. Report only checks actually executed, including their scope. A screenshot of invented data or a source-text assertion is not end-to-end acceptance. Do not claim physical keyboard/clipboard accessibility from DOM-driven form submission.

## Security and private evidence

Do not include credentials, private customer data, database dumps, authenticated screenshots, request headers or unredacted operational state in issues, pull requests or public logs. If the repository offers private vulnerability reporting, use it for sensitive findings. If it does not, first request a private reporting route without disclosing exploit details or secrets in a public issue. No security-response SLA is promised here.

Local operator research, pilot configuration and acceptance captures are not automatically public documentation. Public evidence must be separately reviewed for privacy and supported by an actual controlled-runtime result.

## Publication boundary

This workspace may contain private operational files next to release source. Never publish it using an indiscriminate whole-folder upload or `git add .`. `.gitignore` is defense in depth, not a substitute for a reviewed release manifest. Include only the complete source/configuration/templates/documentation required for a reproducible release, with dependency lockfiles and license notices. Exclude:

- `research/` and its operational history, evidence JSON, screenshots and internal provider/account identifiers;
- live `wrangler.jsonc` / `wrangler.fixture.jsonc`, pilot provisioning/access tools and protected pilot configuration;
- `.tomato-local/`, `.tomato-dev/`, `.tomato-production/`, `.wrangler/`, `.mf/` and verification scratch;
- environment values, bootstrap/worker credentials, private keys/certificates, database/backup archives, logs and customer data;
- generated build artifacts and installed dependency directories.

Public runtime configuration must be safe templates with no user-specific provider IDs or credential values. Release instructions must distinguish newly verified portable code from any still-running previous production release. A release maintainer must complete runtime, dependency/license and source-privacy review before repository publication; publication is not an automatic implementation side effect. Production deployment/cutover, external signup/customer mail and commercial payment products/charges require their own explicitly approved targets, providers and values.
