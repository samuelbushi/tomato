import type { AccountRole, AuthenticatedView, AvailabilityReport, DeliveryView, DisplayMonitor, MaintenanceWindow, NotificationDefaultsView, ReadinessView, UiPage, WalletView } from "./product-types";
import type { Incident, MonitorState, StoredObservation } from "./types";

const HTML_ENTITIES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const CHECK_LABELS: Record<string, string> = { http: "HTTP / HTTPS", heartbeat: "Heartbeat", dns: "DNS", websocket: "WebSocket", tcp: "TCP", tls: "TLS" };
const STATE_DESCRIPTIONS: Record<MonitorState, string> = {
  UP: "Latest observation succeeded", DOWN: "Confirmed failure", SUSPECT: "Failure awaiting confirmation",
  RECOVERING: "Recovery awaiting confirmation", UNKNOWN: "Not observed or no fresh result", PAUSED: "Monitoring paused",
  MAINTENANCE: "Scheduled maintenance; checks and alerts suppressed",
};
const ROLE_DESCRIPTIONS: Record<AccountRole, string> = {
  owner: "Manage checks, public pages, invitations and workspace members.",
  editor: "Manage checks and alerts; cannot change public pages or workspace members.",
  viewer: "Read monitoring data; cannot change checks or public pages.",
};
const NUMBER_FORMATTER = new Intl.NumberFormat("en", { maximumFractionDigits: 2 });

function escape(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, character => HTML_ENTITIES[character]!);
}

function timestamp(at: number | null | undefined): string {
  if (at === null || at === undefined || !Number.isFinite(at)) return '<span class="muted">Never / not available</span>';
  const iso = new Date(at).toISOString();
  return `<time datetime="${iso}">${iso.slice(0, 19).replace("T", " ")} UTC</time>`;
}

function number(value: number): string {
  return NUMBER_FORMATTER.format(value);
}

function state(value: MonitorState, freshUntil?: number | null): string {
  const freshness = freshUntil !== undefined ? ` data-current-state data-fresh-until="${freshUntil ?? ""}"` : "";
  return `<span class="state ${value}"${freshness} title="${escape(STATE_DESCRIPTIONS[value])}">${value}</span>`;
}

function panel(title: string, content: string): string {
  return `<section class="window"><div class="title-bar"><h2>${escape(title)}</h2></div><div class="window-body">${content}</div></section>`;
}

function heading(title: string, description = "", actions = ""): string {
  return `<div class="page-heading"><div><h1>${escape(title)}</h1>${description ? `<p class="muted">${escape(description)}</p>` : ""}</div>${actions ? `<div class="actions">${actions}</div>` : ""}</div>`;
}

function hidden(name: string, value: unknown): string {
  return `<input type="hidden" name="${escape(name)}" value="${escape(value)}">`;
}

function csrf(token: string): string {
  return hidden("csrfToken", token);
}

function field(name: string, label: string, value: unknown = "", options: { type?: string; required?: boolean; min?: number; max?: number; step?: string; pattern?: string; autocomplete?: string; help?: string; full?: boolean; maxLength?: number; readonly?: boolean } = {}): string {
  const attributes = `${options.required ? " required" : ""}${options.min !== undefined ? ` min="${options.min}"` : ""}${options.max !== undefined ? ` max="${options.max}"` : ""}${options.step ? ` step="${escape(options.step)}"` : ""}${options.pattern ? ` pattern="${escape(options.pattern)}"` : ""}${options.autocomplete ? ` autocomplete="${escape(options.autocomplete)}"` : ""}${options.maxLength ? ` maxlength="${options.maxLength}"` : ""}${options.readonly ? " readonly" : ""}`;
  return `<div class="field${options.full ? " full" : ""}"><label for="${escape(name)}">${escape(label)}</label><input id="${escape(name)}" name="${escape(name)}" type="${escape(options.type ?? "text")}" value="${escape(value)}"${attributes}${options.help ? ` aria-describedby="${escape(name)}-help"` : ""}>${options.help ? `<span class="help" id="${escape(name)}-help">${escape(options.help)}</span>` : ""}</div>`;
}

function textarea(name: string, label: string, value: string, help = "", required = false): string {
  return `<div class="field full"><label for="${escape(name)}">${escape(label)}</label><textarea id="${escape(name)}" name="${escape(name)}"${required ? " required" : ""}${help ? ` aria-describedby="${escape(name)}-help"` : ""}>${escape(value)}</textarea>${help ? `<span class="help" id="${escape(name)}-help">${escape(help)}</span>` : ""}</div>`;
}

function select(name: string, label: string, choices: Record<string, string>, selected: string, help = ""): string {
  return `<div class="field"><label for="${escape(name)}">${escape(label)}</label><select id="${escape(name)}" name="${escape(name)}"${help ? ` aria-describedby="${escape(name)}-help"` : ""}>${Object.entries(choices).map(([value, text]) => `<option value="${escape(value)}"${value === selected ? " selected" : ""}>${escape(text)}</option>`).join("")}</select>${help ? `<span class="help" id="${escape(name)}-help">${escape(help)}</span>` : ""}</div>`;
}

function checkbox(name: string, label: string, checked: boolean, value = "on"): string {
  return `<label class="check-label"><input type="checkbox" name="${escape(name)}" value="${escape(value)}"${checked ? " checked" : ""}> <span>${escape(label)}</span></label>`;
}

function copyControl(id: string, label: string): string {
  return `<div class="actions copy-control"><button type="button" hidden data-copy-target="${escape(id)}">${escape(label)}</button><span class="help" data-copy-status role="status"></span></div>`;
}

function secretReveal(id: string, value: string): string {
  return `<pre id="${escape(id)}" data-secret>${escape(value)}</pre>${copyControl(id, "Copy once-shown secret")}`;
}

function defaultsOptIn(defaults?: NotificationDefaultsView): string {
  if (!defaults?.webhook && !defaults?.email) return "";
  return `<div class="panel">${checkbox("useNotificationDefaults", "Use workspace alert destinations for this new monitor", false, "true")}
    <p class="help">${escape([defaults.webhook?.url, defaults.email?.address].filter(Boolean).join(" · "))}. Copied at creation only; changing defaults never silently changes existing monitors or sends a test.</p></div>`;
}

function setupGuide(page: AuthenticatedView, monitors: DisplayMonitor[], deliveries: DeliveryView[]): string {
  const observed = monitors.find(monitor => monitor.lastObservedAt !== null);
  const configured = monitors.find(monitor => monitor.webhook || monitor.email);
  const tests = configured ? deliveries.filter(delivery => delivery.type === "test" && delivery.monitorId === configured.id) : [];
  const test = tests.reduce<DeliveryView | undefined>((latest, delivery) => !latest || (delivery.occurredAt ?? 0) > (latest.occurredAt ?? 0) ? delivery : latest, undefined);
  const base = accountPath(page);
  return `<ol class="setup-steps">
    <li><strong>Monitor and first evidence.</strong> ${!monitors.length ? "Create a monitor above; it starts UNKNOWN, never assumed healthy." :
      observed ? `<a href="${monitorPath(page, observed)}">${escape(observed.name)}</a> ${state(observed.effectiveState)} · observed ${timestamp(observed.lastObservedAt)}.` :
      `Saved; waiting for a real observation. <a href="${base}">Refresh evidence</a> after the next due time, or send a real job pulse for heartbeat monitoring.`}</li>
    <li><strong>Alerts — optional.</strong> ${configured ? `<a href="${monitorPath(page, configured)}#alerts">${escape(configured.name)} has a destination</a>. ${test ? `${test.occurredAt ? "Latest explicit test" : "Recorded explicit test"}: ${escape(test.channel)} / ${escape(test.status)} (${number(test.attempts)} attempts).` : "Send an explicit test from the monitor, then inspect delivery status."}` :
      `<a href="${base}/settings#notification-defaults">Set reusable destinations</a> or configure one monitor. No email or webhook is sent automatically.`}</li>
    <li><strong>Public status — optional.</strong> ${page.account.role === "owner" ? `<a href="${base}/status-page">Choose public labels and opt-in components</a>; review and publish explicitly.` : "A workspace owner can opt in safe public components."} Private targets and secrets are never automatically published.</li>
  </ol>`;
}

function actionForm(action: string, token: string, label: string, values: Record<string, unknown> = {}, buttonClass = ""): string {
  return `<form method="post" action="${escape(action)}">${csrf(token)}${Object.entries(values).map(([name, value]) => hidden(name, value)).join("")}<button type="submit"${buttonClass ? ` class="${escape(buttonClass)}"` : ""}>${escape(label)}</button></form>`;
}

function accountPath(page: AuthenticatedView): string {
  return `/app/accounts/${encodeURIComponent(page.account.id)}`;
}

function monitorPath(page: AuthenticatedView, monitor: DisplayMonitor): string {
  return `${accountPath(page)}/monitors/${encodeURIComponent(monitor.id)}`;
}

function target(monitor: DisplayMonitor): string {
  const check = monitor.check;
  switch (check.kind) {
    case "http": case "websocket": return check.url;
    case "dns": return `${check.name} (${check.recordType})`;
    case "tcp": case "tls": return `${check.hostname}:${check.port}`;
    case "heartbeat": return "Authenticated incoming pulses";
  }
}


function monitorActions(page: AuthenticatedView, monitor: DisplayMonitor, includeDelete = false): string {
  if (page.account.role === "viewer") return "";
  const path = monitorPath(page, monitor);
  const canCheck = !monitor.paused && monitor.effectiveState !== "MAINTENANCE" && monitor.check.kind !== "heartbeat";
  return `<div class="actions"><a class="button" href="${path}/edit">Edit</a>${canCheck ? actionForm(`${path}/check-now`, page.csrfToken, page.mode === "self-host" ? "Check now (one eligible observation)" : "Check now (up to 1 credit)", { revision: monitor.revision }) : ""}${actionForm(`${path}/${monitor.paused ? "resume" : "pause"}`, page.csrfToken, monitor.paused ? "Resume" : "Pause", { revision: monitor.revision })}${includeDelete ? `<a class="button danger" href="#delete-monitor">Delete…</a>` : ""}</div>`;
}

function walletSummary(wallet: WalletView): string {
  const metrics: Record<string, number> = wallet.mode === "self-host" ? {
    "Eligible primary observations and heartbeat pulses": wallet.usage,
    "Running work reservations": wallet.reserved, "Missed slots": wallet.missedSlots,
  } : {
    "Available credits": wallet.available, Balance: wallet.balance,
    "Reserved for running checks": wallet.reserved, "Credits consumed": wallet.usage, "Missed slots": wallet.missedSlots,
  };
  return `<dl class="metrics">${Object.entries(metrics).map(([label, value]) =>
    `<div class="metric"><dt>${label}</dt><dd>${number(value)}</dd></div>`).join("")}</dl>
    ${wallet.mode === "self-host" ? '<p class="help">Self-hosted usage ledger: no paid balance, depletion cutoff or payment requirement.</p>' : wallet.available === 0 ? '<p class="warning">No available credits. Unfunded checks are UNKNOWN, not successful. Cadence does not silently change.</p>' : ""}`;
}

function deliveryTable(page: AuthenticatedView, deliveries: DeliveryView[]): string {
  if (!deliveries.length) return '<p class="empty">No notification deliveries yet. Incident transitions and explicitly requested tests appear here.</p>';
  const canEdit = page.account.role !== "viewer";
  return `<div class="table-scroll"><table>
    <caption>Actual notification delivery attempts</caption>
    <thead><tr><th scope="col">Monitor / event</th><th scope="col">Channel</th><th scope="col">Status</th>
      <th scope="col">Attempts</th><th scope="col">Delivered / next attempt</th>
      <th scope="col">Last error</th>${canEdit ? '<th scope="col">Action</th>' : ""}</tr></thead>
    <tbody>${deliveries.map(delivery => `<tr>
      <td class="wrap"><a href="${accountPath(page)}/monitors/${encodeURIComponent(delivery.monitorId)}">${escape(delivery.monitorId)}</a>
        <span class="help">${escape(delivery.type)}${delivery.incidentId ? ` · ${escape(delivery.incidentId)}` : ""}</span></td>
      <td>${escape(delivery.channel)}</td><td>${escape(delivery.status)}</td><td>${number(delivery.attempts)}</td>
      <td>${delivery.deliveredAt !== null ? timestamp(delivery.deliveredAt) : timestamp(delivery.nextAttemptAt)}</td>
      <td class="wrap">${escape(delivery.lastError ?? "None recorded")}</td>
      ${canEdit ? `<td>${delivery.status === "failed" ? actionForm(`${accountPath(page)}/notifications/retry`, page.csrfToken, "Retry delivery", { eventId: delivery.id }) : "—"}</td>` : ""}
    </tr>`).join("")}</tbody></table></div>`;
}

function incidentTable(incidents: Incident[], page?: AuthenticatedView): string {
  if (!incidents.length) return '<p class="empty">No incidents recorded in this history.</p>';
  const canEdit = page && page.account.role !== "viewer";
  return `<div class="table-scroll"><table><caption>Confirmed incidents; unknown coverage is not an outage claim</caption>
    <thead><tr><th scope="col">Monitor</th><th scope="col">First failure</th><th scope="col">Opened</th><th scope="col">Recovered</th><th scope="col">Acknowledgement</th></tr></thead>
    <tbody>${incidents.map(incident => `<tr><td class="wrap">${escape(incident.monitorName ?? incident.monitorId)}<span class="help mono">${escape(incident.id)}</span></td>
      <td>${timestamp(incident.firstFailureAt)}</td><td>${timestamp(incident.openedAt)}</td><td>${incident.closedAt === null ? "Open" : timestamp(incident.closedAt)}</td>
      <td>${incident.acknowledgedAt ? `Acknowledged ${timestamp(incident.acknowledgedAt)}${incident.acknowledgedBy ? `<span class="help">${escape(incident.acknowledgedBy)}</span>` : ""}` : "Not acknowledged"}
        ${canEdit ? actionForm(`${accountPath(page!)}/incidents/${encodeURIComponent(incident.id)}/acknowledgement`, page!.csrfToken, incident.acknowledgedAt ? "Clear acknowledgement" : "Acknowledge", { acknowledged: !incident.acknowledgedAt }) : ""}</td></tr>`).join("")}</tbody></table></div>
    ${canEdit ? '<p class="help">Acknowledgement records responsibility; it does not change observed health or suppress alerts.</p>' : ""}`;
}

function observationTable(observations: StoredObservation[]): string {
  if (!observations.length) return '<p class="empty">No stored observations yet. A new monitor starts UNKNOWN until a real result arrives.</p>';
  return `<div class="table-scroll"><table><caption>Recent observations, newest first; no remote response HTML is rendered</caption><thead><tr><th scope="col">Scheduled</th><th scope="col">Observed</th><th scope="col">Outcome / code</th><th scope="col">Latency</th><th scope="col">Evidence</th></tr></thead><tbody>${observations.map(observation => `<tr><td>${timestamp(observation.scheduledAt)}</td><td>${timestamp(observation.result.finishedAt)}</td><td class="wrap">${escape(observation.result.outcome)}<span class="help mono">${escape(observation.result.code)}</span></td><td>${number(observation.result.latencyMs)} ms</td><td class="wrap mono">${observation.result.evidence ? escape(JSON.stringify(observation.result.evidence)) : "Not recorded"}</td></tr>`).join("")}</tbody></table></div>`;
}

function dashboard(page: Extract<UiPage, { kind: "dashboard" }>): string {
  const canEdit = page.account.role !== "viewer";
  const base = accountPath(page);
  const bulk = canEdit && page.monitors.length > 1;
  const counts: Record<MonitorState, number> = { UP: 0, DOWN: 0, SUSPECT: 0, RECOVERING: 0, UNKNOWN: 0, PAUSED: 0, MAINTENANCE: 0 };
  for (const monitor of page.monitors) counts[monitor.effectiveState]++;
  const rows = page.monitors.map(monitor => `<tr data-monitor-row data-search="${escape(`${monitor.name} ${monitor.id} ${target(monitor)}`.toLowerCase())}">
    ${bulk ? `<td data-label="Select"><label class="check-label"><input type="checkbox" name="monitorId" value="${escape(monitor.id)}" form="monitor-bulk"><span class="sr-only">Select ${escape(monitor.name)}</span></label><input type="hidden" name="revision_${escape(monitor.id)}" value="${monitor.revision}" form="monitor-bulk"></td>` : ""}
    <td data-label="Monitor" class="wrap"><a href="${monitorPath(page, monitor)}"><strong>${escape(monitor.name)}</strong></a><span class="help mono">${escape(monitor.id)}</span></td>
    <td data-label="Type">${escape(CHECK_LABELS[monitor.check.kind])}</td><td data-label="Target" class="target-cell">${escape(target(monitor))}</td>
    <td data-label="State">${state(monitor.effectiveState, monitor.freshUntil)}${monitor.effectiveState === "MAINTENANCE" ? `<span class="help">Until ${timestamp(monitor.maintenanceUntil)}</span>` : monitor.effectiveState !== monitor.state ? '<span class="help">Stored state is stale.</span>' : ""}</td>
    <td data-label="Last observation">${timestamp(monitor.lastObservedAt)}${monitor.freshUntil ? `<span class="help">Evidence expires ${timestamp(monitor.freshUntil)}</span>` : ""}</td>
    <td data-label="Next due">${monitor.paused ? "Paused" : timestamp(monitor.maintenanceUntil ?? monitor.nextDueAt)}</td>
    <td data-label="Alerts" class="target-cell">${escape(monitor.webhook?.url ?? "No webhook")}${monitor.email ? `<span class="help">${escape(monitor.email.address)} (email)</span>` : ""}</td>
    ${canEdit ? `<td class="actions-cell">${monitorActions(page, monitor)}</td>` : ""}
  </tr>`).join("");
  const quick = canEdit ? `<form method="post" action="${base}/new-monitor" class="quick-create">
    ${csrf(page.csrfToken)}${hidden("kind", "http")}
    ${field("url", "Website or health-check URL", "", { type: "url", required: true, full: true, help: "HTTP(S) · GET · any 2xx · every 60 seconds · 5-second timeout. Name and identifier are generated." })}
    ${defaultsOptIn(page.notificationDefaults)}
    <div class="actions"><button class="primary" type="submit">Create monitor</button><a href="${base}/new-monitor">All six types and advanced settings</a></div>
    <p class="help">At most 1,440 primary checks/day · 43,200 per 30 days. ${page.mode === "self-host" ? "One usage unit per accepted primary observation; no paid balance or depletion cutoff." : "One credit per accepted primary observation."} Unknown work, confirmations and retries add no usage.</p>
  </form>` : "";
  return heading("Monitors", "Real evidence, clear uncertainty, predictable usage.", canEdit ? `<a class="button" href="${base}/new-monitor">Advanced setup</a>` : "") +
    (canEdit ? panel(page.monitors.length ? "Quick add" : "Start monitoring", page.monitors.length ? `<details><summary>Add an HTTP(S) monitor</summary>${quick}</details>` : quick) : "") +
    (!page.monitors.length || !page.monitors.some(monitor => monitor.lastObservedAt !== null) ? panel("Setup guide", setupGuide(page, page.monitors, page.deliveries)) :
      `<details><summary>Setup guide: evidence, alerts and public status</summary>${setupGuide(page, page.monitors, page.deliveries)}</details>`) +
    walletSummary(page.wallet) + panel("Current state", `
      <div class="state-counts">${(Object.keys(counts) as MonitorState[]).map(value => `<span>${state(value)} <strong data-state-count="${value}">${counts[value]}</strong></span>`).join("")}</div>
      <p class="help">Snapshot ${timestamp(page.generatedAt)}. Temporal confirmation is not independent geographic coverage. Stale outbound evidence, including DOWN, becomes UNKNOWN; retained incident history is separate.</p>
      <p class="help">Check now queues one real primary check without changing ordinary cadence. An accepted target observation adds one ${page.mode === "self-host" ? "usage unit (not a payment charge)" : "credit of consumption"}; unknown work and confirmation add none. Heartbeats need a real job pulse.</p>
      <div class="toolbar"><label for="monitor-search">Filter monitors <input id="monitor-search" type="search" data-monitor-filter placeholder="Name, target or state" autocomplete="off"></label>
        <a class="button" href="${base}">Refresh evidence</a>${page.monitors.length ? `<a href="${base}/reports?monitorId=${encodeURIComponent(page.monitors[0]!.id)}">Availability report</a>` : ""}</div>
      ${bulk ? `<form id="monitor-bulk" method="post" action="${base}/monitors/bulk" data-bulk-form class="toolbar">
        ${csrf(page.csrfToken)}<label hidden><input type="checkbox" hidden data-select-visible> Select visible monitors</label>
        <label for="bulk-action">Selected monitors <select name="action" id="bulk-action"><option value="pause">Pause</option><option value="resume">Resume</option></select></label>
        <button type="submit">Apply to selected</button><span data-selection-count role="status">Choose monitors below</span>
      </form><p class="help">All selected revisions are validated together. A filtered-out selection remains selected; no deletion or alert send is performed.</p>` : ""}
      ${page.monitors.length ? `<div class="table-scroll"><table class="monitor-table">
        <caption>${page.monitors.length} configured monitors</caption>
        <thead><tr>${bulk ? '<th scope="col">Select</th>' : ""}<th scope="col">Monitor</th><th scope="col">Type</th><th scope="col">Target</th><th scope="col">State</th>
          <th scope="col">Last observation</th><th scope="col">Next due</th><th scope="col">Alerts</th>${canEdit ? '<th scope="col">Actions</th>' : ""}</tr></thead>
        <tbody>${rows}</tbody></table></div><p hidden data-filter-empty class="empty" role="status">No monitors match this filter.</p>` :
        `<p class="empty">No configured monitors. ${canEdit ? "Paste a URL above to start." : "Ask an owner or editor to add a monitor."}</p>`}
      <noscript><p class="help">The full list is shown without JavaScript. Creation, monitor actions and bulk selection still work.</p></noscript>`) +
    panel("Incidents", incidentTable(page.incidents, page)) + panel("Recent alert deliveries", deliveryTable(page, page.deliveries));
}

function reportSummary(report: AvailabilityReport): string {
  return `<dl class="metrics">
    <div class="metric"><dt>Availability while observed</dt><dd>${report.uptimeRatio === null ? "Not available" : `${number(report.uptimeRatio * 100)}%`}</dd></div>
    <div class="metric"><dt>Observation coverage</dt><dd>${number(report.coverageRatio * 100)}%</dd></div>
    <div class="metric"><dt>Observed duration</dt><dd>${number(report.observedMs / 60000)} min</dd></div>
    <div class="metric"><dt>Excluded duration</dt><dd>${number(report.excludedMs / 60000)} min</dd></div>
  </dl>${report.truncated ? `<p class="warning">The requested window ${timestamp(report.requestedFrom)} — ${timestamp(report.requestedTo)} was shortened to retained/current data. Retained coverage begins ${timestamp(report.retainedFrom)}. The percentages shown describe only the displayed window.</p>` : ""}
  ${report.legacyCoverageMs > 0 ? `<p class="warning"><strong>Older history has unverified evidence semantics.</strong> It cannot be fully reconstructed. Unsupported historical time is conservatively UNKNOWN and excluded from observed availability, never assumed healthy or retroactively counted as observed uptime/downtime from the monitor's current protocol.</p>` : ""}
  <p class="help">Time-weighted: UP / (UP + DOWN + SUSPECT + RECOVERING). Coverage is observed duration / the whole window. UNKNOWN, PAUSED and MAINTENANCE are excluded from availability, never treated as success. Window ${timestamp(report.from)} — ${timestamp(report.to)}; generated ${timestamp(report.generatedAt)}.</p>`;
}

function reports(page: Extract<UiPage, { kind: "reports" }>): string {
  const report = page.report;
  const dateValue = (at: number): string => new Date(at).toISOString().slice(0, -1);
  return heading("Availability report", "Observed availability and missing coverage are shown separately.") +
    panel("Report window", `<form method="get" action="${accountPath(page)}/reports"><div class="form-grid">
      ${select("monitorId", "Monitor", Object.fromEntries(page.monitors.map(monitor => [monitor.id, monitor.name])), report.monitorId)}
      ${field("from", "From (UTC)", dateValue(report.from), { type: "datetime-local", required: true, step: "0.001" })}
      ${field("to", "To (UTC)", dateValue(report.to), { type: "datetime-local", required: true, step: "0.001" })}
      </div><p class="help">Values are interpreted as UTC, not your device's time zone. Maximum window: seven days.</p><button class="primary" type="submit">Show report</button></form>`) +
    panel("Availability and coverage", reportSummary(report) + `<div class="table-scroll"><table><caption>Duration by state in the requested window</caption>
      <thead><tr><th scope="col">State</th><th scope="col">Minutes</th></tr></thead>
      <tbody>${Object.entries(report.durationsMs).map(([value, duration]) => `<tr><td>${state(value as MonitorState)}</td><td>${number(duration / 60000)}</td></tr>`).join("")}</tbody></table></div>`) +
    panel("Observed latency", `<dl class="details"><dt>Samples</dt><dd>${number(report.latency.samples)}</dd>
      <dt>Average</dt><dd>${report.latency.averageMs === null ? "Not available" : `${number(report.latency.averageMs)} ms`}</dd>
      <dt>p95</dt><dd>${report.latency.p95Ms === null ? "Not available" : `${number(report.latency.p95Ms)} ms`}</dd></dl>
      <p class="help">Latency uses retained observations only. It is not a network-only measurement or a commercial performance guarantee.</p>`);
}

function maintenanceControls(page: Extract<UiPage, { kind: "monitor" }>, windows: MaintenanceWindow[]): string {
  const canEdit = page.account.role !== "viewer";
  const base = accountPath(page);
  const startsAt = Math.ceil(page.generatedAt / 60000) * 60000;
  return panel("Maintenance", `<p>During a maintenance window, new checks and alerts are suppressed without charging check credits. Incident history remains; maintenance is not a successful observation. Pausing remains a separate, indefinite action.</p>
    ${windows.length ? `<div class="table-scroll"><table><caption>Scheduled and recorded maintenance for this monitor</caption><thead><tr><th scope="col">Reason</th><th scope="col">Starts</th><th scope="col">Ends</th><th scope="col">Status</th>${canEdit ? '<th scope="col">Action</th>' : ""}</tr></thead>
      <tbody>${windows.map(window => `<tr><td class="wrap">${escape(window.reason)}</td><td>${timestamp(window.startsAt)}</td><td>${timestamp(window.endsAt)}</td><td>${escape(window.status)}</td>
        ${canEdit ? `<td>${window.status === "active" || window.status === "scheduled" ? actionForm(`${base}/maintenance/${encodeURIComponent(window.id)}/cancel`, page.csrfToken, "Cancel window", { monitorId: page.monitor.id, revision: page.monitor.revision }) : "—"}</td>` : ""}</tr>`).join("")}</tbody></table></div>` : '<p class="help">No maintenance windows scheduled.</p>'}
    ${canEdit ? `<details><summary>Schedule maintenance…</summary><form method="post" action="${base}/maintenance">
      ${csrf(page.csrfToken)}${hidden("monitorId", page.monitor.id)}${hidden("revision", page.monitor.revision)}<div class="form-grid">
      ${field("startsAt", "Starts (UTC)", new Date(startsAt).toISOString().slice(0, 16), { type: "datetime-local", required: true })}
      ${field("endsAt", "Ends (UTC)", new Date(startsAt + 3600000).toISOString().slice(0, 16), { type: "datetime-local", required: true })}
      ${field("reason", "Reason", "", { required: true, maxLength: 240, full: true, help: "Internal maintenance label. Date/time values are interpreted as UTC." })}</div>
      <div class="form-actions"><button type="submit">Schedule maintenance for ${escape(page.monitor.name)}</button></div>
    </form></details>` : ""}`);
}

function certificateEvidence(page: Extract<UiPage, { kind: "monitor" }>): string {
  const monitor = page.monitor;
  if (monitor.check.kind !== "tls" && !(monitor.check.kind === "http" && monitor.check.url.startsWith("https:"))) return "";
  const certificate = monitor.certificate;
  return panel("Certificate evidence", certificate ? `
    <p class="${certificate.status === "valid" && !certificate.stale ? "help" : "warning"}">Recorded certificate: <strong>${escape(certificate.status)}</strong>${certificate.stale ? " · evidence stale" : ""}. Certificate warnings are separate from outage state.</p>
    <dl class="details"><dt>Observed</dt><dd>${timestamp(certificate.observedAt)}</dd><dt>Valid from</dt><dd>${timestamp(certificate.validFrom)}</dd>
    <dt>${monitor.check.kind === "http" ? "Earliest verified HTTPS hop expiry" : "Verified TLS peer expiry"}</dt><dd>${timestamp(certificate.validTo)} · ${number(certificate.daysRemaining)} days from this snapshot</dd>
    <dt>Early-expiry threshold</dt><dd>${number(certificate.thresholdDays)} days</dd></dl>
    <p class="help">${monitor.check.kind === "http" ? "HTTPS evidence is the earliest authenticated leaf expiry across all required secure redirect hops, not necessarily the final destination." : "Direct TLS evidence describes the single authenticated peer."} This is last-observed assertion evidence, not a guarantee for a future connection. Configured channels receive deduplicated expiry warnings; missing evidence is never invented success.</p>` :
    '<p class="help">No retained certificate evidence yet. Missing evidence is not proof of validity; the transport must observe and verify the certificate.</p>');
}

function monitorDetail(page: Extract<UiPage, { kind: "monitor" }>): string {
  const monitor = page.monitor;
  const path = monitorPath(page, monitor);
  const canEdit = page.account.role !== "viewer";
  const heartbeat = monitor.check.kind === "heartbeat" ? panel("Heartbeat instructions", `
    <p>Send a POST with the bearer token and a unique Idempotency-Key for each real pulse.
      ${page.mode === "self-host" ? "One unique accepted pulse records one usage unit; no paid-credit balance is enforced." : "One unique accepted pulse uses one credit from the enforced hosted ledger."} Retries using the same ID add no usage.
      An accepted pulse renews the interval plus grace deadline. Paused monitors reject pulses.</p>
    <p class="help">The token is only shown at creation or rotation. It is not recoverable from this page.
      Genuine overdue-pulse detection can remain DOWN even when the last successful pulse is old.</p>
    ${canEdit ? `<details><summary>Rotate heartbeat token…</summary>
      <p class="warning">Rotating invalidates the existing token for ${escape(monitor.name)} immediately. Update the job that sends pulses.</p>
      ${actionForm(`${path}/heartbeat-token`, page.csrfToken, "Rotate and reveal new token", { revision: monitor.revision }, "danger")}</details>` : ""}`) : "";
  const coverage = page.coverage.length ? `<div class="table-scroll"><table>
    <caption>Persisted state coverage; unobserved and paused periods are never counted as successful checks</caption>
    <thead><tr><th scope="col">State</th><th scope="col">Started</th><th scope="col">Ended</th></tr></thead>
    <tbody>${page.coverage.map(segment => `<tr><td>${state(segment.state)}</td><td>${timestamp(segment.startedAt)}</td>
      <td>${segment.endedAt === null ? "Open stored segment — see current freshness above" : timestamp(segment.endedAt)}</td></tr>`).join("")}</tbody>
    </table></div>` : '<p class="empty">No state coverage segments recorded.</p>';
  return heading(monitor.name, `${monitor.id} · ${CHECK_LABELS[monitor.check.kind]}`, monitorActions(page, monitor, true)) +
    panel("Current observation", `
      <p>${state(monitor.effectiveState, monitor.freshUntil)} <span data-current-description>${escape(STATE_DESCRIPTIONS[monitor.effectiveState])}</span></p>
      ${monitor.effectiveState === "UNKNOWN" && monitor.effectiveState !== monitor.state ? '<p class="warning">The stored state no longer has fresh supporting evidence; effective state is UNKNOWN. Any retained open incident remains visible in history below.</p>' : ""}
      <dl class="details"><dt>Target</dt><dd>${escape(target(monitor))}</dd>
        <dt>Last observed</dt><dd>${timestamp(monitor.lastObservedAt)}</dd><dt>Evidence expires</dt><dd>${timestamp(monitor.freshUntil)}</dd>
        <dt>Next due / deadline</dt><dd>${monitor.paused ? "Paused" : timestamp(monitor.maintenanceUntil ?? monitor.heartbeatDeadline ?? monitor.nextDueAt)}</dd>
        <dt>Cadence</dt><dd>${number(monitor.intervalMs / 1000)} seconds</dd><dt>Timeout</dt><dd>${number(monitor.timeoutMs / 1000)} seconds</dd>
        <dt>Confirmation delay</dt><dd>${number(monitor.confirmationDelayMs / 1000)} seconds (temporal)</dd>
        <dt>Execution window</dt><dd>${number(monitor.executionWindowMs / 1000)} seconds</dd><dt>Revision</dt><dd>${monitor.revision}</dd>
        <dt>HTTP header names</dt><dd>${monitor.check.kind === "http" && monitor.check.hasHeaders ? escape(monitor.check.headerNames.join(", ")) + " (values hidden)" : "None / not applicable"}</dd>
        <dt>Webhook</dt><dd>${escape(monitor.webhook?.url ?? "Not configured")}</dd><dt>Email</dt><dd>${escape(monitor.email?.address ?? "Not configured")}</dd>
      </dl>`) +
    (monitor.lastObservedAt === null && !monitor.paused ? `<section data-first-evidence-url="/api/accounts/${encodeURIComponent(page.account.id)}/monitors/${encodeURIComponent(monitor.id)}">
      ${panel("First result and optional setup", setupGuide(page, [monitor], page.deliveries) + `<p class="help" data-evidence-wait role="status">Waiting for the first stored result. <a href="${path}">Refresh evidence</a>; a new monitor remains UNKNOWN until observed.</p>`)}
    </section>` : "") +
    (page.report ? panel("Availability and coverage", reportSummary(page.report) + `<p><a href="${accountPath(page)}/reports?monitorId=${encodeURIComponent(monitor.id)}">Choose a report window</a></p>`) : "") +
    certificateEvidence(page) + maintenanceControls(page, page.maintenance ?? []) +
    `<details><summary>Saved check configuration</summary><pre>${escape(JSON.stringify(monitor.check, null, 2))}</pre></details>` + heartbeat +
    panel("Recent observations", observationTable(page.observations)) + `<details><summary>Persisted state coverage segments</summary>${coverage}</details>` +
    panel("Incidents", incidentTable(page.incidents, page)) +
    `<section id="alerts">${panel("Alert deliveries", `${!page.emailConfigured ? '<p class="help">Email transport is not configured; there is no simulated send.</p>' : ""}
      ${canEdit && (monitor.webhook || monitor.email) ? `<p>Explicit tests contact all configured alert channels. They do not charge check credits.</p>
        ${actionForm(`${path}/notification-test`, page.csrfToken, "Send test alert to configured destinations", { revision: monitor.revision })}` :
        canEdit ? `<p><a href="${path}/edit">Configure monitor alerts</a> or <a href="${accountPath(page)}/settings#notification-defaults">set workspace defaults for future monitors</a>.</p>` : ""}
      ${deliveryTable(page, page.deliveries)}`)}</section>` +
    (canEdit ? `<section id="delete-monitor">${panel("Delete monitor", `<details class="confirm-delete"><summary>Delete ${escape(monitor.name)}…</summary>
      <p class="warning">Permanently remove monitor ${escape(monitor.id)} and cancel its pending execution. Review the identifier before confirming.</p>
      ${actionForm(`${path}/delete`, page.csrfToken, `Delete monitor ${monitor.id}`, { revision: monitor.revision }, "danger")}</details>`)}</section>` : "");
}

function monitorEditor(page: Extract<UiPage, { kind: "monitor-edit" }>): string {
  const monitor = page.monitor;
  const check = monitor?.check;
  const entered = page.entered;
  const value = (name: string, fallback: unknown = ""): unknown => entered?.[name] ?? fallback;
  const checked = (name: string, fallback: boolean): boolean => entered ? entered[name] === "on" || entered[name] === "true" : fallback;
  const kind = String(value("kind", check?.kind ?? "http"));
  const http = check?.kind === "http" ? check : null;
  const dns = check?.kind === "dns" ? check : null;
  const websocket = check?.kind === "websocket" ? check : null;
  const socket = check?.kind === "tcp" || check?.kind === "tls" ? check : null;
  const heartbeat = check?.kind === "heartbeat" ? check : null;
  const action = monitor ? `${monitorPath(page, monitor)}/edit` : `${accountPath(page)}/new-monitor`;
  const open = (nonDefault: boolean): string => nonDefault || Boolean(entered) ? " open" : "";
  const literal = (name: string, label: string, current: string | undefined): string => `<div class="field full">
    ${checkbox(`${name}Enabled`, label, checked(`${name}Enabled`, current !== undefined))}<label for="${name}">${escape(label)} value (an empty string is meaningful)</label>
    <textarea id="${name}" name="${name}" maxlength="4096">${escape(value(name, current ?? ""))}</textarea></div>`;
  const headerChoices: Record<string, string> = http?.hasHeaders ? { keep: "Keep stored values", replace: "Replace values", remove: "Remove headers" } : { remove: "No headers", replace: "Supply values" };
  const webhookChoices: Record<string, string> = monitor?.webhook ? { keep: "Keep destination and secret", replace: "Replace destination and secret", remove: "Remove webhook" } : { remove: "No webhook", replace: "Configure webhook" };
  const emailChoices: Record<string, string> = monitor?.email ? { keep: "Keep destination", replace: "Replace destination", remove: "Remove email" } : { remove: "No email", replace: "Configure email" };
  return heading(monitor ? `Edit ${monitor.name}` : "Add monitor", "Start with the destination. Advanced controls keep their meaningful defaults; secret values are never prefilled.") +
    panel("Check configuration", `<form method="post" action="${action}" data-monitor-form>
      ${csrf(page.csrfToken)}${monitor ? hidden("revision", value("revision", monitor.revision)) : ""}
      <fieldset><legend>Basics</legend><div class="form-grid">
        ${select("kind", "Check type", CHECK_LABELS, kind)}
        ${field("name", "Display name", value("name", monitor?.name), { required: Boolean(monitor), maxLength: 120, help: monitor ? "" : "Optional for a new monitor; generated from the target when blank." })}
      </div><details${open(Boolean(monitor) || Boolean(entered?.id))}><summary>Identifier and cadence</summary><div class="form-grid">
        ${monitor ? field("monitor-id-display", "Identifier (unchanged)", monitor.id, { readonly: true }) :
          field("id", "Identifier", value("id"), { maxLength: 64, pattern: "[A-Za-z0-9_\\-]{1,64}", help: "Optional; generated when blank. If supplied: 1–64 letters, numbers, hyphens or underscores." })}
        ${field("intervalSeconds", "Interval (seconds)", value("intervalSeconds", monitor ? monitor.intervalMs / 1000 : 60), { type: "number", min: 60, max: 2592000, step: "0.001", required: true, help: "Minimum 60 seconds. For heartbeat, the expected pulse period." })}
      </div></details><p class="help" data-usage-estimate>At 60 seconds: at most 1,440 primary checks/day · 43,200 per 30 days. Heartbeat usage depends on accepted pulses; no commercial price is configured.</p></fieldset>
      <fieldset data-check-kinds="http websocket"><legend>URL destination</legend><div class="form-grid">
        ${field("url", "Target URL", value("url", http?.url ?? websocket?.url), { type: "url", full: true, help: "HTTP(S): http:// or https://. WebSocket: ws:// or wss://. No embedded credentials or private network targets." })}
      </div></fieldset>
      <fieldset data-check-kinds="http"><legend>HTTP / HTTPS</legend><details${open(Boolean(http && (http.method === "HEAD" || http.status?.length || http.contains !== undefined || http.hasHeaders || http.maxBodyBytes !== 65536 || http.maxRedirects !== 3)))}><summary>Assertions, headers and response bounds</summary><div class="form-grid">
        ${select("method", "Method", { GET: "GET", HEAD: "HEAD" }, String(value("method", http?.method ?? "GET")))}
        ${field("status", "Allowed status codes", value("status", http?.status?.join(", ")), { help: "Comma-separated; blank accepts any 200–299 response." })}
        ${literal("contains", "Require literal response content", http?.contains)}
        ${field("maxBodyBytes", "Maximum decoded response bytes", value("maxBodyBytes", http?.maxBodyBytes ?? 65536), { type: "number", min: 1, max: 262144, step: "1" })}
        ${field("maxRedirects", "Maximum redirects", value("maxRedirects", http?.maxRedirects ?? 3), { type: "number", min: 0, max: 5, step: "1" })}
        ${select("headersMode", "HTTP header values", headerChoices, String(value("headersMode", http?.hasHeaders ? "keep" : "remove")), http?.hasHeaders ? `Stored names: ${http.headerNames.join(", ")}. Values cannot be retrieved.` : "Values are used only when supplying/replacing.")}
        ${textarea("headers", "Replacement HTTP headers (JSON object)", "", 'Secret-bearing values must be re-entered after any failed submission. Host, framing, hop-by-hop and proxy headers cannot be replaced.')}
      </div></details></fieldset>
      <fieldset data-check-kinds="dns"><legend>DNS assertion</legend><div class="form-grid">
        ${field("dnsName", "DNS name", value("dnsName", dns?.name), { help: "Hostname, not a URL." })}
        ${select("recordType", "Record type", { A: "A", AAAA: "AAAA", MX: "MX", TXT: "TXT", NS: "NS", CNAME: "CNAME" }, String(value("recordType", dns?.recordType ?? "A")))}
        ${textarea("expected", "Expected answers (one per line)", String(value("expected", dns?.expected?.join("\n"))), "Blank accepts returned records. MX: priority and host, e.g. 10 mail.example.com. Trusted resolver is fixed.")}
      </div></fieldset>
      <fieldset data-check-kinds="tcp tls"><legend>TCP / TLS destination</legend><div class="form-grid">
        ${field("hostname", "Hostname or public IP address", value("hostname", socket?.hostname), { help: "Public targets only; TLS verifies the original hostname/IP certificate identity." })}
        ${field("port", "Port", value("port", socket?.port), { type: "number", min: 1, max: 65535, step: "1" })}
      </div><details${open(Boolean(socket && socket.maxResponseBytes !== 16384))}><summary>Response bound</summary>
        ${field("maxResponseBytes", "Maximum response bytes", value("maxResponseBytes", socket?.maxResponseBytes ?? 16384), { type: "number", min: 1, max: 65536, step: "1" })}
      </details></fieldset>
      <fieldset data-check-kinds="websocket tcp tls"><legend>Message / banner</legend><details${open(Boolean(websocket?.send !== undefined || websocket?.expect !== undefined || socket?.send !== undefined || socket?.expect !== undefined))}><summary>Send text or require a literal reply</summary><div class="form-grid">
        ${literal("send", "Send literal text", websocket?.send ?? socket?.send)}
        ${literal("expect", "Require literal reply", websocket?.expect ?? socket?.expect)}
      </div><p class="help">WebSocket: one bounded complete message. TCP/TLS: bounded response prefix.</p></details></fieldset>
      <fieldset data-check-kinds="websocket"><legend>WebSocket limit</legend><details${open(Boolean(websocket && websocket.maxMessageBytes !== 16384))}><summary>Message bound</summary>
        ${field("maxMessageBytes", "Maximum message bytes", value("maxMessageBytes", websocket?.maxMessageBytes ?? 16384), { type: "number", min: 1, max: 65536, step: "1" })}
      </details></fieldset>
      <fieldset data-check-kinds="heartbeat"><legend>Heartbeat deadline</legend>
        ${field("graceSeconds", "Extra grace (seconds)", value("graceSeconds", heartbeat?.graceMs ? heartbeat.graceMs / 1000 : ""), { type: "number", min: 0.001, max: 604800, step: "0.001", help: "Blank adds none. A token is revealed once after creation." })}
      </fieldset>
      <fieldset data-check-kinds="http tls"><legend>Certificate evidence</legend><details${open(Boolean(monitor && monitor.certificateExpiryDays !== 14))}><summary>Certificate-expiry threshold</summary>
        ${field("certificateExpiryDays", "Warn when certificate expires within (days)", value("certificateExpiryDays", monitor?.certificateExpiryDays ?? 14), { type: "number", min: 0, max: 365, step: "1", help: "HTTPS/TLS, actual transport evidence only. Warnings are separate from outage state. Zero disables early warning, not certificate identity/validity verification. Missing evidence is not proof of validity." })}
      </details></fieldset>
      <details${open(Boolean(monitor && (monitor.timeoutMs !== 5000 || monitor.confirmationDelayMs !== 1000 || monitor.executionWindowMs !== 60000)))}><summary>Advanced scheduling bounds</summary><div class="form-grid">
        ${field("timeoutSeconds", "Timeout (seconds)", value("timeoutSeconds", monitor ? monitor.timeoutMs / 1000 : 5), { type: "number", min: 0.1, max: 30, step: "0.001", required: true })}
        ${field("confirmationDelaySeconds", "Confirmation delay (seconds)", value("confirmationDelaySeconds", monitor ? monitor.confirmationDelayMs / 1000 : 1), { type: "number", min: 0.1, max: 60, step: "0.001", required: true })}
        ${field("executionWindowSeconds", "Execution window (seconds)", value("executionWindowSeconds", monitor ? monitor.executionWindowMs / 1000 : 60), { type: "number", min: 0.6, max: 300, step: "0.001", required: true, help: "Must include target timeout and validated executor-start/RPC allowance. Late work is unknown/missed coverage." })}
      </div></details>
      ${!monitor ? defaultsOptIn(page.notificationDefaults) : ""}
      <details${open(Boolean(monitor?.webhook || monitor?.email))}><summary>Monitor-specific alerts — optional</summary>
        <fieldset><legend>Signed webhook</legend><div class="form-grid">
          ${select("webhookMode", "Webhook configuration", webhookChoices, String(value("webhookMode", monitor?.webhook ? "keep" : "remove")))}
          ${field("webhookUrl", "Replacement HTTPS destination", value("webhookUrl", monitor?.webhook?.url), { type: "url", help: "Used only for replace; saving is not a test send." })}
          ${field("webhookSecret", "Replacement signing secret", "", { type: "password", autocomplete: "new-password", maxLength: 256, help: "16–256 characters. Never recovered or redisplayed." })}
        </div></fieldset>
        <fieldset><legend>Email</legend>${!page.emailConfigured ? '<p class="help">Email transport is not configured; no simulated send or automatic substitute.</p>' : ""}
          <div class="form-grid">${select("emailMode", "Email configuration", page.emailConfigured ? emailChoices : (monitor?.email ? { keep: "Keep destination", remove: "Remove email" } : { remove: "Email not configured" }), String(value("emailMode", monitor?.email ? "keep" : "remove")))}
          ${page.emailConfigured ? field("emailAddress", "Replacement email destination", value("emailAddress"), { type: "email", help: monitor?.email ? `Current: ${monitor.email.address}. Replace only; use an approved recipient.` : "Replace only; use an approved recipient." }) : ""}</div>
        </fieldset>
      </details>
      <noscript><p class="help">All protocol sections are available without JavaScript; only the selected check type is used. Open advanced sections to change their default values. The server validates required protocol fields.</p></noscript>
      <div class="actions form-actions"><button class="primary" type="submit">${monitor ? "Save monitor" : "Create monitor"}</button>
        <a class="button" href="${monitor ? monitorPath(page, monitor) : accountPath(page)}">Cancel</a></div>
      <p class="help" data-submit-status role="status"></p>
    </form>`);
}

function heartbeatToken(page: Extract<UiPage, { kind: "heartbeat-token" }>): string {
  const detailPath = monitorPath(page, page.monitor);
  return heading("Heartbeat token", page.monitor.name) + panel("Save this token now", `
    <div class="warning">This token is shown once. Treat it like a password. It is not stored in browser storage by Tomato; keep it in your job's secret configuration.</div>
    ${secretReveal("heartbeat-secret", page.heartbeatToken)}<p>Send POST requests to <code>${escape(page.heartbeatUrl)}</code> with:</p>
    <pre>Authorization: Bearer &lt;your saved token&gt;\nIdempotency-Key: &lt;a new unique pulse ID&gt;</pre>
    <p>Use the same pulse ID when retrying one pulse. Use a new ID for the next real pulse.
      ${page.mode === "self-host" ? "One unique accepted pulse records one usage unit without enforcing a paid-credit balance." : "One unique accepted pulse uses one credit; no-credit ingestion returns an explicit error."} Duplicates add no usage. Paused monitors reject ingestion.</p>
    <a class="button primary" href="${detailPath}">I saved the token — open monitor</a>`);
}

function wallet(page: Extract<UiPage, { kind: "wallet" }>): string {
  if (page.wallet.mode === "self-host") return heading("Usage ledger", "Self-hosted monitoring has no paid credit balance or depletion cutoff.") + walletSummary(page.wallet) +
    panel("Eligible monitoring work", `<dl class="details"><dt>Scheduled primary checks/day</dt><dd>${number(page.wallet.forecastChecksPerDay)} (estimate for active outbound monitors)</dd></dl><ul><li>One accepted primary target observation adds one usage unit, including a target failure or timeout.</li><li>One unique accepted heartbeat pulse adds one usage unit; duplicate pulse IDs add none.</li><li>Confirmations, alert delivery retries, internal/unknown results, cancelled work and missed slots add no usage.</li></ul><p>Usage records describe actual eligible work. They are not a payment balance and do not stop self-hosted monitoring.</p>`);
  const grants = page.wallet.grants.map(grant => `<tr><td class="mono wrap">${escape(grant.id)}</td>
    <td>${number(grant.credits)}</td><td class="wrap">${escape(grant.reason)}</td><td>${timestamp(grant.createdAt)}</td></tr>`).join("");
  return heading("Credits and usage", "Exact engine credits, not a simulated commercial wallet.") + walletSummary(page.wallet) +
    panel("Usage and forecast", `<dl class="details"><dt>Credit source</dt><dd>Auditable operator-issued testing grants</dd>
      <dt>Scheduled primary checks/day</dt><dd>${number(page.wallet.forecastChecksPerDay)} (estimate for active outbound monitors)</dd>
      <dt>Estimated depletion</dt><dd>${timestamp(page.wallet.estimatedDepletionAt)}</dd></dl>
      <p class="help">The forecast assumes every scheduled primary reaches a billable observation. Pauses, unknown results and skipped work change consumption.
        Heartbeat credits depend on actual accepted pulses, not this cadence forecast.</p>
      <ul><li>One accepted primary target observation costs one credit, including a target failure or timeout.</li>
        <li>One unique accepted heartbeat pulse costs one credit; duplicate pulse IDs are free.</li>
        <li>Confirmation, alert delivery retries, internal/unknown results, cancelled work and missed slots cost zero.</li>
        <li>Reservation prevents a running check's credits from being spent twice.</li>
        <li>Insufficient credits means UNKNOWN/unobserved coverage. It never backfills success.</li></ul>
      <p>No payment processor, commercial price, purchase or automatic refill is configured in this pilot.
        Ask your operator for a testing grant; there is no customer credit mutation endpoint.</p>`) +
    panel("Testing grant history", grants ? `<div class="table-scroll"><table><caption>Actual credit grant receipts</caption>
      <thead><tr><th scope="col">Receipt</th><th scope="col">Credits</th><th scope="col">Reason</th><th scope="col">Granted</th></tr></thead>
      <tbody>${grants}</tbody></table></div>` : '<p class="empty">No grant receipts recorded.</p>');
}

function notifications(page: Extract<UiPage, { kind: "notifications" }>): string {
  const canEdit = page.account.role !== "viewer";
  return heading("Alert destinations and deliveries", "Signed webhooks, configured email and actual transport status.") +
    panel("Configured destinations", `${!page.emailConfigured ? '<p class="warning">Email is not configured. There is no silent substitute or simulated send.</p>' : ""}
      ${page.monitors.length ? `<ul>${page.monitors.map(monitor => `<li class="wrap">
        <a href="${monitorPath(page, monitor)}">${escape(monitor.name)}</a>: ${escape(monitor.webhook?.url ?? "No webhook")}
        ${monitor.email ? ` · ${escape(monitor.email.address)} (email)` : " · No email"}
        ${canEdit ? `<a href="${monitorPath(page, monitor)}/edit">Configure</a>` : ""}</li>`).join("")}</ul>` :
        '<p class="empty">Add a monitor to configure a destination.</p>'}`) +
    panel("Webhook verification", '<p>Verify HMAC-SHA256 over <code>&lt;X-Tomato-Timestamp&gt;.&lt;raw JSON body&gt;</code> using your saved signing secret and compare it to <code>X-Tomato-Signature</code>. Deduplicate recipient effects using <code>Idempotency-Key</code>.</p><p>Delivery is at least once. A successful response means the transport accepted the request, not that a person read it or an email reached an inbox. Tests are sent only when explicitly requested on a monitor.</p>') +
    panel("Delivery status", deliveryTable(page, page.deliveries));
}

function statusPageEditor(page: Extract<UiPage, { kind: "status-page-edit" }>): string {
  const config = page.page;
  const path = `${accountPath(page)}/status-page`;
  const canEdit = page.account.role === "owner";
  let form: string;
  if (canEdit) {
    const selected = new Map(config?.components.map(component => [component.monitorId, component.label]));
    form = `<form method="post" action="${path}">${csrf(page.csrfToken)}${hidden("revision", page.pageRevision ?? config?.revision ?? 0)}<div class="form-grid">${field("slug", "Public URL slug", config?.slug ?? "", { required: true, pattern: "[a-z0-9][a-z0-9\\-]{1,61}[a-z0-9]", maxLength: 63, help: "3–63 lowercase letters, numbers or hyphens; start and end with a letter or number. Publishing makes selected status information public." })}${field("title", "Public page title", config?.title ?? page.account.name, { required: true, maxLength: 120 })}</div><fieldset><legend>Opted-in public components</legend><p class="help">Nothing is selected automatically. Labels are public; targets, private check settings, header values, webhook destinations and wallet data are not published.</p>${page.monitors.map(monitor => `<div class="panel">${checkbox("componentId", monitor.name, selected.has(monitor.id), monitor.id)}${field(`componentLabel_${monitor.id}`, "Public component label", selected.get(monitor.id) ?? monitor.name, { maxLength: 120 })}</div>`).join("") || '<p class="empty">No monitors available. Add one before publishing.</p>'}</fieldset>${checkbox("published", "Publish this page and selected components publicly", config?.published ?? false)}<div class="actions form-actions"><button class="primary" type="submit">Save public page configuration</button></div></form>`;
  } else {
    form = `<p>Only workspace owners can modify publication.</p><dl class="details"><dt>Title</dt><dd>${escape(config?.title ?? "Not configured")}</dd><dt>Publication</dt><dd>${config?.published ? "Published" : "Unpublished"}</dd><dt>Components</dt><dd>${escape(config?.components.map(component => component.label).join(", ") ?? "None")}</dd></dl>`;
  }
  const updates = config?.updates ?? [];
  const updateForm = canEdit && config ? `<form method="post" action="${path}/updates">${csrf(page.csrfToken)}${hidden("revision", config.revision)}${select("incidentId", "Incident to update", Object.fromEntries(page.incidents.map(incident => [incident.id, `${incident.monitorId} — ${new Date(incident.openedAt).toISOString()}`])), page.incidents[0]?.id ?? "")}${textarea("body", "Public customer-safe update", "", "This text is public. Do not include private URLs, tokens, response bodies or account details.", true)}<button class="primary" type="submit"${page.incidents.length ? "" : " disabled"}>Publish incident update</button></form>` : "";
  return heading("Public status page", "Deliberate opt-in publication with visible observation freshness.", config?.published ? `<a class="button" href="/status/${encodeURIComponent(config.slug)}" target="_blank" rel="noopener noreferrer">Open public page</a>` : "") + panel("Publication settings", form) + (canEdit && config?.published ? panel("Unpublish", `<p>Remove the public page from serving. Internal monitor data and configuration remain.</p>${actionForm(`${path}/unpublish`, page.csrfToken, `Unpublish ${config.slug}`, { revision: config.revision }, "danger")}`) : "") + panel("Public incident updates", `${updateForm}${updates.length ? updates.map(update => `<article class="panel"><p class="small">${timestamp(update.publishedAt)} · ${escape(update.incidentId)}</p><div class="public-update">${escape(update.body)}</div>${canEdit ? `<details><summary>Remove this public update…</summary><p>Remove this exact update from the public page.</p>${actionForm(`${path}/updates/remove`, page.csrfToken, "Remove update", { updateId: update.id, revision: config!.revision }, "danger")}</details>` : ""}</article>`).join("") : '<p class="empty">No public updates published.</p>'}`);
}

function readinessSummary(readiness: ReadinessView): string {
  return panel("Deployment readiness", `<dl class="details">
    <dt>Access</dt><dd>Verified identities and membership-based workspace permissions; no commercial payments</dd>
    <dt>Check bounds</dt><dd>Minimum ${number(readiness.limits.minimumIntervalMs / 1000)} seconds · ${number(readiness.limits.maxMonitors)} monitors/workspace</dd>
    <dt>Transport capacity</dt><dd>${readiness.limits.proberConcurrency === null ? "Prober not configured" : `${number(readiness.limits.proberConcurrency)} simultaneous probes per configured runner`} · capacity ${escape(readiness.capacity)}</dd>
    <dt>Confirmation / geography</dt><dd>${escape(readiness.confirmation)} · geographic coverage ${escape(readiness.geographicCoverage)}</dd>
    <dt>SQL observation retention</dt><dd>${number(readiness.limits.sqlHistoryDays)} days</dd>
    <dt>Email</dt><dd>${readiness.emailConfigured ? "Transport configured; explicit approved-recipient tests still required" : "Not configured"}</dd>
    </dl>${readiness.blockers.length ? `<p class="help">Release prerequisites:</p><ul>${readiness.blockers.map(blocker => `<li>${escape(blocker)}</li>`).join("")}</ul>` : ""}`);
}

function notificationDefaults(page: Extract<UiPage, { kind: "settings" }>): string {
  const defaults = page.notificationDefaults;
  if (!defaults) return "";
  const canEdit = page.account.role !== "viewer";
  return `<section id="notification-defaults">${panel("Reusable alert destinations", `
    <p>Defaults are copied only when you opt in while creating a monitor. Existing monitors retain their destinations. Saving does not send a test; test the configured monitor explicitly.</p>
    <dl class="details"><dt>Webhook</dt><dd>${escape(defaults.webhook?.url ?? "None")}</dd><dt>Email</dt><dd>${escape(defaults.email?.address ?? "None")}</dd></dl>
    ${canEdit ? `<form method="post" action="${accountPath(page)}/settings/notification-defaults" data-destination-form>
      ${csrf(page.csrfToken)}${hidden("revision", defaults.revision)}<div class="form-grid">
      ${select("webhookMode", "Webhook default", defaults.webhook ? { keep: "Keep destination and secret", replace: "Replace", remove: "Remove" } : { remove: "No webhook", replace: "Configure" }, defaults.webhook ? "keep" : "remove")}
      ${field("webhookUrl", "Replacement webhook HTTPS URL", "", { type: "url", help: "Used only for replace." })}
      ${field("webhookSecret", "Replacement signing secret", "", { type: "password", autocomplete: "new-password", maxLength: 256, help: "16–256 characters; stored secret is never retrieved." })}
      ${select("emailMode", "Email default", page.emailConfigured ? (defaults.email ? { keep: "Keep destination", replace: "Replace", remove: "Remove" } : { remove: "No email", replace: "Configure" }) : (defaults.email ? { keep: "Keep destination", remove: "Remove" } : { remove: "Email not configured" }), defaults.email ? "keep" : "remove")}
      ${page.emailConfigured ? field("emailAddress", "Replacement email address", "", { type: "email", help: "Use an approved intended recipient; saving does not send." }) : ""}</div>
      <div class="form-actions"><button type="submit">Save defaults for future monitors</button></div></form>` : '<p class="help">Your viewer role cannot change defaults.</p>'}
  `)}</section>`;
}

function settings(page: Extract<UiPage, { kind: "settings" }>): string {
  const base = accountPath(page);
  const path = `${base}/settings`;
  const actions = [
    ["api-keys", "Agent connection and API keys", "Connect your agent; create/revoke account-scoped keys."],
    ["import-export", "Import / export", "Atomic versioned monitor configuration; secrets omitted."],
    ["status-page", "Public status", "Deliberate public components and customer-safe incident updates."],
    ["wallet", page.mode === "self-host" ? "Usage ledger" : "Credits and usage", page.mode === "self-host" ? "Eligible observations and pulses; no paid balance or cutoff." : "Exact testing credits, forecast and grant receipts."],
    ["audit", "Audit trail", "Review consequential changes and their actors."],
    ...(page.account.role === "owner" ? [["team", "Workspace team", "Roles, members and expiring private invitations."]] : []),
  ];
  return heading("Settings and actions", `${page.account.name} · signed in as ${page.actor.username}`) +
    panel("Workspace tools", `<ul class="action-directory">${actions.map(([route, title, description]) => `<li><a href="${base}/${route}"><strong>${escape(title)}</strong></a><span class="help">${escape(description)}</span></li>`).join("")}</ul>
      <p><a href="#notification-defaults">Reusable alert destinations</a> · <a href="#security">Password and sessions</a>. Maintenance is scheduled from the relevant monitor; reports are opened from Monitors.</p>`) +
    (page.account.role === "owner" ? panel("Workspace name", `<form method="post" action="${path}/workspace">${csrf(page.csrfToken)}
      ${field("name", "Workspace display name", page.account.name, { required: true, maxLength: 120 })}
      <div class="form-actions"><button type="submit">Save workspace name</button></div></form>`) : "") +
    notificationDefaults(page) +
    (page.readiness ? readinessSummary(page.readiness) : "") +
    `<section id="security">${panel("Change password", `<details><summary>Change your password…</summary><form method="post" action="${path}/password">${csrf(page.csrfToken)}
      <div class="form-grid">
        ${field("currentPassword", "Current password", "", { type: "password", autocomplete: "current-password", required: true })}
        ${field("newPassword", "New password", "", { type: "password", autocomplete: "new-password", required: true, help: "Use a long unique password. Passwords are never redisplayed." })}
      </div><div class="form-actions"><button class="primary" type="submit">Change password</button></div></form></details>
      <p class="help"><a href="/forgot-password">Email password recovery</a> is available when your administrator has configured SMTP.</p>`)}</section>` +
    panel("Your active sessions", `<p>Revocation takes effect on the next request. Revoking this session signs you out.</p>
      <div class="table-scroll"><table><caption>Your actual browser sessions</caption>
        <thead><tr><th scope="col">Session</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Action</th></tr></thead>
        <tbody>${page.sessions.map(session => `<tr>
          <td>${session.current ? "This session" : "Other session"}<span class="help mono wrap">${escape(session.id)}</span></td>
          <td>${timestamp(session.createdAt)}</td><td>${timestamp(session.expiresAt)}</td>
          <td>${actionForm(`${path}/sessions/revoke`, page.csrfToken, session.current ? "Sign out this session" : "Revoke session", { sessionId: session.id })}</td>
        </tr>`).join("")}</tbody></table></div>
        <div class="form-actions">${actionForm(`${path}/sessions/revoke-others`, page.csrfToken, "Revoke all other sessions")}</div>`);
}

function team(page: Extract<UiPage, { kind: "team" }>): string {
  const path = `${accountPath(page)}/team`;
  const owner = page.account.role === "owner";
  const roles: Record<string, string> = { owner: "Owner", editor: "Editor", viewer: "Viewer" };
  return heading("Workspace team", "Owner-managed roles and expiring invitation links.") + panel("Roles", `<dl class="details">${(Object.keys(ROLE_DESCRIPTIONS) as AccountRole[]).map(role => `<dt>${escape(role)}</dt><dd>${escape(ROLE_DESCRIPTIONS[role])}</dd>`).join("")}</dl><p class="help">At least one owner must remain. Membership and role changes apply on the next request; API keys never exceed their creator's current role.</p>`) + panel("Members", `<div class="table-scroll"><table><caption>Members of ${escape(page.account.name)}</caption><thead><tr><th scope="col">Email</th><th scope="col">Role</th>${owner ? '<th scope="col">Change role</th><th scope="col">Remove</th>' : ""}</tr></thead><tbody>${page.members.map(member => `<tr><td class="wrap">${escape(member.username)}${member.userId === page.actor.id ? ' <span class="help">You</span>' : ""}</td><td>${escape(member.role)}</td>${owner ? `<td><form method="post" action="${path}/members/role">${csrf(page.csrfToken)}${hidden("userId", member.userId)}<label class="small" for="role-${escape(member.userId)}">New role for ${escape(member.username)}</label><select name="role" id="role-${escape(member.userId)}">${Object.entries(roles).map(([role, label]) => `<option value="${role}"${role === member.role ? " selected" : ""}>${label}</option>`).join("")}</select><button type="submit">Save role</button></form></td><td><details><summary>Remove…</summary><p>Remove ${escape(member.username)} from ${escape(page.account.name)}.</p>${actionForm(`${path}/members/remove`, page.csrfToken, `Remove ${member.username}`, { userId: member.userId }, "danger")}</details></td>` : ""}</tr>`).join("")}</tbody></table></div>`) + (owner ? panel("Create invitation", `<form method="post" action="${path}/invitations">${csrf(page.csrfToken)}<div class="form-grid">${field("username", "Invited email address", "", { type: "email", required: true, maxLength: 254, autocomplete: "off", help: "The link is bound to this actual email identity. Share it directly with the intended person; invitation links are not sent automatically." })}${select("role", "Granted role", roles, "viewer")}</div><div class="form-actions"><button class="primary" type="submit">Create 7-day invitation link</button></div></form>`) : "") + panel("Invitations", page.invitations.length ? `<div class="table-scroll"><table><caption>Invitation status; plaintext links are not recoverable</caption><thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Expires</th>${owner ? '<th scope="col">Action</th>' : ""}</tr></thead><tbody>${page.invitations.map(invitation => `<tr><td class="wrap">${escape(invitation.username)}</td><td>${escape(invitation.role)}</td><td>${escape(invitation.status)}</td><td>${timestamp(invitation.expiresAt)}</td>${owner ? `<td>${invitation.status === "pending" ? actionForm(`${path}/invitations/revoke`, page.csrfToken, "Revoke invitation", { invitationId: invitation.id }, "danger") : "—"}</td>` : ""}</tr>`).join("")}</tbody></table></div>` : '<p class="empty">No invitations.</p>');
}

function agentConnection(page: AuthenticatedView): string {
  const endpoint = `${page.origin ?? ""}/mcp`;
  return panel("Connect an agent", `<ol class="setup-steps">
    <li>Create a read-only key below, or deliberately choose a broader scope for management.</li>
    <li>Save the once-shown key in your client's secret manager. Use it as an Authorization bearer header; never include it in a URL.</li>
    <li>Connect using Streamable HTTP, or the included stdio bridge. Account tools use <code>accountId: ${escape(JSON.stringify(page.account.id))}</code>.</li>
    </ol><dl class="details"><dt>MCP endpoint</dt><dd><code id="mcp-endpoint">${escape(endpoint)}</code>${copyControl("mcp-endpoint", "Copy MCP endpoint")}</dd>
    <dt>Transport</dt><dd>Streamable HTTP; authenticated bearer header. No hosted OAuth connector is claimed.</dd>
    <dt>Workspace</dt><dd><code>${escape(page.account.id)}</code> · current role ${escape(page.account.role)}</dd></dl>
    <details><summary>Stdio client configuration</summary>
      <p>Use Node 24 or newer. Set the client command to <code>node</code> and its sole argument to the <strong>absolute path</strong> of <code>scripts/agent-stdio.ts</code> inside your Tomato installation. Do not pass a relative path, working-directory-dependent loader or secret argument. Configure the process environment:</p>
      <pre id="stdio-config">TOMATO_MCP_URL=${escape(endpoint)}\nTOMATO_API_KEY=&lt;key supplied by your client secret manager&gt;</pre>
      <p class="help">Direct Node launch does not require the client to start in your project directory. Alternatively, use <code>npm run --silent agent:stdio</code> only with the client's working directory explicitly set to your Tomato installation; keep <code>--silent</code> to prevent npm's lifecycle banner from corrupting protocol stdout. The bridge receives newline-framed MCP on stdin/stdout. Diagnostics never include the key. Client schemas differ; use these exact environment names with your client's secret settings.</p>
    </details><p class="help">Membership, expiry, revocation and scope are checked on each operation. Agent-issued derived keys remain bound to their source key's validity/scope; revoking a source cascades to every derived grant. Independent personal root keys are separate. Management never grants operator provisioning, testing-credit grants or recovery.</p>`);
}

function apiKeys(page: Extract<UiPage, { kind: "api-keys" }>): string {
  const path = `${accountPath(page)}/api-keys`;
  const parentLabels = new Map<string, string>();
  for (const key of page.keys) parentLabels.set(key.id, key.name);
  const scopes: Record<string, string> = {
    read: "Read only (recommended first connection)",
    ...(page.account.role !== "viewer" ? { write: "Monitoring and configuration writes" } : {}),
    manage: "Agent management within my current workspace role",
  };
  return heading("Agent connection and API keys", "Account-bound, expiring keys; your current membership remains authoritative.", `<a class="button" href="${accountPath(page)}/api-docs">Management API</a>`) +
    agentConnection(page) +
    panel("Create a scoped key", `<form method="post" action="${path}">${csrf(page.csrfToken)}<div class="form-grid">
      ${field("name", "Key label", "My agent", { required: true, maxLength: 120, help: "Label only; never enter a secret here." })}
      ${select("scope", "Scope", scopes, "read")}
      ${field("expiresInDays", "Expires in days", 30, { type: "number", min: 1, max: 90, step: "1", required: true })}</div>
      <p class="warning">Manage delegates the actions your current role permits, including your own security/key controls. It does not make a viewer/editor an owner. Owners should deliberately review team and public-publication authority before granting manage. Operator provisioning, credit grants and recovery are never delegated.</p>
      <p class="help">Only a hash is stored. Save the once-shown key in your client's secret manager; read is the safe default. Keys issued by an agent are source-bound; revoking their source also revokes its derived keys. Personal keys issued here are independent roots.</p>
      <div class="form-actions"><button class="primary" type="submit">Create and reveal key once</button></div></form>`) +
    panel("Your keys for this workspace", page.keys.length ? `<div class="table-scroll"><table><caption>Your account-scoped keys; secret values are not recoverable</caption>
      <thead><tr><th scope="col">Label</th><th scope="col">Scope</th><th scope="col">Created / expires</th><th scope="col">Last used</th><th scope="col">Action</th></tr></thead>
      <tbody>${page.keys.map(key => `<tr><td class="wrap">${escape(key.name)}<span class="help mono">${escape(key.id)}</span>
        <span class="help">${key.parentKeyId ? `Derived from ${escape(parentLabels.get(key.parentKeyId) ?? key.parentKeyId)}<span class="mono"> (${escape(key.parentKeyId)})</span>` : "Independent personal root key"}</span></td><td>${escape(key.scope)}</td>
        <td>${timestamp(key.createdAt)}<span class="help">${timestamp(key.expiresAt)}</span></td><td>${timestamp(key.lastUsedAt)}</td>
        <td><details><summary>Revoke…</summary><p>Immediately revoke ${escape(key.name)} and all keys derived from it. Independent personal root keys are unaffected.</p>${actionForm(`${path}/revoke`, page.csrfToken, "Revoke key and derived grants", { keyId: key.id }, "danger")}</details></td></tr>`).join("")}</tbody></table></div>` : '<p class="empty">No API keys created by you for this workspace.</p>');
}

function importExport(page: Extract<UiPage, { kind: "import-export" }>): string {
  const importPath = `${accountPath(page)}/monitors/import`;
  const revelations = page.importedHeartbeats?.length ? panel("Save imported heartbeat tokens now", `
    <p class="warning">These newly generated tokens are shown once. Store them in the corresponding jobs' secret configuration.
      Export does not include tokens, and Tomato does not persist them in browser storage.</p>
    ${page.importedHeartbeats.map(heartbeat => `<article class="panel">
      <h3>${escape(heartbeat.name)} <span class="small mono">${escape(heartbeat.monitorId)}</span></h3>
      <p>POST endpoint: <code>${escape(heartbeat.url)}</code></p>${secretReveal(`import-secret-${heartbeat.monitorId}`, heartbeat.token)}
      <p class="help">Send Authorization: Bearer &lt;saved token&gt; and a new unique Idempotency-Key per real pulse. Retry one pulse with the same ID.</p>
      <a href="${accountPath(page)}/monitors/${encodeURIComponent(heartbeat.monitorId)}">Open monitor</a>
    </article>`).join("")}`) : "";
  return heading("Import and export", "Versioned monitoring configuration, with explicit secret omissions.") +
    (page.importedCount !== undefined ? `<p class="notice" role="status">Imported ${number(page.importedCount)} monitors.</p>` : "") + revelations +
    panel("Export configuration", `<p>Download actual check, scheduling, alert and configured pause settings. HTTP header values, webhook secrets and heartbeat tokens are omitted and marked explicitly.
      Export is not a backup of secrets.</p><a class="button" href="/api/accounts/${encodeURIComponent(page.account.id)}/export"
      download="tomato-monitor-configuration.json">Download redacted configuration</a>`) +
    (page.account.role !== "viewer" ? panel("Import configuration", `
      <div class="warning">Imports are atomic and bounded to 100 monitors / 1 MiB. An export marked with omitted secrets cannot be imported unchanged:
        supply replacement values or explicitly remove the omitted configuration. Review every target before submitting.
        Paused imports remain PAUSED until you resume them; active imports start UNKNOWN until a real observation. Observed health, incident history and wallet data are not restored.
        Save any newly issued heartbeat tokens on the import result page.</div>
      <form method="post" action="${importPath}">${csrf(page.csrfToken)}
        ${textarea("configuration", "Version 1 monitor JSON", "", 'Shape: {"version":1,"monitors":[{"id":"api","name":"API","check":{"kind":"http","url":"https://example.com/health"},"intervalMs":60000,"paused":true}]}. Duplicate identifiers are rejected; do not paste credentials into untrusted tools.', true)}
        <div class="form-actions"><button class="primary" type="submit">Import reviewed configuration</button></div>
      </form>`) : panel("Import permissions", '<p>Your viewer role can export safe configuration but cannot import monitors.</p>'));
}

function apiDocs(page: Extract<UiPage, { kind: "api-docs" }>): string {
  const base = `/api/accounts/${encodeURIComponent(page.account.id)}`;
  const endpoints = [
    ["GET", "/state, /history, /incidents, /usage", "Read current monitoring and exact credit data"],
    ["GET / POST", "/monitors", "List / create monitors"],
    ["GET / PUT / DELETE", "/monitors/:id", "Read / update / delete; update and delete require revision"],
    ["POST", "/monitors/:id/pause, /monitors/:id/resume", "Pause or resume with current revision"],
    ["POST", "/monitors/bulk", "Atomic revision-fenced pause/resume of selected monitors"],
    ["POST", "/monitors/:id/heartbeat-token", "Rotate and reveal token once; requires revision"],
    ["POST", "/monitors/:id/notification-test", "Real configured-channel test; requires revision"],
    ["POST", "/monitors/:id/check-now", "Queue one real primary check with current revision; ordinary cadence unchanged"],
    ["GET", "/notifications", "Read transport channel, status, attempts and timestamps"],
    ["POST", "/notifications/:event/retry", "Retry a failed notification"],
    ["GET / PUT / DELETE", "/status-page", "Read / save / unpublish opted-in public configuration"],
    ["POST / DELETE", "/status-page/updates, /status-page/updates/:id", "Publish / remove public-safe incident text"],
    ["GET / POST", "/export, /monitors/import", "Redacted versioned export / atomic bounded import"],
    ["GET / POST / DELETE", "/api-keys, /api-keys/:id", "Your account-bound scoped keys"],
    ["GET / PUT / DELETE", "/members, /members/:userId", "List; owner-only role changes and removal"],
    ["GET / POST / DELETE", "/invitations, /invitations/:id", "Owner invitation management"],
    ["GET", "/audit", "Consequential changes; no secret values"],
    ["GET / PUT", "/workspace", "Read / owner-authorized rename; manage scope required for key writes"],
    ["GET / PUT", "/notification-defaults", "Redacted revision-fenced defaults; copied only by explicit creation opt-in"],
    ["GET / POST", "/maintenance", "List / schedule per-monitor maintenance windows"],
    ["DELETE", "/maintenance/:id", "Cancel a maintenance window"],
    ["GET", "/reports?monitorId=:id&from=:epochMs&to=:epochMs", "Time-based availability, coverage and retained latency; bounded seven-day window"],
    ["POST / DELETE", "/incidents/:id/acknowledgement", "Acknowledge / clear acknowledgement without changing observed health"],
  ];
  const example = { id: "api", name: "API health", check: { kind: "http", url: "https://example.com/health", status: [200] }, intervalMs: 60000, timeoutMs: 5000, confirmationDelayMs: 1000 };
  return heading("Management API", "Real account endpoints; customer clients do not need operator credentials.") +
    agentConnection(page) +
    (page.tools ? panel("Available agent tools", `<p>Tools advertised for your current role and scope; backend authorization applies on every call. Initialize <code>/mcp</code> and use <code>tools/list</code> to discover the live input schemas.</p>
      <details><summary>${page.tools.length} available tools</summary><dl class="details">${page.tools.map(tool => `<dt class="mono">${escape(tool.name)}</dt><dd>${escape(tool.description)}</dd>`).join("")}</dl></details>`) : "") +
    panel("Authentication", `<p>Send <code>Authorization: Bearer &lt;your scoped API key&gt;</code> to authorized account endpoints.
      Read is read-only. Write permits role-authorized monitoring/configuration changes. Manage also delegates your role-authorized workspace/security/key actions; it never elevates a viewer/editor to owner.</p>
      <p>Browser-cookie mutations additionally require the exact Origin and <code>X-CSRF-Token</code> from <code>GET /api/session</code>.
        Manage scope does not bypass current membership, current-password checks or operator-only boundaries. Never put credentials in URLs or browser storage.</p>
      <pre>curl ${escape(JSON.stringify(`${page.origin}${base}/state`))} \\\n  -H 'Authorization: Bearer &lt;your saved key&gt;'</pre>`) +
    panel("Account routes", `<p>All paths below start with <code>${escape(base)}</code>. The server enforces role, scope and current membership on every request.</p>
      <div class="table-scroll"><table><caption>Actual account management API</caption>
        <thead><tr><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Behavior</th></tr></thead>
        <tbody>${endpoints.map(([method, path, description]) => `<tr><td>${escape(method)}</td>
          <td class="mono wrap">${escape(path)}</td><td>${escape(description)}</td></tr>`).join("")}</tbody></table></div>`) +
    panel("Create and update", `<p>POST native JSON configuration. A new unsampled monitor is UNKNOWN.</p>
      <pre>${escape(JSON.stringify(example, null, 2))}</pre>
      <p>For PUT updates send the current <code>revision</code> and explicit <code>headersMode</code>, <code>webhookMode</code> and
        <code>emailMode</code> where applicable: <code>keep</code>, <code>replace</code> or <code>remove</code>.
        Keep never fetches stored secrets; replace must supply real replacement values. Stale revisions are rejected.</p>
      <p>DELETE, pause/resume, heartbeat rotation and notification tests also require <code>{"revision":&lt;current revision&gt;}</code>.
        Heartbeat creation/rotation and imports reveal newly generated tokens once. Never log secret-bearing responses.</p>`) +
    panel("Identity and recovery", '<p><code>GET /api/session</code>; <code>POST /api/auth/login</code>, <code>/api/auth/logout</code>, <code>/api/auth/password</code>; <code>GET /api/auth/sessions</code>; <code>DELETE /api/auth/sessions/:id</code>; <code>POST /api/auth/sessions/revoke-others</code>.</p><p>Credits are operator testing grants; no customer purchase/deposit endpoint exists. Operator account/grant/recovery routes are privileged and cannot be authorized by scoped management keys. Lost access requires the operator-assisted recovery path, not an unconfigured email reset.</p>');
}

function publicStatus(page: Extract<UiPage, { kind: "public-status" }>): string {
  const status = page.page;
  return heading(status.title, "Current component state. Unknown means there is no fresh supporting observation.") +
    panel("Components", `<p class="help">Generated ${timestamp(status.generatedAt)}. Configuration last updated ${timestamp(status.updatedAt)}.
      This is a snapshot. Refresh for current state; incident history does not prove that an old observation remains current.</p>
      <p><a class="button" href="/status/${encodeURIComponent(status.slug)}">Refresh status</a></p>
      ${status.components.length ? `<ul class="component-list">${status.components.map(component => `<li>
        <div class="component-heading"><strong class="wrap">${escape(component.label)}</strong>${state(component.state, component.freshUntil)}</div>
        <p class="small muted">Last observed ${timestamp(component.lastObservedAt)}${component.freshUntil ? ` · Evidence expires ${timestamp(component.freshUntil)}` : ""}</p>
      </li>`).join("")}</ul>` : '<p class="empty">No public components selected.</p>'}`) +
    panel("Incidents and updates", status.incidents.length ? status.incidents.map(incident => `<article class="panel">
      <h3>${escape(incident.componentLabel)} — ${incident.closedAt === null ? "Open incident" : "Recovered"}</h3>
      <p class="small">Opened ${timestamp(incident.openedAt)}${incident.closedAt !== null ? ` · Recovered ${timestamp(incident.closedAt)}` : ""}</p>
      ${incident.updates.map(update => `<div class="public-update"><p class="small">${timestamp(update.publishedAt)}</p>${escape(update.body)}</div>`).join("")}
    </article>`).join("") : '<p class="empty">No published component incidents recorded.</p>') +
    '<p class="footer">Powered by Tomato. Monitoring and this page share deployment infrastructure; no provider-independent coverage is promised.</p>';
}

function landing(): string {
  return `<section class="landing-hero" aria-labelledby="landing-title">
    <div class="landing-intro"><p class="landing-eyebrow">Uptime monitoring, without the mystery</p>
      <h1 id="landing-title">Know what broke.<br>See the evidence.<br>Count the checks.</h1>
      <p class="landing-lead">Keep an eye on websites, services and scheduled jobs. Tomato turns real observations into confirmed incidents, useful alerts and a usage ledger you can actually explain.</p>
      <div class="actions"><a class="button primary" href="/app">Open console</a><a class="button" href="/login">Sign in</a></div>
      <p class="help">Closed pilot · Access through a provisioned account or workspace invitation. Public signup is not open yet.</p>
    </div>
    ${panel("From URL to action", `<p class="help">Illustrative workflow · not a live monitor</p>
      <ol class="landing-workflow">
        <li><span class="landing-step">01</span><div><h3>Add your URL</h3><p>One submission for an HTTP(S) check. Set cadence and assertions when you need more control.</p></div></li>
        <li><span class="landing-step">02</span><div><h3>Get real evidence</h3><p>Inspect the response, timing and observation timestamp. A new check starts UNKNOWN, not magically UP.</p></div></li>
        <li><span class="landing-step">03</span><div><h3>Confirm the incident</h3><p>A first failure is SUSPECT. A separate check confirms DOWN; recovery is confirmed too.</p></div></li>
        <li><span class="landing-step">04</span><div><h3>Send a useful alert</h3><p>Connect a signed webhook, inspect delivery attempts and acknowledge the incident.</p></div></li>
      </ol>`)}
  </section>
  <section id="product" class="landing-section" aria-labelledby="product-title">
    <p class="landing-eyebrow">Product</p><h2 id="product-title">Different services. One clear picture.</h2>
    <p class="landing-section-lead">From a health endpoint to a nightly backup, choose the evidence that matters—not just whether a homepage loads.</p>
    <div class="landing-checks">
      ${panel("HTTP / HTTPS", "<p>Check websites and APIs with expected status codes, bounded response assertions and safe redirects.</p>")}
      ${panel("Heartbeat", "<p>Let your job send an authenticated pulse. Find out when an expected run goes missing.</p>")}
      ${panel("DNS", "<p>Check A, AAAA, MX, TXT, NS and CNAME answers through DNS-over-HTTPS, with optional expected records.</p>")}
      ${panel("WebSocket", "<p>Connect, optionally send a message and verify an expected response—not just an open port.</p>")}
      ${panel("TCP", "<p>Test a service connection with optional send and bounded response assertions.</p>")}
      ${panel("TLS", "<p>Check a secure service connection and inspect authenticated certificate validity evidence.</p>")}
    </div>
    ${panel("The work around the check", `<div class="landing-capabilities">
      <div><h3>Make room for maintenance</h3><p>Schedule a window that suppresses checks and alerts without erasing incident history.</p></div>
      <div><h3>Report what was observed</h3><p>See duration-based availability alongside coverage. UNKNOWN and paused time never turn into invented uptime.</p></div>
      <div><h3>Catch certificate expiry</h3><p>Inspect HTTPS and TLS certificate evidence, with early-expiry warnings separate from outage state.</p></div>
      <div><h3>Keep people informed</h3><p>Reuse alert destinations, see delivery status and explicitly publish safe components and incident updates to a public status page.</p></div>
      <div><h3>Work as a team</h3><p>Invite owners, editors and viewers. Use revision-fenced changes and an audit trail to keep shared work accountable.</p></div>
      <div><h3>Keep control of your setup</h3><p>Manage checks in native forms or through the API. Import and export redacted configuration without pretending health history can be imported.</p></div>
    </div>`)}
  </section>
  <section id="pricing" class="landing-section" aria-labelledby="pricing-title">
    <p class="landing-eyebrow">Pricing philosophy</p><h2 id="pricing-title">Your cadence. Your usage. One understandable unit.</h2>
    <p class="landing-section-lead">No bundle puzzle. No infrastructure meters passed through as a bill. Tomato counts eligible checks in an exact credit ledger.</p>
    <div class="landing-two">
      ${panel("What one credit means", `<p class="landing-credit"><strong>1 eligible primary observation = 1 credit</strong></p>
        <p>A genuine target failure counts too, including a target timeout or failed assertion. Extra failure and recovery confirmations, retries and UNKNOWN work are free.</p>
        <p><strong>Heartbeat:</strong> one accepted unique pulse uses one credit. Duplicate pulses and overdue detection are free; the expected cadence is not itself a charge.</p>
        <p>Pauses and maintenance suppress checks and their charges. Actual usage—not a forecast—is recorded in the ledger.</p>`)}
      ${panel("Choose the cadence you need", `<div class="table-scroll"><table>
        <caption>Usage examples · one outbound monitor, continuously enabled</caption>
        <thead><tr><th scope="col">Cadence</th><th scope="col">Primaries / day</th><th scope="col">Primaries / 30 days</th></tr></thead>
        <tbody><tr><th scope="row">1 minute</th><td>1,440</td><td>43,200</td></tr><tr><th scope="row">5 minutes</th><td>288</td><td>8,640</td></tr><tr><th scope="row">15 minutes</th><td>96</td><td>2,880</td></tr></tbody>
      </table></div><p class="help">Baseline scheduled examples, assuming one primary per slot—not spending caps. Ten monitors at five minutes schedule 86,400 primaries per 30 days. Eligible Check now runs consume additional credits. Pauses, maintenance, missed work and UNKNOWN results reduce consumption; confirmations do not add credits.</p>`)}
    </div>
    <p class="landing-pilot-note"><strong>Today: testing credits in a closed pilot.</strong> Commercial rates and purchase terms are not approved; signup and checkout are disabled. There is no purchasable plan on this page.</p>
  </section>
  <section id="agents" class="landing-section" aria-labelledby="agents-title">
    <p class="landing-eyebrow">For you and your agents</p><h2 id="agents-title">Bring your agent. Keep the authority yours.</h2>
    <p class="landing-section-lead">Let the agent in your own client inspect evidence and use real monitoring tools. The console and agent work with the same workspace, not two separate versions of the truth.</p>
    <div class="landing-two">
      ${panel("Connect → discover → act", `<ol class="setup-steps">
        <li><strong>Create a scoped key.</strong> Start read-only; add write or manage scope only when the task needs it.</li>
        <li><strong>Connect your client.</strong> Use the remote MCP endpoint at <code>/mcp</code>, the management API or the local Node stdio bridge. Connection instructions are in the console.</li>
        <li><strong>Discover real tools.</strong> Inspect monitors, evidence, incidents and reports; authorized tools can change configuration and manage workspace access.</li>
      </ol><div class="actions"><a class="button" href="/app">Connect from the console</a></div>`)}
      ${panel("Delegation, not a blank cheque", `<p>Keys stay within their creator’s current role and scope. Owner, editor and viewer permissions still apply; manage scope cannot promote a viewer into an owner.</p>
        <p>Monitor edits use revisions, consequential changes are audited, and keys can expire or be revoked. Revoking a source key also revokes its derived grants.</p>
        <p>You supply the external agent and its client. Tomato provides the tools—not an embedded AI chat or a universal OAuth connector.</p>`)}
    </div>
  </section>
  <section id="faq" class="landing-section" aria-labelledby="faq-title">
    <p class="landing-eyebrow">FAQ</p><h2 id="faq-title">A few things worth knowing.</h2>
    <details><summary>Can I use Tomato today?</summary><p>Yes, if you have a provisioned closed-pilot account or a workspace invitation. <a href="/app">Open the console</a> or <a href="/login">sign in</a>. Public signup, checkout and outbound email are disabled; signed webhooks are the available alert path.</p></details>
    <details><summary>Where do checks run? How are failures confirmed?</summary><p>Tomato runs on Cloudflare. Outbound failures and recoveries are confirmed by a separate observation over time, not by an independent provider quorum. Heartbeats detect an expired expected pulse and recover on an accepted pulse. Monitoring and public status pages share this provider; no guaranteed geography, dual-stack coverage or SLA is offered.</p></details>
    <details><summary>Is UNKNOWN just another word for UP?</summary><p>No. Missing, stale or unavailable observations are UNKNOWN. Reports show observed availability and coverage separately, and exclude UNKNOWN, PAUSED and MAINTENANCE from the availability calculation. An incident is retained even when its latest supporting observation becomes stale.</p></details>
    <details><summary>Will an outage run up extra credits?</summary><p>An eligible primary target failure costs one credit, just like a success. Separate confirmations and retries add no credits. Internal or UNKNOWN work is free. Heartbeats charge only accepted unique pulses, never duplicate retries or the detection of a missing pulse.</p></details>
    <details><summary>What becomes public?</summary><p>Only the components and safe labels an owner deliberately publishes, plus customer-safe incident updates. Private target URLs, headers, destinations and wallet data stay private. Adding a monitor does not publish it.</p></details>
  </section>
  ${panel("Less guessing. More evidence.", `<div class="landing-close"><div><h2>Your next check starts with a URL.</h2><p>For websites, services and jobs—with a console built to explain what happened.</p></div>
    <div class="actions"><a class="button primary" href="/app">Open console</a><a class="button" href="/login">Sign in</a></div></div>`)}
  <footer class="footer landing-footer"><span>Tomato · Uptime monitoring with an auditable check ledger.</span><a href="#main">Back to top</a></footer>`;
}

function document(title: string, content: string, page: UiPage): string {
  const authenticated = "account" in page;
  const actor = "actor" in page ? page.actor : null;
  const token = "csrfToken" in page ? page.csrfToken : null;
  const pageMessages = page.kind === "error" ? "" :
    `${"error" in page && page.error ? `<div class="error" role="alert"><strong>Could not complete the action.</strong> ${escape(page.error)}</div>` : ""}
     ${"notice" in page && page.notice ? `<div class="notice" role="status">${escape(page.notice)}</div>` : ""}`;
  const nav: Record<string, string> = {
    dashboard: "Monitors", notifications: "Alerts", wallet: authenticated && page.mode === "self-host" ? "Usage" : "Credits", "status-page": "Public status", settings: "Settings",
  };
  const current = page.kind === "monitor" || page.kind === "monitor-edit" || page.kind === "heartbeat-token" ? "dashboard" :
    page.kind === "status-page-edit" ? "status-page" : ["team", "api-keys", "api-key-reveal", "api-docs", "import-export", "audit", "invitation-reveal"].includes(page.kind) ? "settings" : page.kind === "reports" ? "dashboard" : page.kind;
  const navigation = authenticated ? `<nav class="nav" aria-label="Workspace">
    ${Object.entries(nav).map(([key, label]) => key === "team" && page.account.role !== "owner" ? "" : `<a href="${accountPath(page)}${key === "dashboard" ? "" : `/${key}`}"
      ${key === current ? ' aria-current="page"' : ""}>${label}</a>`).join("")}</nav>
    <p class="breadcrumb"><a href="/app">Workspaces</a> / ${escape(page.account.name)} · ${escape(page.account.role)}</p>` : "";
  const chrome = `<header class="topbar"><a class="brand" href="/">Tomato</a>
    <div class="account-line">${actor ? `<a href="/app">Open console</a><span>${escape(actor.username)}</span>${token ? actionForm("/logout", token, "Log out") : ""}` :
      '<a href="/app">Open console</a><a href="/login">Sign in</a>'}</div></header>${page.kind === "landing" ? `<nav class="nav" aria-label="Product"><a href="#product">Product</a><a href="#pricing">Pricing</a><a href="#agents">Agents</a><a href="#faq">FAQ</a></nav>` : navigation}`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    ${page.kind !== "public-status" && page.kind !== "landing" ? '<meta name="robots" content="noindex, nofollow">' : ""}
    ${page.kind === "landing" ? '<meta name="description" content="Monitor websites, services and jobs with real evidence, confirmed incidents and an auditable check ledger. Six check types, a practical console and scoped MCP tools.">' : ""}
    <title>${escape(title)} — Tomato</title><link rel="stylesheet" href="/tomato.css">${page.kind === "landing" ? "" : '<script src="/tomato.js" defer></script>'}
    </head><body${page.kind === "landing" ? ' class="landing"' : ""}><a class="skip-link" href="#main">Skip to content</a>
    <div class="app-shell${page.kind === "login" || page.kind === "enrollment" || page.kind === "invite" || page.kind === "error" ? " narrow" : ""}">${chrome}
      <main id="main">
        ${pageMessages}
        ${page.kind === "landing" ? "" : `<p hidden data-freshness-warning class="warning" role="status">Supporting observations expired while this page was open.
          Current coverage is UNKNOWN. Incident history is retained. Refresh for current observations.</p>`}
        ${content}
      </main>
      ${authenticated ? `<footer class="footer">Tomato · ${escape(page.account.name)} · Snapshot ${timestamp(page.generatedAt)} ·
        Cloudflare-only; temporal confirmation is not independent-provider confirmation.</footer>` : ""}
    </div></body></html>`;
}

export function renderUi(page: UiPage): string {
  let title: string;
  let content: string;
  switch (page.kind) {
    case "landing": title = "Uptime monitoring. Real evidence. Clear usage."; content = landing(); break;
    case "login": {
      const mode = page.mode;
      title = mode === "signup" ? "Create account" : mode === "forgot" ? "Recover password" : mode === "reset" ? "Reset password" : mode === "verify" ? "Verify email" : "Log in";
      const action = mode === "signup" ? "/signup" : mode === "forgot" ? "/forgot-password" : mode === "reset" ? "/reset-password" : mode === "verify" ? "/verify-email" : "/login";
      content = heading(title) + panel("Email identity", `${page.notice ? `<p class="notice" role="status">${escape(page.notice)}</p>` : ""}<p>Use your real verified email identity. A newly verified identity receives one workspace; access to other workspaces requires membership or an invitation.</p><form method="post" action="${action}">${csrf(page.csrfToken)}${page.next ? hidden("next", page.next) : ""}${mode === "reset" ? hidden("token", page.resetToken ?? "") : ""}<div class="form-grid">${mode === "signup" ? field("name", "Your name", "", { required: true, autocomplete: "name", full: true }) : ""}${mode !== "reset" ? field("email", "Email address", "", { type: "email", required: true, maxLength: 254, autocomplete: "username", full: true }) : ""}${!mode || mode === "signup" || mode === "reset" ? field("password", mode === "reset" ? "New password" : "Password", "", { type: "password", required: true, autocomplete: !mode ? "current-password" : "new-password", full: true, help: mode ? "At least 14 characters; use a unique password." : undefined }) : ""}</div><div class="form-actions"><button class="primary" type="submit">${escape(title)}</button></div></form>${!mode ? `<p class="help">${page.signup ? '<a href="/signup">Create account</a> · ' : ""}${page.email ? '<a href="/forgot-password">Forgot password?</a> · <a href="/verify-email">Resend verification email</a>' : "Email recovery is disabled until SMTP is configured; contact your administrator."}</p>${(["github", "google"] as const).filter(provider => page[provider]).map(provider => `<form method="post" action="/auth/social">${csrf(page.csrfToken)}${hidden("provider", provider)}<button type="submit">Continue with ${provider === "github" ? "GitHub" : "Google"}</button></form>`).join("")}` : '<p><a href="/login">Return to sign in</a></p>'}`);
      if (!mode && page.enrollment) content += panel("Existing username account", '<p>Keep your original password, workspace, API keys and history. Your old credentials can only authorize verified-contact enrollment, not a browser session.</p><a class="button" href="/enroll">Claim existing username identity</a>');
      break;
    }
    case "enrollment": {
      title = page.stage === "proof" ? "Claim existing username" : page.stage === "invite" ? "Claim username invitation" : page.stage === "verify" ? "Finish verified enrollment" : "Verify your actual contact";
      const action = page.stage === "proof" ? "/enroll" : page.stage === "invite" ? "/enroll/invitation" : page.stage === "verify" ? "/enroll/verify" : "/enroll/contact";
      const inputs = page.stage === "proof" || page.stage === "invite"
        ? `${page.invitationToken ? hidden("invitationToken", page.invitationToken) : ""}${field("username", "Original target username", page.username ?? "", { required: true, autocomplete: "username", maxLength: 120, full: true })}${field("password", page.stage === "proof" ? "Original password (unchanged)" : "Password for this new invited identity", "", { type: "password", required: true, autocomplete: page.stage === "proof" ? "current-password" : "new-password", full: true, help: page.stage === "proof" ? "Previously valid shorter passwords are preserved. This proof cannot open a product session." : "At least 14 characters. Only this original invitation's workspace and role will be joined." })}`
        : page.stage === "verify" ? `${hidden("emailToken", page.emailToken ?? "")}<p>Confirm the verified contact <strong>${escape(page.email ?? "")}</strong> in this original claim browser.</p>`
        : field("email", "Your actual email address", page.email ?? "", { type: "email", required: true, autocomplete: "email", maxLength: 254, full: true });
      content = heading(title) + panel("Restricted, single-use enrollment", `${page.notice ? `<p class="notice" role="status">${escape(page.notice)}</p>` : ""}<p>No substitute workspace or fabricated email is created. Existing username claims retain their stable identity and original password. Invitation-only claims require the unchanged invitation token and verify your actual contact before joining.</p>${page.expiresAt ? `<p class="warning">This claim expires ${timestamp(page.expiresAt)}. Open the verification email in this same browser. Expired claims never affect existing monitoring or API keys; prove your original credentials again to start a fresh claim.</p>` : ""}<form method="post" action="${action}">${csrf(page.csrfToken)}<div class="form-grid">${inputs}</div><div class="form-actions"><button class="primary" type="submit">${page.stage === "verify" ? "Verify contact and finish claim" : page.stage === "contact" ? "Send verification email" : "Start restricted claim"}</button></div></form><p><a href="/login">Return to email sign in</a></p>`);
      break;
    }
    case "accounts":
      title = "Workspaces";
      content = heading("Your workspaces") + panel("Choose workspace", page.accounts.length ? `<ul>${page.accounts.map(account => `<li><a href="/app/accounts/${encodeURIComponent(account.id)}">${escape(account.name)}</a> — ${escape(account.role)}</li>`).join("")}</ul>` : '<p class="empty">No workspace membership. Ask an owner for an invitation or contact your operator.</p>');
      break;
    case "dashboard": title = "Monitors"; content = dashboard(page); break;
    case "reports": title = "Availability report"; content = reports(page); break;
    case "monitor": title = page.monitor.name; content = monitorDetail(page); break;
    case "monitor-edit": title = page.monitor ? "Edit monitor" : "Add monitor"; content = monitorEditor(page); break;
    case "heartbeat-token": title = "Heartbeat token"; content = heartbeatToken(page); break;
    case "wallet": title = "Credits and usage"; content = wallet(page); break;
    case "notifications": title = "Alerts"; content = notifications(page); break;
    case "status-page-edit": title = "Public status page"; content = statusPageEditor(page); break;
    case "settings": title = "Settings and actions"; content = settings(page); break;
    case "audit":
      title = "Audit log";
      content = heading("Consequential audit log", "Recorded actions and subjects; never plaintext credentials.") + panel("Workspace changes",
        page.entries.length ? `<div class="table-scroll"><table><caption>Actual auditable changes to ${escape(page.account.name)}</caption>
          <thead><tr><th scope="col">Time</th><th scope="col">Actor identity</th><th scope="col">Action</th><th scope="col">Subject</th></tr></thead>
          <tbody>${page.entries.map(entry => `<tr><td>${timestamp(entry.occurredAt)}</td><td class="wrap">${escape(entry.actor)}</td>
            <td class="wrap">${escape(entry.action)}</td><td class="wrap">${escape(entry.subject)}</td></tr>`).join("")}</tbody></table></div>` :
          '<p class="empty">No consequential changes recorded.</p>');
      break;
    case "team": title = "Workspace team"; content = team(page); break;
    case "invitation-reveal":
      title = "Invitation created";
      content = heading("Invitation created", `${page.invitation.username} · ${page.invitation.role}`) + panel("Share this link with the intended person", `<p class="warning">This private link is shown once, bound to ${escape(page.invitation.username)}, and expires ${timestamp(page.invitation.expiresAt)}. Share only with the intended person; no automatic email is sent.</p>${secretReveal("invitation-secret", page.invitationUrl)}<a class="button" href="${accountPath(page)}/team">Return to team</a>`);
      break;
    case "api-keys": title = "API keys"; content = apiKeys(page); break;
    case "api-key-reveal":
      title = "API key created";
      content = heading("API key created", `${page.key.name} · ${page.key.scope}`) + panel("Save this key now", `<p class="warning">Shown once. Save in your client's secret configuration. Tomato stores only its hash, never browser storage. Expires ${timestamp(page.key.expiresAt)}.</p>${secretReveal("api-key-secret", page.apiKey)}<a class="button primary" href="${accountPath(page)}/api-keys">I saved the key — return to keys</a>`) + agentConnection(page);
      break;
    case "import-export": title = "Import and export"; content = importExport(page); break;
    case "api-docs": title = "Management API"; content = apiDocs(page); break;
    case "invite":
      title = "Accept workspace invitation";
      content = heading("Accept workspace invitation", `${page.accountName} · ${page.role}`) + panel("Confirm invited identity", `<dl class="details"><dt>Email</dt><dd>${escape(page.username)}</dd><dt>Role</dt><dd>${escape(page.role)}</dd><dt>Expires</dt><dd>${timestamp(page.expiresAt)}</dd></dl>${page.signedIn ? `<form method="post" action="/invite/${encodeURIComponent(page.invitationToken)}">${csrf(page.csrfToken)}<button class="primary" type="submit">Accept invitation as ${escape(page.username)}</button></form>` : page.identityStatus === "verified" ? `<p>Sign in with this verified email, then return here to accept membership.</p><a class="button primary" href="/login?next=${encodeURIComponent(`/invite/${page.invitationToken}`)}">Sign in to accept</a>` : `<p>${page.identityStatus === "unverified" ? "Use the password you originally created to resend verification. This does not replace your identity or password." : "Create this invited email identity, verify the email we send, then sign in and return to this link."}</p><form method="post" action="/invite/${encodeURIComponent(page.invitationToken)}">${csrf(page.csrfToken)}${hidden("register", "true")}${page.identityStatus === "new" ? field("name", "Your name", "", { required: true, autocomplete: "name" }) : ""}${field("password", page.identityStatus === "unverified" ? "Original password" : "New password", "", { type: "password", required: true, autocomplete: page.identityStatus === "unverified" ? "current-password" : "new-password", help: "At least 14 characters; use a unique password." })}<div class="form-actions"><button class="primary" type="submit">${page.identityStatus === "unverified" ? "Resend verification" : "Create invited identity"}</button></div></form>`}`);
      break;
    case "public-status": title = page.page.title; content = publicStatus(page); break;
    case "error": title = `${page.status} error`; content = heading(`${page.status} — Request unavailable`) + panel("Error", `<p>${escape(page.error)}</p><a class="button" href="/app">Return to application</a>`); break;
  }
  return document(title, content, page);
}
