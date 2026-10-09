"use strict";
const NUMBER_FORMATTER = new Intl.NumberFormat("en", { maximumFractionDigits: 2 });

const monitorForm = document.querySelector("[data-monitor-form]");
if (monitorForm) {
  const kind = monitorForm.elements.namedItem("kind");
  const interval = monitorForm.elements.namedItem("intervalSeconds");
  const sections = Array.from(monitorForm.querySelectorAll("fieldset[data-check-kinds]"));
  const estimate = monitorForm.querySelector("[data-usage-estimate]");

  function updateMonitorForm() {
    for (const section of sections) {
      const enabled = section.dataset.checkKinds.split(" ").includes(kind.value);
      section.hidden = !enabled;
      section.disabled = !enabled;
    }
    const requiredFields = {
      url: kind.value === "http" || kind.value === "websocket",
      dnsName: kind.value === "dns",
      hostname: kind.value === "tcp" || kind.value === "tls",
      port: kind.value === "tcp" || kind.value === "tls",
    };
    for (const [name, required] of Object.entries(requiredFields)) {
      monitorForm.elements.namedItem(name).required = required;
    }
    for (const [modeName, fieldNames] of Object.entries({
      headersMode: ["headers"], webhookMode: ["webhookUrl", "webhookSecret"], emailMode: ["emailAddress"],
    })) {
      const mode = monitorForm.elements.namedItem(modeName);
      const replace = mode && mode.value === "replace";
      for (const name of fieldNames) {
        const input = monitorForm.elements.namedItem(name);
        if (input) {
          input.disabled = !replace;
          input.required = Boolean(replace);
        }
      }
    }
    const method = monitorForm.elements.namedItem("method");
    const containsEnabled = monitorForm.elements.namedItem("containsEnabled");
    if (kind.value === "http" && method.value === "HEAD") containsEnabled.checked = false;
    containsEnabled.disabled = kind.value !== "http" || method.value === "HEAD";
    for (const name of ["contains", "send", "expect"]) {
      const input = monitorForm.elements.namedItem(name);
      const enabled = monitorForm.elements.namedItem(`${name}Enabled`);
      input.disabled = !enabled.checked || input.closest("fieldset").hidden;
    }
    const seconds = Number(interval.value);
    if (kind.value === "heartbeat") {
      estimate.textContent = "One credit per unique accepted pulse; duplicate retries and overdue detection are free. Cadence defines the expected pulse period, not a scheduled charge.";
    } else if (seconds >= 60) {
      const daily = NUMBER_FORMATTER.format(86400 / seconds);
      const monthly = NUMBER_FORMATTER.format(2592000 / seconds);
      estimate.textContent = `At most ${daily} primary checks/day · ${monthly} per 30 days. One accepted primary observation uses one credit; confirmations/retries are included. Unknown results, maintenance, pauses and skipped work change consumption. No commercial price is configured.`;
    } else {
      estimate.textContent = "Choose an interval of at least 60 seconds. Credits are exact engine usage; no commercial price is configured.";
    }
  }
  monitorForm.addEventListener("change", updateMonitorForm);
  interval.addEventListener("input", updateMonitorForm);
  updateMonitorForm();
}

for (const form of document.querySelectorAll("[data-destination-form]")) {
  function updateDestinationForm() {
    for (const [modeName, names] of Object.entries({ webhookMode: ["webhookUrl", "webhookSecret"], emailMode: ["emailAddress"] })) {
      const mode = form.elements.namedItem(modeName);
      for (const name of names) {
        const input = form.elements.namedItem(name);
        if (input) {
          input.disabled = !mode || mode.value !== "replace";
          input.required = Boolean(mode && mode.value === "replace");
        }
      }
    }
  }
  form.addEventListener("change", updateDestinationForm);
  updateDestinationForm();
}

for (const form of document.querySelectorAll("form")) {
  form.addEventListener("invalid", event => {
    for (let parent = event.target.parentElement; parent && parent !== form; parent = parent.parentElement) {
      if (parent.tagName === "DETAILS") parent.open = true;
    }
  }, true);
}

const bulkForm = document.querySelector("[data-bulk-form]");
if (bulkForm) {
  const selected = Array.from(document.querySelectorAll(`input[form="${bulkForm.id}"][name="monitorId"]`));
  const selectAll = document.querySelector("[data-select-visible]");
  const count = bulkForm.querySelector("[data-selection-count]");
  function updateSelection() {
    const visible = selected.filter(input => !input.closest("[data-monitor-row]").hidden);
    const total = selected.filter(input => input.checked).length;
    count.textContent = `${total} selected`;
    selectAll.checked = visible.length > 0 && visible.every(input => input.checked);
    selectAll.indeterminate = visible.some(input => input.checked) && !selectAll.checked;
  }
  selectAll.hidden = false;
  selectAll.closest("label").hidden = false;
  selectAll.addEventListener("change", () => {
    for (const input of selected) if (!input.closest("[data-monitor-row]").hidden) input.checked = selectAll.checked;
    updateSelection();
  });
  for (const input of selected) input.addEventListener("change", updateSelection);
  document.addEventListener("tomato:filter", updateSelection);
  updateSelection();
}

for (const button of document.querySelectorAll("[data-copy-target]")) {
  if (!navigator.clipboard?.writeText) continue;
  button.hidden = false;
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    const status = button.parentElement.querySelector("[data-copy-status]");
    if (!target || target.dataset.cleared) {
      status.textContent = "This value is no longer available. Create or rotate a replacement if you did not save it.";
      return;
    }
    try {
      await navigator.clipboard.writeText(target.textContent);
      status.textContent = target.hasAttribute("data-secret") ? "Copied. Save it in your client's secret configuration; your system clipboard now contains a secret." : "Copied.";
    } catch {
      status.textContent = "Clipboard access was not granted. Select and copy the displayed value manually.";
    }
  });
}

const monitorRows = Array.from(document.querySelectorAll("[data-monitor-row]"));
const filter = document.querySelector("[data-monitor-filter]");
const filterEmpty = document.querySelector("[data-filter-empty]");
if (filter) {
  filter.addEventListener("input", () => {
    const search = filter.value.trim().toLowerCase();
    let visible = 0;
    for (const row of monitorRows) {
      const currentState = row.querySelector("[data-current-state]");
      row.hidden = !`${row.dataset.search} ${currentState ? currentState.textContent : ""}`.toLowerCase().includes(search);
      if (!row.hidden) visible++;
    }
    if (filterEmpty) filterEmpty.hidden = visible !== 0;
    document.dispatchEvent(new Event("tomato:filter"));
  });
}

const currentStates = Array.from(document.querySelectorAll("[data-current-state]"));
if (currentStates.length) {
  function expireCurrentEvidence() {
    if (document.visibilityState === "hidden") return;
    let expired = false;
    const now = Date.now();
    for (const badge of currentStates) {
      const expiry = Number(badge.dataset.freshUntil);
      if (expiry > 0 && now > expiry && !["UNKNOWN", "PAUSED", "MAINTENANCE"].includes(badge.textContent)) {
        badge.textContent = "UNKNOWN";
        badge.className = "state UNKNOWN";
        badge.title = "Supporting observation expired; refresh for current coverage";
        expired = true;
      }
    }
    if (expired) {
      const warning = document.querySelector("[data-freshness-warning]");
      if (warning) warning.hidden = false;
      const description = document.querySelector("[data-current-description]");
      if (description) description.textContent = "No fresh supporting observation; incident history remains below.";
      const counts = { UP: 0, DOWN: 0, SUSPECT: 0, RECOVERING: 0, UNKNOWN: 0, PAUSED: 0, MAINTENANCE: 0 };
      for (const row of monitorRows) {
        const badge = row.querySelector("[data-current-state]");
        if (badge && Object.hasOwn(counts, badge.textContent)) counts[badge.textContent]++;
      }
      for (const count of document.querySelectorAll("[data-state-count]")) {
        count.textContent = String(counts[count.dataset.stateCount]);
      }
      if (filter) filter.dispatchEvent(new Event("input"));
    }
  }
  expireCurrentEvidence();
  setInterval(expireCurrentEvidence, 1000);
  document.addEventListener("visibilitychange", expireCurrentEvidence);
}

const firstEvidence = document.querySelector("[data-first-evidence-url]");
if (firstEvidence) {
  const startedAt = Date.now();
  const status = firstEvidence.querySelector("[data-evidence-wait]");
  let edited = false;
  let stopped = false;
  document.addEventListener("input", () => { edited = true; }, { once: true });
  window.addEventListener("pagehide", () => { stopped = true; }, { once: true });
  async function awaitFirstEvidence() {
    if (stopped) return;
    if (Date.now() - startedAt > 60000) {
      status.prepend("Automatic first-result waiting has ended; use Refresh evidence. ");
      return;
    }
    if (document.visibilityState !== "hidden") {
      try {
        const response = await fetch(firstEvidence.dataset.firstEvidenceUrl, { credentials: "same-origin", cache: "no-store", signal: AbortSignal.timeout(8000) });
        if (!response.ok) {
          status.prepend("Automatic waiting is unavailable; use Refresh evidence. ");
          return;
        }
        const data = await response.json();
        if (data.monitor && Number.isFinite(data.monitor.lastObservedAt) && data.monitor.lastObservedAt > 0) {
          if (!edited && !document.activeElement?.closest("form")) {
            window.location.reload();
          } else {
            status.prepend("A real stored result is ready. Your form edits have been preserved; ");
          }
          return;
        }
      } catch {
        status.prepend("Automatic waiting could not read current evidence; use Refresh evidence. ");
        return;
      }
    }
    setTimeout(awaitFirstEvidence, 2000);
  }
  setTimeout(awaitFirstEvidence, 2000);
}

const pendingButtonLabels = new Map();
for (const form of document.querySelectorAll('form[method="post"]')) {
  form.addEventListener("submit", event => {
    if (form.dataset.submitting) {
      event.preventDefault();
      return;
    }
    form.dataset.submitting = "true";
    form.setAttribute("aria-busy", "true");
    for (const button of form.querySelectorAll('button[type="submit"]')) {
      if (!button.disabled) {
        pendingButtonLabels.set(button, button.textContent);
        button.dataset.pendingDisabled = "true";
        button.textContent = "Submitting…";
        button.disabled = true;
      }
    }
    const status = form.querySelector("[data-submit-status]");
    if (status) status.textContent = "Submitting… The server will validate and complete this action.";
  });
}

window.addEventListener("pageshow", () => {
  for (const form of document.querySelectorAll("form[data-submitting]")) {
    delete form.dataset.submitting;
    form.removeAttribute("aria-busy");
    for (const button of form.querySelectorAll("button[data-pending-disabled]")) {
      button.disabled = false;
      button.textContent = pendingButtonLabels.get(button) ?? button.textContent;
      pendingButtonLabels.delete(button);
      delete button.dataset.pendingDisabled;
    }
    const status = form.querySelector("[data-submit-status]");
    if (status) status.textContent = "";
  }
});

window.addEventListener("pagehide", () => {
  for (const secret of document.querySelectorAll("[data-secret]")) {
    secret.textContent = "Secret cleared after leaving this page. If it was not saved, revoke or rotate it and create a replacement.";
    secret.dataset.cleared = "true";
  }
});
