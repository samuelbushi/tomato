import { ApiError, body, constantEqual, digest, identifier, integer, json, monitorInput, monitorView, probeResult, record, text } from "./validation";
import type { ValidatedMonitorInput } from "./validation";
import type { ClaimedCheck, CoverageSegment, EngineMessage, EngineSnapshot, ExecutionJob, Incident, MonitorRecord, MonitorState, MonitorView, NotificationRecord, NotificationView, ProbeResult, StoredObservation } from "./types";
import type { Env } from "./runtime-types";
import type { AuditView, PublicPageConfig, PublicStatusView, WalletView, MaintenanceWindow, NotificationDefaultsView, AvailabilityReport } from "./product-types";
import { EGRESS_OVERHEAD_MS } from "./probes";
import type { PgDatabase, PgTransaction } from "./database";
import { AccountSecrets } from "./account-secrets";
const RETENTION_MS = 7 * 86400000;
const LEASE_MARGIN_MS = 5000;
export class AccountEngine {
    private readonly secrets: AccountSecrets;
    constructor(private readonly tx: PgTransaction, private readonly env: Env, private readonly accountId: string) {
        this.secrets = new AccountSecrets(env.DATA_KEY, accountId);
    }
    async handle(request: Request): Promise<Response> {
        await this.advanceMaintenance(Date.now());
        const account = request.headers.get("X-Tomato-Account");
        if (account && account !== this.accountId)
            throw new ApiError(403, "account_mismatch");
        const url = new URL(request.url);
        const path = url.pathname;
        const actor = identifier(request.headers.get("X-Tomato-Actor-ID") ?? "operator");
        if (request.method === "GET" && path === "/state")
            return json(await this.snapshot());
        if (request.method === "GET" && path === "/usage")
            return json(await this.usage());
        if (request.method === "GET" && path === "/history")
            return json(await this.page("observations", "observations", url));
        if (request.method === "GET" && path === "/incidents")
            return json(await this.page("incidents", "incidents", url));
        if (request.method === "GET" && path === "/notifications")
            return json(await this.page("notifications", "notifications", url, value => this.notificationView(value as NotificationRecord)));
        if (request.method === "GET" && path === "/audit")
            return json(await this.page("audit", "entries", url));
        if (request.method === "GET" && path === "/monitors")
            return json({ monitors: (await this.snapshot()).monitors });
        if (request.method === "GET" && path === "/export")
            return json(await this.exportMonitors());
        if (request.method === "GET" && path === "/status-page")
            return json({ page: await this.statusPage(), revision: await this.pageRevision() });
        if (request.method === "GET" && path === "/public-status")
            return json(await this.publicStatus());
        if (request.method === "GET" && path === "/notification-defaults")
            return json({ defaults: await this.defaultsView() });
        if (request.method === "GET" && path === "/maintenance")
            return json({ maintenance: await this.maintenance() });
        if (request.method === "GET" && path === "/coverage")
            return json(await this.coveragePage(url));
        if (request.method === "GET" && path === "/reports")
            return json(await this.report(url));
        let value: unknown;
        let status = 200;
        const credit = path.match(/^\/credits\/([A-Za-z0-9_-]{1,64})$/);
        const monitorPath = path.match(/^\/monitors\/([A-Za-z0-9_-]{1,64})$/);
        const action = path.match(/^\/monitors\/([A-Za-z0-9_-]{1,64})\/(pause|resume|heartbeat|heartbeat-token|notification-test|check-now)$/);
        if (request.method === "GET" && monitorPath)
            return json({ monitor: monitorView(await this.monitor(monitorPath[1]!)) });
        if (request.method === "PUT" && credit) {
            value = await this.deposit(credit[1]!, await body(request));
        }
        else if (request.method === "PUT" && path === "/notification-defaults") {
            value = await this.saveDefaults(await body(request));
        }
        else if (request.method === "POST" && path === "/monitors/bulk") {
            value = await this.bulkPaused(await body(request));
        }
        else if (request.method === "POST" && path === "/maintenance") {
            value = await this.createMaintenance(await body(request));
        }
        else if (request.method === "DELETE" && path.startsWith("/maintenance/")) {
            value = await this.cancelMaintenance(identifier(path.slice(13)), await body(request));
        }
        else if (request.method === "POST" && path === "/incidents/acknowledgement") {
            value = await this.acknowledge(await body(request), actor);
        }
        else if (request.method === "POST" && path === "/monitors/import") {
            value = await this.importMonitors(await body(request, 1048576));
            status = 201;
        }
        else if (request.method === "POST" && path === "/monitors") {
            value = await this.createMonitor(await body(request));
            status = 201;
        }
        else if (request.method === "PUT" && monitorPath) {
            value = await this.updateMonitor(monitorPath[1]!, await body(request));
        }
        else if (request.method === "DELETE" && monitorPath) {
            value = await this.deleteMonitor(monitorPath[1]!, await body(request));
        }
        else if (request.method === "POST" && action) {
            if (action[2] === "heartbeat")
                value = await this.heartbeat(action[1]!, request);
            else {
                const input = request.body ? await body(request) : {};
                if (action[2] === "heartbeat-token")
                    value = await this.rotateHeartbeat(action[1]!, input);
                else if (action[2] === "notification-test")
                    value = await this.testNotification(action[1]!, input);
                else if (action[2] === "check-now")
                    value = await this.checkNow(action[1]!, input);
                else
                    value = await this.setPaused(action[1]!, action[2] === "pause", input);
            }
        }
        else if (request.method === "POST" && path === "/notifications/retry") {
            value = await this.retryNotification(await body(request));
        }
        else if (request.method === "POST" && path === "/status-page/validate") {
            value = await this.saveStatusPage(await body(request), false);
        }
        else if (request.method === "PUT" && path === "/status-page") {
            value = await this.saveStatusPage(await body(request));
        }
        else if (request.method === "DELETE" && path === "/status-page") {
            const input = await body(request);
            const revision = await this.pageRevision();
            if (integer(input.revision, 0, Number.MAX_SAFE_INTEGER, "revision") !== revision) throw new ApiError(409, "revision_conflict");
            await this.tx.query("DELETE FROM metadata WHERE key='status-page'");
            await this.tx.query("INSERT INTO metadata(key,value) VALUES('status-page-revision',$1) ON CONFLICT(account_id,key) DO UPDATE SET value=excluded.value", [String(revision + 1)]);
            value = { deleted: true, revision: revision + 1 };
        }
        else if (request.method === "POST" && path === "/status-page/updates") {
            value = await this.publishUpdate(await body(request));
            status = 201;
        }
        else if (request.method === "DELETE" && path === "/status-page/updates") {
            value = await this.removeUpdate(await body(request));
        }
        else if (request.method === "POST" && path === "/audit") {
            value = { entry: await this.audit(await body(request)) };
        }
        else if (request.method === "POST" && path === "/tick") {
            await this.advance(Date.now());
            value = { dispatched: true };
        }
        else if (request.method === "POST" && path === "/claim") {
            const input = await body(request);
            value = { claim: await this.claim(String(input.jobId ?? ""), Date.now()) };
        }
        else if (request.method === "POST" && path === "/complete") {
            const input = await body(request, 131072);
            value = { accepted: await this.complete(String(input.jobId ?? ""), String(input.leaseToken ?? ""), probeResult(input.result, Date.now())) };
        }
        else if (request.method === "POST" && path === "/notifications/claim") {
            const input = await body(request);
            value = { notification: await this.claimNotification(String(input.eventId ?? ""), Date.now()) };
        }
        else if (request.method === "POST" && path === "/notifications/complete") {
            const input = await body(request);
            if (typeof input.success !== "boolean")
                throw new ApiError(400, "invalid_delivery_result");
            value = { accepted: await this.completeNotification(String(input.eventId ?? ""), String(input.leaseToken ?? ""), input.success, Date.now(), input.lastError) };
        }
        else if (request.method === "POST" && path === "/archive/claim") {
            value = { batch: await this.claimArchive() };
        }
        else if (request.method === "POST" && path === "/archive/complete") {
            const input = await body(request);
            value = { accepted: await this.completeArchive(String(input.batchId ?? "")) };
        }
        else
            throw new ApiError(404, "not_found");
        if ((/^\/(?:monitors|credits|status-page)(?:\/|$)/.test(path) && !path.endsWith("/heartbeat")) || path === "/notifications/retry") {
            await this.audit({ actor, action: `${request.method.toLowerCase()}:${path.split("/").slice(1).filter(part => part !== monitorPath?.[1] && part !== action?.[1] && part !== credit?.[1]).join(":")}`, subject: monitorPath?.[1] ?? action?.[1] ?? credit?.[1] ?? "account" });
        }
        if (value && typeof value === "object" && "error" in value && value.error === "insufficient_credits")
            status = 402;
        return json(value, status);
    }
    private async monitor(id: string): Promise<MonitorRecord> {
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM monitors WHERE id=$1", [id]))[0];
        if (!row)
            throw new ApiError(404, "monitor_not_found");
        return this.secrets.decodeMonitor(row.data);
    }
    private async saveMonitor(monitor: MonitorRecord): Promise<void> {
        (await this.tx.query("INSERT INTO monitors(id,next_due,paused,data) VALUES($1,$2,$3,$4) ON CONFLICT(account_id,id) DO UPDATE SET next_due=excluded.next_due,paused=excluded.paused,data=excluded.data", [monitor.id, monitor.nextDueAt, Number(monitor.paused), this.secrets.encodeMonitor(monitor)]));
    }
    private async saveJob(job: ExecutionJob): Promise<void> {
        (await this.tx.query("INSERT INTO jobs(id,monitor_id,status,expires_at,scheduled_at,data) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(account_id,id) DO UPDATE SET status=excluded.status,data=excluded.data", [job.id, job.monitorId, job.status, job.expiresAt, job.scheduledAt, JSON.stringify(job)]));
    }
    private async setState(monitor: MonitorRecord, state: MonitorState, at: number): Promise<void> {
        if (monitor.state === state)
            return;
        const previous = (await this.tx.query<{
            started_at: number;
        }>("SELECT started_at FROM coverage WHERE monitor_id=$1 AND ended_at IS NULL", [monitor.id]))[0];
        const timestamp = Math.max(at, (previous?.started_at ?? 0) + 1);
        (await this.tx.query("UPDATE coverage SET ended_at=$1 WHERE monitor_id=$2 AND ended_at IS NULL", [timestamp, monitor.id]));
        (await this.tx.query("INSERT INTO coverage(monitor_id,started_at,ended_at,state,evidence_mode) VALUES($1,$2,NULL,$3,$4)", [monitor.id, timestamp, state, monitor.check.kind === "heartbeat" && state === "DOWN" ? "heartbeat-deadline" : "freshness"]));
        monitor.state = state;
    }
    private async enqueue(id: string, message: EngineMessage, dueAt = Date.now()): Promise<void> {
        (await this.tx.query("INSERT INTO outbox(id,next_due,message) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", [id, dueAt, JSON.stringify(message)]));
    }
    private async deposit(id: string, input: Record<string, unknown>): Promise<unknown> {
        if (this.env.MODE === "self-host")
            throw new ApiError(409, "credits_not_used_in_self_host");
        const credits = integer(input.credits, 1, 1000000000, "credits");
        const reason = input.reason === undefined ? "operator-testing-grant" : text(input.reason, 200, "credit_reason");
        const existing = (await this.tx.query<{
            credits: number;
        }>("SELECT credits FROM deposits WHERE id=$1", [id]))[0];
        if (existing && existing.credits !== credits)
            throw new ApiError(409, "deposit_conflict");
        if (!existing) {
            const wallet = (await this.tx.query<{
                balance: number;
            }>("SELECT balance FROM wallet WHERE id=1"))[0]!;
            if (wallet.balance + credits > Number.MAX_SAFE_INTEGER)
                throw new ApiError(409, "balance_limit");
            (await this.tx.query("INSERT INTO deposits(id,credits) VALUES($1,$2)", [id, credits]));
            (await this.tx.query("INSERT INTO grants(id,reason,created_at) VALUES($1,$2,$3)", [id, reason, Date.now()]));
            (await this.tx.query("UPDATE wallet SET balance=balance+$1 WHERE id=1", [credits]));
        }
        return { balance: (await this.tx.query<{
                balance: number;
            }>("SELECT balance FROM wallet WHERE id=1"))[0]!.balance, duplicate: Boolean(existing) };
    }
    private async createMonitor(input: Record<string, unknown>): Promise<unknown> {
        return (await this.insertMonitors([input]))[0];
    }
    private async insertMonitors(inputs: Record<string, unknown>[]): Promise<{
        monitor: MonitorView;
        heartbeatToken?: string;
    }[]> {
        const prepared: { config: ValidatedMonitorInput; token: string | undefined; tokenHash: string | undefined }[] = [];
        for (const input of inputs) {
            const defaults = input.useNotificationDefaults === true ? await this.defaults() : {};
            const config = monitorInput({ ...defaults, ...input }, this.env);
            const token = config.check.kind === "heartbeat" ? crypto.randomUUID() + crypto.randomUUID() : undefined;
            prepared.push({ config, token, tokenHash: token ? await digest(token) : undefined });
        }
        const count = (await this.tx.query<{
            count: number;
        }>("SELECT COUNT(*) AS count FROM monitors"))[0]!.count;
        if (count + prepared.length > 100)
            throw new ApiError(409, "account_monitor_limit");
        const ids = new Set<string>();
        for (const { config } of prepared) {
            if (ids.has(config.id) || (await this.tx.query("SELECT 1 FROM monitors WHERE id=$1 UNION ALL SELECT 1 FROM retired_monitors WHERE id=$2", [config.id, config.id])).length)
                throw new ApiError(409, "monitor_id_unavailable");
            ids.add(config.id);
        }
        const now = Date.now();
        const results: { monitor: MonitorView; heartbeatToken?: string }[] = [];
        for (const { config, token, tokenHash } of prepared) {
            const heartbeatDeadline = config.check.kind === "heartbeat" ? now + config.intervalMs + (config.check.graceMs ?? 0) : undefined;
            const monitor: MonitorRecord = { ...config, revision: 1, state: config.paused ? "PAUSED" : "UNKNOWN", paused: config.paused, nextDueAt: heartbeatDeadline ?? now, lastObservedAt: null, lastSlotAt: 0, candidateJobId: null, candidateSuccess: null, incidentId: null, ...(tokenHash ? { heartbeatTokenHash: tokenHash, heartbeatDeadline } : {}) };
            await this.saveMonitor(monitor);
            (await this.tx.query("INSERT INTO coverage(monitor_id,started_at,ended_at,state,evidence_mode) VALUES($1,$2,NULL,$3,'freshness')", [config.id, now, monitor.state]));
            results.push({ monitor: monitorView(monitor), ...(token ? { heartbeatToken: token } : {}) });
        }
        return results;
    }
    private revision(monitor: MonitorRecord, input: Record<string, unknown>, required = true): void {
        if (input.revision === undefined && !required)
            return;
        if (integer(input.revision, 1, Number.MAX_SAFE_INTEGER, "revision") !== monitor.revision)
            throw new ApiError(409, "revision_conflict");
    }
    private async cancelJobs(id: string): Promise<void> {
        for (const row of (await this.tx.query<{
            data: string;
        }>("SELECT data FROM jobs WHERE monitor_id=$1 AND status IN ('pending','running')", [id]))) {
            const job = JSON.parse(row.data) as ExecutionJob;
            await this.release(job);
            job.status = "cancelled";
            job.leaseToken = null;
            job.leaseUntil = 0;
            await this.saveJob(job);
            (await this.tx.query("DELETE FROM outbox WHERE id=$1", [job.id]));
        }
    }
    private async cancelNotifications(id: string, reason = "monitor_configuration_changed"): Promise<void> {
        for (const row of (await this.tx.query<{
            id: string;
            data: string;
        }>("SELECT id,data FROM notifications WHERE (data::jsonb #>> '{monitorId}')=$1 AND status IN ('pending','sending')", [id]))) {
            const notification = this.secrets.decodeNotification(row.data);
            notification.status = "failed";
            notification.lastError = reason;
            notification.leaseToken = null;
            notification.leaseUntil = 0;
            (await this.tx.query("UPDATE notifications SET status='failed',data=$1 WHERE id=$2", [this.secrets.encodeNotification(notification), row.id]));
            (await this.tx.query("DELETE FROM outbox WHERE id=$1", [row.id]));
        }
    }
    private mode(input: Record<string, unknown>, field: string): "keep" | "replace" | "remove" {
        const mode = input[`${field}Mode`] ?? "keep";
        if (mode !== "keep" && mode !== "replace" && mode !== "remove")
            throw new ApiError(400, `invalid_${field}_mode`);
        return mode;
    }
    private async updateMonitor(id: string, input: Record<string, unknown>): Promise<unknown> {
        const previous = await this.monitor(id);
        this.revision(previous, input);
        const merged: Record<string, unknown> = { ...previous, ...input, id };
        if (input.id !== undefined && input.id !== id)
            throw new ApiError(400, "monitor_id_immutable");
        const check = record(input.check ?? previous.check);
        if (check.kind === "http") {
            const headersMode = this.mode(input, "headers");
            const headers = headersMode === "remove" ? undefined : headersMode === "replace"
                ? check.headers : previous.check.kind === "http" ? previous.check.headers : undefined;
            if (headersMode === "replace" && check.headers === undefined)
                throw new ApiError(400, "replacement_headers_required");
            merged.check = { ...check, headers };
        }
        else
            merged.check = check;
        for (const field of ["webhook", "email"] as const) {
            const mode = this.mode(input, field);
            if (mode === "replace" && input[field] === undefined)
                throw new ApiError(400, `replacement_${field}_required`);
            merged[field] = mode === "keep" ? previous[field] : mode === "remove" ? undefined : input[field];
        }
        const config = monitorInput(merged, this.env);
        const token = config.check.kind === "heartbeat" && previous.check.kind !== "heartbeat" ? crypto.randomUUID() + crypto.randomUUID() : undefined;
        const hash = token ? await digest(token) : undefined;
        const current = await this.monitor(id);
        this.revision(current, input);
        const now = Date.now();
        await this.cancelJobs(id);
        await this.cancelNotifications(id);
        const monitor: MonitorRecord = { ...current, ...config, webhook: config.webhook, email: config.email, revision: current.revision + 1, candidateJobId: null, candidateSuccess: null, lastObservedAt: null, lastSlotAt: 0 };
        delete monitor.heartbeatTokenHash;
        delete monitor.heartbeatDeadline;
        delete monitor.certificate;
        delete monitor.certificateWarnedFor;
        if (config.check.kind === "heartbeat") {
            monitor.heartbeatTokenHash = hash ?? current.heartbeatTokenHash;
            monitor.heartbeatDeadline = now + config.intervalMs + (config.check.graceMs ?? 0);
        }
        monitor.nextDueAt = monitor.heartbeatDeadline ?? now;
        if (monitor.maintenanceUntil && monitor.maintenanceUntil > now)
            monitor.nextDueAt = monitor.maintenanceUntil;
        await this.setState(monitor, monitor.paused ? "PAUSED" : monitor.maintenanceUntil && monitor.maintenanceUntil > now ? "MAINTENANCE" : "UNKNOWN", now);
        await this.saveMonitor(monitor);
        return { monitor: monitorView(monitor), ...(token ? { heartbeatToken: token } : {}) };
    }
    private async deleteMonitor(id: string, input: Record<string, unknown>): Promise<unknown> {
        const monitor = await this.monitor(id);
        this.revision(monitor, input);
        const now = Date.now();
        await this.cancelJobs(id);
        await this.cancelNotifications(id, "monitor_deleted");
        (await this.tx.query("UPDATE coverage SET ended_at=GREATEST(started_at+1,$1) WHERE monitor_id=$2 AND ended_at IS NULL", [now, id]));
        (await this.tx.query("INSERT INTO retired_monitors(id,name,deleted_at) VALUES($1,$2,$3)", [id, monitor.name ?? id, now]));
        for (const table of ["observations", "incidents"] as const) {
            (await this.tx.query(`UPDATE ${table} SET data=jsonb_set(data::jsonb,'{monitorName}',to_jsonb($1::text))::text WHERE (data::jsonb #>> '{monitorId}')=$2 AND (data::jsonb #>> '{monitorName}') IS NULL`, [monitor.name ?? id, id]));
        }
        (await this.tx.query("DELETE FROM monitors WHERE id=$1", [id]));
        (await this.tx.query("DELETE FROM pulses WHERE monitor_id=$1", [id]));
        const page = await this.statusPage();
        if (page) {
            page.components = page.components.filter(component => component.monitorId !== id);
            const incidentIds = new Set((await this.tx.query<{
                id: string;
            }>("SELECT id FROM incidents WHERE (data::jsonb #>> '{monitorId}')=$1", [id])).map(row => row.id));
            page.updates = page.updates.filter(update => !incidentIds.has(update.incidentId));
            page.updatedAt = now;
            await this.storeStatusPage(page);
        }
        return { deleted: true };
    }
    private async rotateHeartbeat(id: string, input: Record<string, unknown>): Promise<unknown> {
        const token = crypto.randomUUID() + crypto.randomUUID();
        const hash = await digest(token);
        const monitor = await this.monitor(id);
        this.revision(monitor, input);
        if (monitor.check.kind !== "heartbeat")
            throw new ApiError(400, "not_heartbeat_monitor");
        monitor.heartbeatTokenHash = hash;
        monitor.revision++;
        (await this.tx.query("DELETE FROM pulses WHERE monitor_id=$1", [id]));
        await this.saveMonitor(monitor);
        return { monitor: monitorView(monitor), heartbeatToken: token };
    }
    private async exportMonitors(): Promise<unknown> {
        const monitors = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM monitors ORDER BY id")).map(row => {
            const monitor = this.secrets.decodeMonitor(row.data);
            const view = monitorView(monitor);
            return { id: view.id, name: view.name, check: view.check, intervalMs: view.intervalMs, paused: view.paused, timeoutMs: view.timeoutMs, confirmationDelayMs: view.confirmationDelayMs, executionWindowMs: view.executionWindowMs, certificateExpiryDays: view.certificateExpiryDays, ...(view.webhook ? { webhook: view.webhook } : {}), ...(view.email ? { email: view.email } : {}), secretOmissions: { headers: view.check.kind === "http" && view.check.hasHeaders, webhook: Boolean(view.webhook), heartbeatToken: monitor.check.kind === "heartbeat" } };
        });
        return { version: 1, secretOmissions: true, monitors };
    }
    private async importMonitors(input: Record<string, unknown>): Promise<unknown> {
        if (input.version !== 1)
            throw new ApiError(400, "unsupported_import_version");
        if (!Array.isArray(input.monitors) || input.monitors.length < 1 || input.monitors.length > 100)
            throw new ApiError(400, "invalid_import_count");
        const configs = input.monitors.map(value => {
            const config = { ...record(value) };
            const omissions = config.secretOmissions === undefined ? {} : record(config.secretOmissions);
            const check = { ...record(config.check) };
            if (check.kind === "http") {
                if (omissions.headers === true || check.hasHeaders === true) {
                    const mode = this.mode(config, "headers");
                    if (mode !== "remove" && !(mode === "replace" && check.headers !== undefined))
                        throw new ApiError(400, "import_headers_replacement_required");
                    if (mode === "remove")
                        delete check.headers;
                }
                delete check.headerNames;
                delete check.hasHeaders;
            }
            if (omissions.webhook === true || (config.webhook !== undefined && record(config.webhook).secret === undefined)) {
                const mode = this.mode(config, "webhook");
                if (mode === "remove")
                    delete config.webhook;
                else if (mode !== "replace" || config.webhook === undefined || record(config.webhook).secret === undefined)
                    throw new ApiError(400, "import_webhook_replacement_required");
            }
            config.check = check;
            return config;
        });
        const results = await this.insertMonitors(configs);
        return { importedCount: results.length, monitors: results };
    }
    private async page(table: "observations" | "incidents" | "notifications" | "audit", key: string, url: URL, project: (value: unknown) => unknown = value => value): Promise<unknown> {
        const limit = integer(Number(url.searchParams.get("limit") ?? 100), 1, 100, "limit");
        const cursor = url.searchParams.get("cursor");
        const before = cursor === null ? Number.MAX_SAFE_INTEGER : integer(Number(cursor), 1, Number.MAX_SAFE_INTEGER, "cursor");
        const monitorId = url.searchParams.get("monitorId");
        if (monitorId)
            identifier(monitorId);
        const filter = monitorId && table !== "audit" ? " AND (data::jsonb->>'monitorId')=$2" : "";
        const params: (string | number)[] = [before];
        if (filter)
            params.push(monitorId!);
        params.push(limit + 1);
        const rows = (await this.tx.query<{
            cursor: number;
            data: string;
        }>(`SELECT cursor,data FROM ${table} WHERE cursor<$1${filter} ORDER BY cursor DESC LIMIT $${params.length}`, params));
        const items = rows.slice(0, limit);
        return { [key]: items.map(row => project(JSON.parse(row.data))), cursor: rows.length > limit ? String(items[items.length - 1]!.cursor) : null };
    }
    private async usage(): Promise<WalletView> {
        const wallet = (await this.tx.query<{
            balance: number;
            reserved: number;
            usage: number;
            missed: number;
        }>("SELECT balance,reserved,usage,missed FROM wallet WHERE id=1"))[0]!;
        const monitors = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM monitors WHERE paused=0")).map(row => this.secrets.decodeMonitor(row.data));
        const forecastChecksPerDay = monitors.filter(monitor => monitor.check.kind !== "heartbeat" && !(monitor.maintenanceUntil && monitor.maintenanceUntil > Date.now())).reduce((sum, monitor) => sum + 86400000 / monitor.intervalMs, 0);
        const grants = (await this.tx.query<{
            id: string;
            credits: number;
            reason: string;
            createdAt: number;
        }>("SELECT deposits.id,credits,COALESCE(reason,'legacy-operator-testing-grant') AS reason,COALESCE(created_at,0) AS \"createdAt\" FROM deposits LEFT JOIN grants ON grants.id=deposits.id ORDER BY \"createdAt\" DESC,deposits.id"));
        const heartbeatReceipts = (await this.tx.query<{
            count: number;
        }>("SELECT COUNT(*) AS count FROM pulses"))[0]!.count;
        const heartbeatCreditsUsed = Number((await this.tx.query<{
            value: string;
        }>("SELECT value FROM metadata WHERE key='heartbeat-usage'"))[0]!.value);
        return { mode: this.env.MODE, creditEnforced: this.env.MODE === "hosted", balance: wallet.balance, reserved: wallet.reserved, available: wallet.balance - wallet.reserved, usage: wallet.usage, missedSlots: wallet.missed, forecastChecksPerDay, estimatedDepletionAt: this.env.MODE === "hosted" && forecastChecksPerDay > 0 ? Date.now() + (wallet.balance - wallet.reserved) / forecastChecksPerDay * 86400000 : null, creditSource: this.env.MODE === "self-host" ? "self-host" : "hosted-ledger", grants, heartbeatCreditsUsed, heartbeatReceipts };
    }
    private async audit(input: Record<string, unknown>): Promise<AuditView> {
        const entry: AuditView = { id: crypto.randomUUID(), actor: text(input.actor, 120, "actor"), action: text(input.action, 120, "action"), subject: text(input.subject, 120, "subject"), occurredAt: Date.now() };
        (await this.tx.query("INSERT INTO audit(id,data) VALUES($1,$2)", [entry.id, JSON.stringify(entry)]));
        return entry;
    }
    private async statusPage(): Promise<PublicPageConfig | null> {
        const row = (await this.tx.query<{
            value: string;
        }>("SELECT value FROM metadata WHERE key='status-page'"))[0];
        return row ? JSON.parse(row.value) as PublicPageConfig : null;
    }
    private async pageRevision(): Promise<number> {
        const rows = await this.tx.query<{value:string}>("SELECT value FROM metadata WHERE key='status-page-revision'");
        return Number(rows[0]?.value ?? 0);
    }
    private async storeStatusPage(page: PublicPageConfig): Promise<void> {
        (await this.tx.query("INSERT INTO metadata(key,value) VALUES('status-page',$1) ON CONFLICT(account_id,key) DO UPDATE SET value=excluded.value", [JSON.stringify(page)]));
        await this.tx.query("INSERT INTO metadata(key,value) VALUES('status-page-revision',$1) ON CONFLICT(account_id,key) DO UPDATE SET value=excluded.value", [String(page.revision)]);
    }
    private async saveStatusPage(input: Record<string, unknown>, commit = true): Promise<unknown> {
        const revision = await this.pageRevision();
        if (integer(input.revision, 0, Number.MAX_SAFE_INTEGER, "revision") !== revision) throw new ApiError(409, "revision_conflict");
        const slug = text(input.slug, 63, "slug");
        if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(slug))
            throw new ApiError(400, "invalid_slug");
        if (typeof input.published !== "boolean" || !Array.isArray(input.components) || input.components.length > 100)
            throw new ApiError(400, "invalid_status_page");
        const selected = new Set<string>();
        const components: PublicPageConfig["components"] = [];
        for (const value of input.components) {
            const component = record(value);
            const monitorId = identifier(String(component.monitorId ?? ""));
            await this.monitor(monitorId);
            if (selected.has(monitorId))
                throw new ApiError(400, "duplicate_component");
            selected.add(monitorId);
            components.push({ monitorId, label: text(component.label, 120, "component_label") });
        }
        const previous = await this.statusPage();
        const page: PublicPageConfig = { revision: revision + 1, slug, title: text(input.title, 120, "title"), published: input.published, components, updatedAt: Date.now(), updates: previous?.updates ?? [] };
        if (commit)
            await this.storeStatusPage(page);
        return { page };
    }
    private async publishUpdate(input: Record<string, unknown>): Promise<unknown> {
        const page = await this.statusPage();
        if (!page)
            throw new ApiError(404, "status_page_not_found");
        if (integer(input.revision, 1, Number.MAX_SAFE_INTEGER, "revision") !== page.revision) throw new ApiError(409, "revision_conflict");
        const incidentId = text(input.incidentId, 512, "incident_id");
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM incidents WHERE id=$1", [incidentId]))[0];
        if (!row)
            throw new ApiError(404, "incident_not_found");
        const incident = JSON.parse(row.data) as Incident;
        if (!page.components.some(component => component.monitorId === incident.monitorId))
            throw new ApiError(400, "incident_not_selected");
        if (page.updates.length >= 100)
            throw new ApiError(409, "status_update_limit");
        const update = { id: crypto.randomUUID(), incidentId, body: text(input.body, 2000, "update_body", true), publishedAt: Date.now() };
        page.updates.push(update);
        page.updatedAt = update.publishedAt;
        page.revision++;
        await this.storeStatusPage(page);
        return { update, page };
    }
    private async removeUpdate(input: Record<string, unknown>): Promise<unknown> {
        const page = await this.statusPage();
        if (!page)
            throw new ApiError(404, "status_page_not_found");
        if (integer(input.revision, 1, Number.MAX_SAFE_INTEGER, "revision") !== page.revision) throw new ApiError(409, "revision_conflict");
        const id = identifier(String(input.id ?? ""));
        if (!page.updates.some(update => update.id === id))
            throw new ApiError(404, "update_not_found");
        page.updates = page.updates.filter(update => update.id !== id);
        page.updatedAt = Date.now();
        page.revision++;
        await this.storeStatusPage(page);
        return { page };
    }
    private async publicStatus(): Promise<PublicStatusView> {
        const page = await this.statusPage();
        if (!page || !page.published)
            throw new ApiError(404, "status_page_not_found");
        const now = Date.now();
        const components: PublicStatusView["components"] = [];
        for (const component of page.components) {
            const monitor = monitorView(await this.monitor(component.monitorId), now);
            components.push({ label: component.label, state: monitor.effectiveState, lastObservedAt: monitor.lastObservedAt, freshUntil: monitor.freshUntil });
        }
        const incidents: PublicStatusView["incidents"] = [];
        for (const component of page.components) {
            const rows = await this.tx.query<{ data: string }>("SELECT data FROM incidents WHERE (data::jsonb #>> '{monitorId}')=$1 ORDER BY cursor DESC LIMIT 100", [component.monitorId]);
            for (const row of rows) {
                const incident = JSON.parse(row.data) as Incident;
                incidents.push({ componentLabel: component.label, openedAt: incident.openedAt, closedAt: incident.closedAt, updates: page.updates.filter(update => update.incidentId === incident.id).map(update => ({ body: update.body, publishedAt: update.publishedAt })) });
            }
        }
        return { slug: page.slug, title: page.title, generatedAt: now, updatedAt: page.updatedAt, components, incidents };
    }
    private async checkNow(id: string, input: Record<string, unknown>): Promise<unknown> {
        const now = Date.now();
        await this.advanceMaintenance(now);
        const monitor = await this.monitor(id);
        this.revision(monitor, input);
        if (monitor.paused)
            throw new ApiError(409, "monitor_paused");
        if (monitor.maintenanceUntil && monitor.maintenanceUntil > now)
            throw new ApiError(409, "monitor_in_maintenance");
        if (monitor.check.kind === "heartbeat")
            throw new ApiError(409, "heartbeat_requires_authenticated_pulse");
        const wallet = (await this.tx.query<{
            balance: number;
            reserved: number;
        }>("SELECT balance,reserved FROM wallet WHERE id=1"))[0]!;
        if (this.env.MODE === "hosted" && wallet.balance - wallet.reserved < 1)
            throw new ApiError(402, "insufficient_credits");
        if ((await this.tx.query("SELECT 1 FROM jobs WHERE monitor_id=$1 AND status IN ('pending','running') AND (data::jsonb #>> '{manual}')='true'", [id])).length)
            throw new ApiError(409, "manual_check_in_progress");
        const scheduledAt = now;
        const job: ExecutionJob = { id: `${id}:${monitor.revision}:${scheduledAt}:manual:${crypto.randomUUID()}`, monitorId: id, revision: monitor.revision, scheduledAt, expiresAt: scheduledAt + monitor.executionWindowMs, role: "primary", rootJobId: null, status: "pending", leaseToken: null, leaseUntil: 0, reserved: 0, enqueuedAt: now, manual: true };
        await this.saveJob(job);
        await this.enqueue(job.id, { kind: "check", accountId: this.accountId, jobId: job.id });
        return { queued: true, jobId: job.id, monitor: monitorView(monitor), nextOrdinaryDueAt: monitor.nextDueAt };
    }
    private async setPaused(id: string, paused: boolean, input: Record<string, unknown>): Promise<{
        monitor: MonitorView;
    }> {
        const monitor = await this.monitor(id);
        this.revision(monitor, input);
        if (monitor.paused === paused)
            return { monitor: monitorView(monitor) };
        const now = Date.now();
        monitor.paused = paused;
        monitor.revision++;
        monitor.candidateJobId = null;
        monitor.candidateSuccess = null;
        await this.cancelJobs(id);
        if (monitor.check.kind === "heartbeat") {
            monitor.heartbeatDeadline = now + monitor.intervalMs + (monitor.check.graceMs ?? 0);
            monitor.nextDueAt = monitor.heartbeatDeadline;
        }
        else
            monitor.nextDueAt = now;
        if (!paused && monitor.maintenanceUntil && monitor.maintenanceUntil > now)
            monitor.nextDueAt = monitor.maintenanceUntil;
        await this.setState(monitor, paused ? "PAUSED" : monitor.maintenanceUntil && monitor.maintenanceUntil > now ? "MAINTENANCE" : "UNKNOWN", now);
        await this.saveMonitor(monitor);
        return { monitor: monitorView(monitor) };
    }
    private async heartbeat(id: string, request: Request): Promise<unknown> {
        const token = request.headers.get("Authorization")?.replace(/^Bearer /, "") ?? "";
        if (!token || token.length > 256)
            throw new ApiError(401, "invalid_heartbeat_token");
        const tokenHash = await digest(token);
        const pulseId = identifier(request.headers.get("Idempotency-Key") ?? "");
        const now = Date.now();
        await this.advanceMaintenance(now);
        const monitor = await this.monitor(id);
        if (monitor.check.kind !== "heartbeat" || !monitor.heartbeatTokenHash || !constantEqual(tokenHash, monitor.heartbeatTokenHash))
            throw new ApiError(401, "invalid_heartbeat_token");
        if (monitor.paused)
            throw new ApiError(409, "monitor_paused");
        const existing = (await this.tx.query("SELECT 1 FROM pulses WHERE monitor_id=$1 AND pulse_id=$2", [id, pulseId])).length;
        if (existing)
            return { accepted: false, duplicate: true, state: monitor.state };
        const wallet = (await this.tx.query<{
            balance: number;
            reserved: number;
        }>("SELECT balance,reserved FROM wallet WHERE id=1"))[0]!;
        if (monitor.maintenanceUntil && monitor.maintenanceUntil > now)
            return { accepted: false, duplicate: false, maintenance: true, state: "MAINTENANCE" };
        if (this.env.MODE === "hosted" && wallet.balance - wallet.reserved < 1) {
            if (monitor.state !== "DOWN") {
                monitor.heartbeatBlocked = true;
                await this.setState(monitor, "UNKNOWN", now);
            }
            await this.saveMonitor(monitor);
            return { error: "insufficient_credits" };
        }
        (await this.tx.query("INSERT INTO pulses(monitor_id,pulse_id,received_at) VALUES($1,$2,$3)", [id, pulseId, now]));
        await this.tx.query("UPDATE wallet SET balance=balance-$1,usage=usage+1 WHERE id=1", [this.env.MODE === "hosted" ? 1 : 0]);
        (await this.tx.query("UPDATE metadata SET value=((value::bigint)+1)::text WHERE key='heartbeat-usage'"));
        monitor.heartbeatBlocked = false;
        monitor.lastObservedAt = now;
        monitor.heartbeatDeadline = now + monitor.intervalMs + (monitor.check.graceMs ?? 0);
        monitor.nextDueAt = monitor.heartbeatDeadline;
        (await this.tx.query("INSERT INTO freshness(monitor_id,observed_at,fresh_until) VALUES($1,$2,$3) ON CONFLICT(account_id,monitor_id,observed_at) DO UPDATE SET fresh_until=excluded.fresh_until", [monitor.id, now, monitor.heartbeatDeadline]));
        if (monitor.incidentId)
            await this.closeIncident(monitor, now);
        await this.setState(monitor, "UP", now);
        await this.saveMonitor(monitor);
        return { accepted: true, duplicate: false, state: monitor.state };
    }
    private async advance(now: number): Promise<void> {
        await this.advanceMaintenance(now);
        const expired = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM jobs WHERE status IN ('pending','running') AND expires_at<$1 LIMIT 200", [now]));
        for (const row of expired)
            await this.miss(JSON.parse(row.data) as ExecutionJob, now);
        const due = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM monitors WHERE paused=0 AND next_due<=$1 ORDER BY next_due LIMIT 100", [now]));
        for (const row of due) {
            const monitor = this.secrets.decodeMonitor(row.data);
            if (monitor.maintenanceUntil && monitor.maintenanceUntil > now)
                continue;
            if (monitor.check.kind === "heartbeat") {
                const deadline = monitor.heartbeatDeadline ?? monitor.nextDueAt;
                if (monitor.state !== "DOWN") {
                    if (monitor.heartbeatBlocked || now - deadline > monitor.executionWindowMs) {
                        await this.setState(monitor, "UNKNOWN", deadline + monitor.executionWindowMs);
                        (await this.tx.query("UPDATE wallet SET missed=missed+1 WHERE id=1"));
                    }
                    else {
                        if (!monitor.incidentId)
                            await this.openIncident(monitor, `heartbeat:${monitor.id}:${monitor.revision}:${deadline}`, deadline, now);
                        await this.setState(monitor, "DOWN", now);
                    }
                }
                monitor.nextDueAt = now + monitor.intervalMs;
                monitor.heartbeatDeadline = monitor.nextDueAt;
                await this.saveMonitor(monitor);
                continue;
            }
            const elapsedSlots = Math.floor((now - monitor.nextDueAt) / monitor.intervalMs);
            const slot = monitor.nextDueAt + elapsedSlots * monitor.intervalMs;
            if (elapsedSlots > 0) {
                (await this.tx.query("UPDATE wallet SET missed=missed+$1 WHERE id=1", [elapsedSlots]));
                await this.setState(monitor, "UNKNOWN", Math.min(now, monitor.nextDueAt + monitor.executionWindowMs));
                monitor.candidateJobId = null;
                monitor.candidateSuccess = null;
                monitor.lastSlotAt = slot;
            }
            monitor.nextDueAt = slot + monitor.intervalMs;
            if (now > slot + monitor.executionWindowMs) {
                (await this.tx.query("UPDATE wallet SET missed=missed+1 WHERE id=1"));
                await this.setState(monitor, "UNKNOWN", slot + monitor.executionWindowMs);
            }
            else {
                const id = `${monitor.id}:${monitor.revision}:${slot}:primary`;
                const job: ExecutionJob = {
                    id, monitorId: monitor.id, revision: monitor.revision, scheduledAt: slot, expiresAt: slot + monitor.executionWindowMs,
                    role: "primary", rootJobId: null, status: "pending", leaseToken: null, leaseUntil: 0, reserved: 0, enqueuedAt: now,
                };
                if (!(await this.tx.query("SELECT 1 FROM jobs WHERE id=$1", [id])).length) {
                    await this.saveJob(job);
                    await this.enqueue(id, { kind: "check", accountId: this.accountId, jobId: id });
                }
            }
            await this.saveMonitor(monitor);
        }
        (await this.tx.query("DELETE FROM observations WHERE archived=1 AND observed_at<$1", [now - RETENTION_MS]));
        (await this.tx.query("DELETE FROM freshness WHERE fresh_until<$1", [now - RETENTION_MS]));
        (await this.tx.query("DELETE FROM jobs WHERE status IN ('done','missed','cancelled') AND expires_at<$1", [now - RETENTION_MS]));
        await this.tx.query("DELETE FROM coverage WHERE ended_at<$1", [now - RETENTION_MS]);
        await this.tx.query("DELETE FROM maintenance WHERE ends_at<$1", [now - RETENTION_MS]);
        await this.tx.query("DELETE FROM audit WHERE (data::jsonb->>'occurredAt')::bigint<$1", [now - 90 * 86400000]);
        await this.tx.query("DELETE FROM notifications WHERE status IN ('delivered','failed') AND (data::jsonb->>'occurredAt')::bigint<$1", [now - 30 * 86400000]);
        await this.tx.query("DELETE FROM incidents WHERE (data::jsonb->>'closedAt')::bigint<$1 AND NOT EXISTS(SELECT 1 FROM monitors WHERE monitors.id=(incidents.data::jsonb->>'monitorId') AND monitors.data::jsonb->>'incidentId'=incidents.id)", [now - 90 * 86400000]);
        await this.tx.query("DELETE FROM archives WHERE created_at<$1", [now - (this.env.ARCHIVE_RETENTION_DAYS ?? 30) * 86400000]);
    }
    private async release(job: ExecutionJob): Promise<void> {
        if (job.reserved) {
            (await this.tx.query("UPDATE wallet SET reserved=reserved-$1 WHERE id=1", [job.reserved]));
            job.reserved = 0;
        }
    }
    private async miss(job: ExecutionJob, now: number): Promise<void> {
        await this.release(job);
        job.status = "missed";
        await this.saveJob(job);
        (await this.tx.query("DELETE FROM outbox WHERE id=$1", [job.id]));
        const monitor = await this.monitor(job.monitorId);
        if (monitor.revision !== job.revision || monitor.paused)
            return;
        const relevant = job.role === "primary" ? job.scheduledAt >= monitor.lastSlotAt : monitor.candidateJobId === job.rootJobId;
        if (relevant) {
            await this.setState(monitor, "UNKNOWN", Math.min(now, job.expiresAt));
            if (job.role === "primary")
                monitor.lastSlotAt = job.scheduledAt;
            monitor.candidateJobId = null;
            monitor.candidateSuccess = null;
            await this.saveMonitor(monitor);
        }
        if (job.role === "primary")
            (await this.tx.query("UPDATE wallet SET missed=missed+1 WHERE id=1"));
    }
    private async claim(id: string, now: number): Promise<ClaimedCheck | null> {
        await this.advanceMaintenance(now);
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM jobs WHERE id=$1", [id]))[0];
        if (!row)
            return null;
        const job = JSON.parse(row.data) as ExecutionJob;
        if (job.status !== "pending" && job.status !== "running")
            return null;
        if (now > job.expiresAt) {
            await this.miss(job, now);
            return null;
        }
        if (now < job.scheduledAt || (job.status === "running" && job.leaseUntil > now))
            return null;
        const monitor = await this.monitor(job.monitorId);
        if (monitor.paused || monitor.revision !== job.revision || monitor.check.kind === "heartbeat" || (job.role === "confirmation" && monitor.candidateJobId !== job.rootJobId)) {
            await this.release(job);
            job.status = "cancelled";
            await this.saveJob(job);
            (await this.tx.query("DELETE FROM outbox WHERE id=$1", [id]));
            return null;
        }
        if (this.env.MODE === "hosted" && job.role === "primary" && !job.reserved) {
            const wallet = (await this.tx.query<{
                balance: number;
                reserved: number;
            }>("SELECT balance,reserved FROM wallet WHERE id=1"))[0]!;
            if (wallet.balance - wallet.reserved < 1) {
                await this.miss(job, now);
                return null;
            }
            (await this.tx.query("UPDATE wallet SET reserved=reserved+1 WHERE id=1"));
            job.reserved = 1;
        }
        job.status = "running";
        job.leaseToken = crypto.randomUUID();
        const egressOverhead = this.env.PROBER ? EGRESS_OVERHEAD_MS : 0;
        job.leaseUntil = Math.min(job.expiresAt, now + monitor.timeoutMs + egressOverhead + LEASE_MARGIN_MS);
        await this.saveJob(job);
        return { job, check: monitor.check, timeoutMs: monitor.timeoutMs, leaseToken: job.leaseToken };
    }
    private async complete(id: string, token: string, result: ProbeResult): Promise<boolean> {
        const now = Date.now();
        await this.advanceMaintenance(now);
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM jobs WHERE id=$1", [id]))[0];
        if (!row)
            return false;
        const job = JSON.parse(row.data) as ExecutionJob;
        if (job.status !== "running" || !job.leaseToken || !constantEqual(job.leaseToken, token))
            return false;
        const monitor = await this.monitor(job.monitorId);
        if (now > job.expiresAt) {
            await this.miss(job, now);
            return false;
        }
        if (now > job.leaseUntil)
            return false;
        if (monitor.paused || job.revision !== monitor.revision || result.startedAt < job.scheduledAt)
            return false;
        const eligible = result.outcome !== "unknown" && job.role === "primary";
        const debit = eligible && this.env.MODE === "hosted" ? job.reserved : 0;
        await this.release(job);
        if (eligible)
            await this.tx.query("UPDATE wallet SET balance=balance-$1,usage=usage+1 WHERE id=1", [debit]);
        job.status = "done";
        await this.saveJob(job);
        (await this.tx.query("DELETE FROM outbox WHERE id=$1", [id]));
        const observation: StoredObservation = { id, monitorId: monitor.id, monitorName: monitor.name ?? monitor.id, scheduledAt: job.scheduledAt, result };
        (await this.tx.query("INSERT INTO observations(id,observed_at,data) VALUES($1,$2,$3)", [id, result.finishedAt, JSON.stringify(observation)]));
        await this.enqueue(`archive:${this.accountId}`, { kind: "archive", accountId: this.accountId });
        const relevant = job.role === "primary" ? job.scheduledAt >= monitor.lastSlotAt : monitor.candidateJobId === job.rootJobId;
        if (!relevant)
            return true;
        if (job.role === "primary") {
            monitor.lastSlotAt = job.scheduledAt;
            if (result.finishedAt < (monitor.lastObservedAt ?? 0)) {
                await this.saveMonitor(monitor);
                return true;
            }
        }
        if (job.role === "confirmation" && result.finishedAt < (monitor.lastObservedAt ?? 0) &&
            (result.outcome === "unknown" || (result.outcome === "success") !== monitor.candidateSuccess)) {
            const candidateSuccess = monitor.candidateSuccess;
            monitor.candidateJobId = null;
            monitor.candidateSuccess = null;
            const latestRow = (await this.tx.query<{id:string;data:string}>("SELECT jobs.id,jobs.data FROM jobs JOIN observations ON observations.id=jobs.id WHERE jobs.monitor_id=$1 AND (jobs.data::jsonb->>'revision')::bigint=$2 AND jobs.scheduled_at=$3 AND jobs.data::jsonb->>'role'='primary' AND jobs.status='done' ORDER BY observations.cursor DESC LIMIT 1", [monitor.id, monitor.revision, monitor.lastSlotAt]))[0];
            const latestId = latestRow?.id;
            if (latestRow && latestId !== job.rootJobId && candidateSuccess !== null) {
                const latest = JSON.parse(latestRow.data) as ExecutionJob;
                if (latest.status === "done") {
                    monitor.candidateJobId = latest.id;
                    monitor.candidateSuccess = candidateSuccess;
                    await this.confirm(monitor, latest, now);
                }
            }
            await this.saveMonitor(monitor);
            return true;
        }
        monitor.lastObservedAt = Math.max(monitor.lastObservedAt ?? 0, result.finishedAt);
        if (result.evidence?.certificate) {
            monitor.certificate = { ...result.evidence.certificate, observedAt: result.finishedAt };
            if (monitor.certificate.validTo - result.finishedAt <= (monitor.certificateExpiryDays ?? 14) * 86400000 && monitor.certificateWarnedFor !== monitor.certificate.validTo && (monitor.webhook || monitor.email)) {
                await this.notify(monitor, null, "certificate", result.finishedAt, `certificate:${monitor.id}:${monitor.certificate.validTo}`);
                monitor.certificateWarnedFor = monitor.certificate.validTo;
            }
        }
        if (result.outcome !== "unknown")
            (await this.tx.query("INSERT INTO freshness(monitor_id,observed_at,fresh_until) VALUES($1,$2,$3) ON CONFLICT(account_id,monitor_id,observed_at) DO UPDATE SET fresh_until=excluded.fresh_until", [monitor.id, result.finishedAt, result.finishedAt + monitor.intervalMs + monitor.executionWindowMs]));
        if (result.outcome === "unknown") {
            await this.setState(monitor, "UNKNOWN", result.finishedAt);
            monitor.candidateJobId = null;
            monitor.candidateSuccess = null;
        }
        else if (job.role === "primary") {
            const success = result.outcome === "success";
            if ((success && monitor.incidentId) || (!success && !monitor.incidentId)) {
                const pendingConfirmation = monitor.candidateJobId && monitor.candidateSuccess === success &&
                    (await this.tx.query("SELECT 1 FROM jobs WHERE id=$1 AND status IN ('pending','running')", [`${monitor.candidateJobId}:confirmation`])).length > 0;
                if (!pendingConfirmation) {
                    monitor.candidateJobId = id;
                    monitor.candidateSuccess = success;
                    await this.confirm(monitor, job, now);
                }
                await this.setState(monitor, success ? "RECOVERING" : "SUSPECT", result.finishedAt);
            }
            else {
                monitor.candidateJobId = null;
                monitor.candidateSuccess = null;
                await this.setState(monitor, success ? "UP" : "DOWN", result.finishedAt);
            }
        }
        else {
            const success = result.outcome === "success";
            if (!success && !monitor.incidentId) {
                const primary = (await this.tx.query<{
                    data: string;
                }>("SELECT data FROM observations WHERE id=$1", [job.rootJobId!]))[0];
                const firstFailure = primary ? (JSON.parse(primary.data) as StoredObservation).result.finishedAt : result.finishedAt;
                await this.openIncident(monitor, `${job.rootJobId}:incident`, firstFailure, result.finishedAt);
            }
            else if (success && monitor.incidentId)
                await this.closeIncident(monitor, result.finishedAt);
            await this.setState(monitor, success ? "UP" : "DOWN", result.finishedAt);
            monitor.candidateJobId = null;
            monitor.candidateSuccess = null;
        }
        await this.saveMonitor(monitor);
        return true;
    }
    private async confirm(monitor: MonitorRecord, primary: ExecutionJob, now: number): Promise<void> {
        const dueAt = now + monitor.confirmationDelayMs;
        const id = `${primary.id}:confirmation`;
        const confirmation: ExecutionJob = {
            id, monitorId: monitor.id, revision: monitor.revision, scheduledAt: dueAt, expiresAt: dueAt + monitor.executionWindowMs,
            role: "confirmation", rootJobId: primary.id, status: "pending", leaseToken: null, leaseUntil: 0, reserved: 0, enqueuedAt: 0,
        };
        await this.saveJob(confirmation);
        await this.enqueue(id, { kind: "check", accountId: this.accountId, jobId: id }, dueAt);
    }
    private async openIncident(monitor: MonitorRecord, id: string, firstFailureAt: number, at: number): Promise<void> {
        const incident: Incident = { id, monitorId: monitor.id, monitorName: monitor.name ?? monitor.id, openedAt: at, firstFailureAt, closedAt: null };
        (await this.tx.query("INSERT INTO incidents(id,data) VALUES($1,$2)", [id, JSON.stringify(incident)]));
        monitor.incidentId = id;
        await this.notify(monitor, incident, "down", at);
    }
    private async closeIncident(monitor: MonitorRecord, at: number): Promise<void> {
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM incidents WHERE id=$1", [monitor.incidentId!]))[0]!;
        const incident = JSON.parse(row.data) as Incident;
        incident.closedAt = at;
        (await this.tx.query("UPDATE incidents SET data=$1 WHERE id=$2", [JSON.stringify(incident), incident.id]));
        await this.notify(monitor, incident, "recovery", at);
        monitor.incidentId = null;
    }
    private async notify(monitor: MonitorRecord, incident: Incident | null, type: NotificationRecord["type"], at: number, testId: string = crypto.randomUUID()): Promise<NotificationView[]> {
        const baseId = `${this.accountId}:${incident?.id ?? `test:${testId}`}:${type}`;
        const channels: ("webhook" | "email")[] = [];
        if (monitor.webhook)
            channels.push("webhook");
        if (monitor.email)
            channels.push("email");
        const notifications: NotificationView[] = [];
        for (const channel of channels) {
            const id = channel === "webhook" ? baseId : `${baseId}:email`;
            const notification: NotificationRecord = {
                id, monitorId: monitor.id, monitorName: monitor.name ?? monitor.id, incidentId: incident?.id ?? null, type, occurredAt: at, channel,
                ...(type === "certificate" && monitor.certificate ? { certificate: { validTo: monitor.certificate.validTo, observedAt: monitor.certificate.observedAt } } : {}),
                ...(channel === "webhook" ? { url: monitor.webhook!.url, secret: monitor.webhook!.secret } : { email: monitor.email! }),
                status: "pending", leaseToken: null, leaseUntil: 0, attempts: 0, attemptBase: 0, nextAttemptAt: at, deliveredAt: null, lastError: null,
            };
            (await this.tx.query("INSERT INTO notifications(id,status,next_due,data) VALUES($1,'pending',$2,$3) ON CONFLICT DO NOTHING", [id, notification.nextAttemptAt, this.secrets.encodeNotification(notification)]));
            await this.enqueue(id, { kind: "notification", accountId: this.accountId, eventId: id }, at);
            notifications.push(this.notificationView(notification));
        }
        return notifications;
    }
    private notificationView(notification: NotificationRecord): NotificationView {
        const { secret: _secret, leaseToken: _token, leaseUntil: _lease, url: _url, email: _email, attemptBase: _base, ...safe } = notification;
        return { ...safe, channel: notification.channel ?? "webhook", lastError: notification.lastError ?? null };
    }
    private async testNotification(id: string, input: Record<string, unknown>): Promise<unknown> {
        await this.advanceMaintenance(Date.now());
        const monitor = await this.monitor(id);
        this.revision(monitor, input);
        if (monitor.maintenanceUntil && monitor.maintenanceUntil > Date.now())
            throw new ApiError(409, "monitor_in_maintenance");
        if (!monitor.webhook && !monitor.email)
            throw new ApiError(409, "notification_channel_not_configured");
        if (monitor.email && (!this.env.EMAIL || !this.env.EMAIL_FROM))
            throw new ApiError(409, "email_not_configured");
        return { notifications: await this.notify(monitor, null, "test", Date.now()) };
    }
    private async retryNotification(input: Record<string, unknown>): Promise<unknown> {
        const id = text(input.eventId, 1024, "event_id");
        await this.advanceMaintenance(Date.now());
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM notifications WHERE id=$1", [id]))[0];
        if (!row)
            throw new ApiError(404, "notification_not_found");
        const notification = this.secrets.decodeNotification(row.data);
        const activeWindow = (await this.tx.query("SELECT 1 FROM maintenance WHERE monitor_id=$1 AND starts_at<=$2 AND ends_at>$3 AND (data::jsonb #>> '{status}')!='cancelled'", [notification.monitorId, Date.now(), Date.now()])).length;
        if (activeWindow)
            throw new ApiError(409, "monitor_in_maintenance");
        const monitor = await this.monitor(notification.monitorId);
        if (notification.status !== "failed")
            throw new ApiError(409, "notification_not_failed");
        if (notification.channel === "email") {
            if (!this.env.EMAIL || !this.env.EMAIL_FROM)
                throw new ApiError(409, "email_not_configured");
            if (!monitor.email)
                throw new ApiError(409, "notification_channel_not_configured");
            notification.email = monitor.email;
        }
        else {
            if (!monitor.webhook)
                throw new ApiError(409, "notification_channel_not_configured");
            notification.url = monitor.webhook.url;
            notification.secret = monitor.webhook.secret;
        }
        notification.status = "pending";
        notification.attemptBase = notification.attempts;
        notification.leaseToken = null;
        notification.leaseUntil = 0;
        notification.nextAttemptAt = Date.now();
        (await this.tx.query("UPDATE notifications SET status='pending',next_due=$1,data=$2 WHERE id=$3", [notification.nextAttemptAt, this.secrets.encodeNotification(notification), id]));
        await this.enqueue(id, { kind: "notification", accountId: this.accountId, eventId: id });
        return { notification: this.notificationView(notification) };
    }
    private async claimNotification(id: string, now: number): Promise<NotificationRecord | null> {
        await this.advanceMaintenance(now);
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM notifications WHERE id=$1", [id]))[0];
        if (!row)
            return null;
        const notification = this.secrets.decodeNotification(row.data);
        if (notification.status === "delivered" || notification.status === "failed" || notification.nextAttemptAt > now || (notification.status === "sending" && notification.leaseUntil > now))
            return null;
        if (notification.attempts - (notification.attemptBase ?? 0) >= 10) {
            notification.status = "failed";
            notification.lastError = "delivery_lease_expired";
            notification.leaseToken = null;
            notification.leaseUntil = 0;
            (await this.tx.query("UPDATE notifications SET status='failed',data=$1 WHERE id=$2", [this.secrets.encodeNotification(notification), id]));
            (await this.tx.query("DELETE FROM outbox WHERE id=$1", [id]));
            return null;
        }
        notification.status = "sending";
        notification.leaseToken = crypto.randomUUID();
        notification.leaseUntil = now + (notification.channel === "email" ? 60000 : 10000 + (this.env.PROBER ? EGRESS_OVERHEAD_MS : 0) + LEASE_MARGIN_MS);
        notification.attempts++;
        (await this.tx.query("UPDATE notifications SET status='sending',data=$1 WHERE id=$2", [this.secrets.encodeNotification(notification), id]));
        return notification;
    }
    private async completeNotification(id: string, token: string, success: boolean, now: number, lastError: unknown): Promise<boolean> {
        await this.advanceMaintenance(now);
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM notifications WHERE id=$1", [id]))[0];
        if (!row)
            return false;
        const notification = this.secrets.decodeNotification(row.data);
        if (notification.status !== "sending" || !notification.leaseToken || now > notification.leaseUntil || !constantEqual(notification.leaseToken, token))
            return false;
        notification.leaseToken = null;
        notification.leaseUntil = 0;
        if (success) {
            notification.status = "delivered";
            notification.deliveredAt = now;
            notification.lastError = null;
            (await this.tx.query("DELETE FROM outbox WHERE id=$1", [id]));
        }
        else {
            const cycleAttempts = notification.attempts - (notification.attemptBase ?? 0);
            notification.lastError = typeof lastError === "string" && (/^http_[1-5]\d\d$/.test(lastError) || ["delivery_failed", "delivery_timeout", "email_send_failed", "email_not_configured", "egress_not_configured", "egress_unavailable", "network_error", "blocked_target", "unsafe_address", "dns_failure"].includes(lastError)) ? lastError : "delivery_failed";
            notification.status = cycleAttempts >= 10 ? "failed" : "pending";
            notification.nextAttemptAt = now + Math.min(300000, 1000 * 2 ** Math.min(cycleAttempts, 8));
            if (notification.status === "failed")
                (await this.tx.query("DELETE FROM outbox WHERE id=$1", [id]));
            else
                (await this.tx.query("UPDATE outbox SET next_due=$1 WHERE id=$2", [notification.nextAttemptAt, id]));
        }
        (await this.tx.query("UPDATE notifications SET status=$1,next_due=$2,data=$3 WHERE id=$4", [notification.status, notification.nextAttemptAt, this.secrets.encodeNotification(notification), id]));
        return true;
    }
    private async claimArchive(): Promise<{
        id: string;
        observations: StoredObservation[];
    } | null> {
        const pending = (await this.tx.query<{
            value: string;
        }>("SELECT value FROM metadata WHERE key='archive'"))[0];
        if (pending)
            return JSON.parse(pending.value) as {
                id: string;
                observations: StoredObservation[];
            };
        const rows = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM observations WHERE archived=0 ORDER BY observed_at,id LIMIT 100"));
        if (!rows.length) {
            (await this.tx.query("DELETE FROM outbox WHERE id=$1", [`archive:${this.accountId}`]));
            return null;
        }
        (await this.tx.query("UPDATE wallet SET archive_sequence=archive_sequence+1 WHERE id=1"));
        const sequence = (await this.tx.query<{
            archive_sequence: number;
        }>("SELECT archive_sequence FROM wallet WHERE id=1"))[0]!.archive_sequence;
        const observations: StoredObservation[] = [];
        let encodedBytes = 128;
        for (const row of rows) {
            const bytes = Buffer.byteLength(row.data) + 1;
            if (encodedBytes + bytes > 1048576) break;
            observations.push(JSON.parse(row.data) as StoredObservation);
            encodedBytes += bytes;
        }
        if (!observations.length) throw new Error("stored_observation_exceeds_archive_budget");
        const batch = { id: String(sequence).padStart(12, "0"), observations };
        (await this.tx.query("INSERT INTO metadata(key,value) VALUES('archive',$1)", [JSON.stringify(batch)]));
        return batch;
    }
    private async completeArchive(id: string): Promise<boolean> {
        const row = (await this.tx.query<{
            value: string;
        }>("SELECT value FROM metadata WHERE key='archive'"))[0];
        if (!row)
            return false;
        const batch = JSON.parse(row.value) as {
            id: string;
            observations: StoredObservation[];
        };
        if (batch.id !== id)
            return false;
        for (const observation of batch.observations)
            (await this.tx.query("UPDATE observations SET archived=1 WHERE id=$1", [observation.id]));
        (await this.tx.query("DELETE FROM metadata WHERE key='archive'"));
        (await this.tx.query("DELETE FROM outbox WHERE id=$1", [`archive:${this.accountId}`]));
        if ((await this.tx.query("SELECT 1 FROM observations WHERE archived=0 LIMIT 1")).length)
            await this.enqueue(`archive:${this.accountId}`, { kind: "archive", accountId: this.accountId });
        return true;
    }
    private async snapshot(): Promise<EngineSnapshot> {
        const wallet = (await this.tx.query<{
            balance: number;
            reserved: number;
            usage: number;
            missed: number;
        }>("SELECT balance,reserved,usage,missed FROM wallet WHERE id=1"))[0]!;
        const monitors = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM monitors ORDER BY id")).map(row => monitorView(this.secrets.decodeMonitor(row.data)));
        const jobs = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM jobs ORDER BY scheduled_at DESC,id DESC LIMIT 200")).map(row => {
            const { leaseToken: _token, leaseUntil: _lease, ...job } = JSON.parse(row.data) as ExecutionJob;
            return job;
        });
        const notifications = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM notifications ORDER BY next_due DESC LIMIT 200")).map(row => this.notificationView(this.secrets.decodeNotification(row.data)));
        const incidents = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM incidents ORDER BY cursor DESC LIMIT 200")).map(row => JSON.parse(row.data) as Incident);
        const observations = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM observations ORDER BY observed_at DESC LIMIT 200")).map(row => JSON.parse(row.data) as StoredObservation);
        const coverage = (await this.tx.query<{
            monitor_id: string;
            started_at: number;
            ended_at: number | null;
            state: MonitorState;
            name: string | null;
        }>("SELECT coverage.monitor_id,started_at,ended_at,state,COALESCE((monitors.data::jsonb #>> '{name}'),retired_monitors.name,coverage.monitor_id) AS name FROM coverage LEFT JOIN monitors ON monitors.id=coverage.monitor_id LEFT JOIN retired_monitors ON retired_monitors.id=coverage.monitor_id ORDER BY started_at DESC LIMIT 200")).map(row => ({ monitorId: row.monitor_id, monitorName: row.name ?? row.monitor_id, startedAt: row.started_at, endedAt: row.ended_at, state: row.state } satisfies CoverageSegment));
        return { mode: this.env.MODE, creditEnforced: this.env.MODE === "hosted", balance: wallet.balance, reserved: wallet.reserved, usage: wallet.usage, missedSlots: wallet.missed, monitors, jobs, notifications, incidents, observations, coverage };
    }
    private async defaults(): Promise<{
        revision?: number;
        webhook?: MonitorRecord["webhook"];
        email?: MonitorRecord["email"];
    }> {
        const row = (await this.tx.query<{
            value: string;
        }>("SELECT value FROM metadata WHERE key='notification-defaults'"))[0];
        return row ? this.secrets.decodeDefaults(row.value) : {};
    }
    private async defaultsView(): Promise<NotificationDefaultsView> {
        const value = await this.defaults();
        return { revision: value.revision ?? 0, ...(value.webhook ? { webhook: { url: value.webhook.url } } : {}), ...(value.email ? { email: value.email } : {}) };
    }
    private async saveDefaults(input: Record<string, unknown>): Promise<unknown> {
        const previous = await this.defaults();
        if (integer(input.revision, 0, Number.MAX_SAFE_INTEGER, "revision") !== (previous.revision ?? 0))
            throw new ApiError(409, "revision_conflict");
        const values: Record<string, unknown> = { check: { kind: "heartbeat" } };
        for (const field of ["webhook", "email"] as const) {
            const mode = this.mode(input, field);
            if (mode === "replace" && input[field] === undefined)
                throw new ApiError(400, `replacement_${field}_required`);
            values[field] = mode === "keep" ? previous[field] : mode === "replace" ? input[field] : undefined;
        }
        const validated = monitorInput(values, this.env);
        const saved = { revision: (previous.revision ?? 0) + 1, webhook: validated.webhook, email: validated.email };
        (await this.tx.query("INSERT INTO metadata(key,value) VALUES('notification-defaults',$1) ON CONFLICT(account_id,key) DO UPDATE SET value=excluded.value", [this.secrets.encodeDefaults(saved)]));
        return { defaults: await this.defaultsView() };
    }
    private async bulkPaused(input: Record<string, unknown>): Promise<unknown> {
        if (input.action !== "pause" && input.action !== "resume")
            throw new ApiError(400, "invalid_bulk_action");
        if (!Array.isArray(input.monitors) || !input.monitors.length || input.monitors.length > 100)
            throw new ApiError(400, "invalid_bulk_monitors");
        const entries = input.monitors;
        const ids = new Set<string>();
        const selected: { id: string; revision: unknown }[] = [];
        for (const value of entries) {
            const entry = record(value), id = identifier(String(entry.id ?? ""));
            if (ids.has(id))
                throw new ApiError(400, "duplicate_monitor");
            ids.add(id);
            this.revision(await this.monitor(id), entry);
            selected.push({ id, revision: entry.revision });
        }
        const monitors: MonitorView[] = [];
        for (const entry of selected) monitors.push((await this.setPaused(entry.id, input.action === "pause", entry)).monitor);
        return { monitors };
    }
    private async maintenance(): Promise<MaintenanceWindow[]> {
        const now = Date.now();
        return (await this.tx.query<{
            data: string;
        }>("SELECT data FROM maintenance ORDER BY starts_at DESC,id DESC LIMIT 100")).map(row => {
            const value = JSON.parse(row.data) as MaintenanceWindow;
            return { ...value, status: value.status === "cancelled" ? "cancelled" : value.endsAt <= now ? "completed" : value.startsAt <= now ? "active" : "scheduled" };
        });
    }
    private async createMaintenance(input: Record<string, unknown>): Promise<unknown> {
        const now = Date.now(), monitorId = identifier(String(input.monitorId ?? ""));
        this.revision(await this.monitor(monitorId), input);
        const startsAt = integer(input.startsAt, now - 60000, now + 365 * 86400000, "starts_at");
        const endsAt = integer(input.endsAt, Math.max(now + 1, startsAt + 1), startsAt + 30 * 86400000, "ends_at");
        if ((await this.tx.query("SELECT 1 FROM maintenance WHERE monitor_id=$1 AND starts_at<$2 AND ends_at>$3 AND (data::jsonb #>> '{status}')!='cancelled'", [monitorId, endsAt, startsAt])).length)
            throw new ApiError(409, "maintenance_overlap");
        if ((await this.tx.query<{
            count: number;
        }>("SELECT COUNT(*) AS count FROM maintenance WHERE ends_at>$1 AND (data::jsonb #>> '{status}')!='cancelled'", [now]))[0]!.count >= 100)
            throw new ApiError(409, "maintenance_limit");
        const window: MaintenanceWindow = { id: crypto.randomUUID(), monitorId, startsAt, endsAt, reason: text(input.reason, 200, "maintenance_reason"), createdAt: now, status: "scheduled" };
        (await this.tx.query("INSERT INTO maintenance(id,monitor_id,starts_at,ends_at,data) VALUES($1,$2,$3,$4,$5)", [window.id, monitorId, startsAt, endsAt, JSON.stringify(window)]));
        await this.advanceMaintenance(now);
        return { maintenance: window };
    }
    private async cancelMaintenance(id: string, input: Record<string, unknown>): Promise<unknown> {
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM maintenance WHERE id=$1", [id]))[0];
        if (!row)
            throw new ApiError(404, "maintenance_not_found");
        const value = JSON.parse(row.data) as MaintenanceWindow;
        this.revision(await this.monitor(value.monitorId), input);
        value.status = "cancelled";
        (await this.tx.query("UPDATE maintenance SET data=$1 WHERE id=$2", [JSON.stringify(value), id]));
        await this.advanceMaintenance(Date.now());
        return { cancelled: true };
    }
    private async advanceMaintenance(now: number): Promise<void> {
        for (const row of (await this.tx.query<{
            data: string;
        }>("SELECT data FROM monitors"))) {
            const monitor = this.secrets.decodeMonitor(row.data);
            const active = (await this.tx.query<{
                ends_at: number;
            }>("SELECT ends_at FROM maintenance WHERE monitor_id=$1 AND starts_at<=$2 AND ends_at>$3 AND (data::jsonb #>> '{status}')!='cancelled' LIMIT 1", [monitor.id, now, now]))[0];
            if (active && monitor.maintenanceUntil === active.ends_at)
                continue;
            if (!active && !monitor.maintenanceUntil)
                continue;
            monitor.revision++;
            await this.cancelJobs(monitor.id);
            await this.cancelNotifications(monitor.id, "maintenance");
            monitor.candidateJobId = null;
            monitor.candidateSuccess = null;
            monitor.lastObservedAt = null;
            if (active) {
                monitor.maintenanceUntil = active.ends_at;
                monitor.nextDueAt = active.ends_at;
            }
            else {
                delete monitor.maintenanceUntil;
                monitor.heartbeatBlocked = false;
                monitor.nextDueAt = monitor.check.kind === "heartbeat" ? now + monitor.intervalMs + (monitor.check.graceMs ?? 0) : now;
                if (monitor.check.kind === "heartbeat")
                    monitor.heartbeatDeadline = monitor.nextDueAt;
            }
            await this.setState(monitor, monitor.paused ? "PAUSED" : active ? "MAINTENANCE" : "UNKNOWN", now);
            await this.saveMonitor(monitor);
        }
    }
    private async acknowledge(input: Record<string, unknown>, actor: string): Promise<unknown> {
        const id = text(input.incidentId, 1024, "incident_id");
        if (typeof input.acknowledged !== "boolean")
            throw new ApiError(400, "invalid_acknowledged");
        const row = (await this.tx.query<{
            data: string;
        }>("SELECT data FROM incidents WHERE id=$1", [id]))[0];
        if (!row)
            throw new ApiError(404, "incident_not_found");
        const incident = JSON.parse(row.data) as Incident;
        incident.acknowledgedAt = input.acknowledged ? Date.now() : null;
        incident.acknowledgedBy = input.acknowledged ? actor : null;
        (await this.tx.query("UPDATE incidents SET data=$1 WHERE id=$2", [JSON.stringify(incident), id]));
        return { incident };
    }
    private async coveragePage(url: URL): Promise<unknown> {
        const limit = integer(Number(url.searchParams.get("limit") ?? 100), 1, 100, "limit");
        const cursor = integer(Number(url.searchParams.get("cursor") ?? Number.MAX_SAFE_INTEGER), 1, Number.MAX_SAFE_INTEGER, "cursor");
        const monitorId = url.searchParams.get("monitorId");
        if (monitorId)
            identifier(monitorId);
        const rows = (await this.tx.query<{
            cursor: number;
            monitor_id: string;
            started_at: number;
            ended_at: number | null;
            state: MonitorState;
        }>(`SELECT * FROM coverage WHERE cursor<$1${monitorId ? " AND monitor_id=$2" : ""} ORDER BY cursor DESC LIMIT $${monitorId ? 3 : 2}`, [cursor, ...(monitorId ? [monitorId] : []), limit + 1]));
        const items = rows.slice(0, limit);
        return { coverage: items.map(row => ({ monitorId: row.monitor_id, startedAt: row.started_at, endedAt: row.ended_at, state: row.state })), cursor: rows.length > limit ? String(items.at(-1)!.cursor) : null };
    }
    private async report(url: URL): Promise<AvailabilityReport> {
        const now = Date.now(), monitorId = identifier(url.searchParams.get("monitorId") ?? "");
        await this.monitor(monitorId);
        const requestedFrom = integer(Number(url.searchParams.get("from") ?? now - 86400000), 0, Number.MAX_SAFE_INTEGER, "from");
        const requestedTo = integer(Number(url.searchParams.get("to") ?? now), requestedFrom + 1, Number.MAX_SAFE_INTEGER, "to");
        const retainedFrom = Math.max(now - RETENTION_MS, (await this.tx.query<{
            first: number | null;
        }>("SELECT MIN(started_at) AS first FROM coverage WHERE monitor_id=$1", [monitorId]))[0]!.first ?? now);
        const from = Math.max(requestedFrom, retainedFrom), to = Math.min(requestedTo, now);
        if (from >= to)
            throw new ApiError(400, "report_range_unavailable");
        const freshness = (await this.tx.query<{
            observed_at: number;
            fresh_until: number;
        }>("SELECT observed_at,fresh_until FROM freshness WHERE monitor_id=$1 AND observed_at<$2 AND fresh_until>$3 ORDER BY observed_at", [monitorId, to, from]));
        const durationsMs: Record<MonitorState, number> = { UP: 0, DOWN: 0, UNKNOWN: 0, SUSPECT: 0, RECOVERING: 0, PAUSED: 0, MAINTENANCE: 0 };
        let legacyCoverageMs = 0;
        for (const row of (await this.tx.query<{
            started_at: number;
            ended_at: number | null;
            state: MonitorState;
            evidence_mode: string;
        }>("SELECT started_at,ended_at,state,evidence_mode FROM coverage WHERE monitor_id=$1 AND started_at<$2 AND (ended_at IS NULL OR ended_at>$3)", [monitorId, to, from]))) {
            const end = Math.min(to, row.ended_at ?? to), start = Math.max(from, row.started_at);
            const duration = Math.max(0, end - start);
            if (row.state === "DOWN" && row.evidence_mode === "legacy")
                legacyCoverageMs += duration;
            if (["UNKNOWN", "PAUSED", "MAINTENANCE"].includes(row.state) || row.evidence_mode === "heartbeat-deadline" && row.state === "DOWN") {
                durationsMs[row.state] += duration;
            }
            else {
                let coveredUntil = start, observed = 0;
                for (const evidence of freshness) {
                    const evidenceStart = Math.max(start, evidence.observed_at, coveredUntil), evidenceEnd = Math.min(end, evidence.fresh_until);
                    if (evidenceEnd > evidenceStart) {
                        observed += evidenceEnd - evidenceStart;
                        coveredUntil = evidenceEnd;
                    }
                }
                durationsMs[row.state] += observed;
                durationsMs.UNKNOWN += duration - observed;
            }
        }
        const covered = Object.values(durationsMs).reduce((sum, value) => sum + value, 0);
        durationsMs.UNKNOWN += Math.max(0, to - from - covered);
        const observedMs = durationsMs.UP + durationsMs.DOWN + durationsMs.SUSPECT + durationsMs.RECOVERING;
        const samples = (await this.tx.query<{
            latency: number;
        }>("SELECT (data::jsonb #>> '{result,latencyMs}')::double precision AS latency FROM observations WHERE observed_at>=$1 AND observed_at<=$2 AND (data::jsonb #>> '{monitorId}')=$3 AND (data::jsonb #>> '{result,outcome}')!='unknown' ORDER BY latency", [from, to, monitorId])).map(row => row.latency);
        return { monitorId, from, to, requestedFrom, requestedTo, retainedFrom, truncated: from !== requestedFrom || to !== requestedTo, legacyCoverageMs, durationsMs, observedMs, excludedMs: to - from - observedMs, coverageRatio: observedMs / (to - from), uptimeRatio: observedMs ? durationsMs.UP / observedMs : null, latency: { samples: samples.length, averageMs: samples.length ? samples.reduce((sum, value) => sum + value, 0) / samples.length : null, p95Ms: samples.length ? samples[Math.ceil(samples.length * .95) - 1]! : null }, generatedAt: now };
    }
}
export function createAccountService(database: PgDatabase, env: Env) {
    return {
        async fetch(accountId: string, input: Request | string, init?: RequestInit): Promise<Response> {
            const request = input instanceof Request ? input : new Request(input, init);
            try {
                return await database.transaction(accountId, async (tx) => {
                    await tx.query("INSERT INTO wallet(id,balance,reserved,usage,missed,archive_sequence) VALUES(1,0,0,0,0,0) ON CONFLICT DO NOTHING");
                    await tx.query("INSERT INTO metadata(key,value) VALUES('heartbeat-usage','0') ON CONFLICT DO NOTHING");
                    await tx.query("INSERT INTO metadata(key,value) VALUES('engine-mode',$1) ON CONFLICT DO NOTHING", [env.MODE]);
                    const mode = await tx.query<{
                        value: string;
                    }>("SELECT value FROM metadata WHERE key='engine-mode'");
                    if (mode[0]?.value !== env.MODE)
                        throw new ApiError(409, "account_mode_mismatch");
                    return await new AccountEngine(tx, env, accountId).handle(request);
                });
            }
            catch (error) {
                if (error instanceof ApiError)
                    return json({ error: error.message }, error.status);
                throw error;
            }
        }
    };
}
