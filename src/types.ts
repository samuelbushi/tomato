export type Check =
  | { kind: "http"; url: string; method?: "GET" | "HEAD"; headers?: Record<string, string>; status?: number[]; contains?: string; maxBodyBytes?: number; maxRedirects?: number }
  | { kind: "dns"; name: string; recordType: "A" | "AAAA" | "MX" | "TXT" | "NS" | "CNAME"; expected?: string[]; resolverUrl?: string }
  | { kind: "websocket"; url: string; send?: string; expect?: string; maxMessageBytes?: number }
  | { kind: "tcp" | "tls"; hostname: string; port: number; send?: string; expect?: string; maxResponseBytes?: number }
  | { kind: "heartbeat"; graceMs?: number };

export interface MonitorInput {
  id: string;
  name?: string;
  check: Check;
  intervalMs: number;
  paused?: boolean;
  timeoutMs?: number;
  confirmationDelayMs?: number;
  executionWindowMs?: number;
  webhook?: { url: string; secret: string };
  email?: { address: string };
  certificateExpiryDays?: number;
}

export type MonitorState = "UNKNOWN" | "UP" | "SUSPECT" | "DOWN" | "RECOVERING" | "PAUSED" | "MAINTENANCE";
export interface MonitorRecord extends MonitorInput {
  name: string;
  revision: number;
  state: MonitorState;
  paused: boolean;
  nextDueAt: number;
  lastObservedAt: number | null;
  lastSlotAt: number;
  candidateJobId: string | null;
  candidateSuccess: boolean | null;
  incidentId: string | null;
  heartbeatTokenHash?: string;
  heartbeatDeadline?: number;
  heartbeatBlocked?: boolean;
  maintenanceUntil?: number;
  certificate?: { validFrom: number; validTo: number; observedAt: number };
  certificateWarnedFor?: number;
  timeoutMs: number;
  confirmationDelayMs: number;
  executionWindowMs: number;
}

export interface ProbeResult {
  outcome: "success" | "failure" | "unknown";
  code: string;
  startedAt: number;
  finishedAt: number;
  latencyMs: number;
  evidence?: { status?: number; answers?: string[]; bytes?: number; certificate?: { validFrom: number; validTo: number } };
}

export interface CheckJob {
  kind: "check";
  accountId: string;
  jobId: string;
}
export interface NotificationJob {
  kind: "notification";
  accountId: string;
  eventId: string;
}
export interface ArchiveJob { kind: "archive"; accountId: string }
export type EngineMessage = CheckJob | NotificationJob | ArchiveJob;

export interface ExecutionJob {
  id: string;
  monitorId: string;
  revision: number;
  scheduledAt: number;
  expiresAt: number;
  role: "primary" | "confirmation";
  rootJobId: string | null;
  status: "pending" | "running" | "done" | "missed" | "cancelled";
  leaseToken: string | null;
  leaseUntil: number;
  reserved: number;
  enqueuedAt: number;
  manual?: boolean;
}
export interface ClaimedCheck {
  job: ExecutionJob;
  check: Check;
  timeoutMs: number;
  leaseToken: string;
}

export interface Incident {
  id: string;
  monitorId: string;
  monitorName?: string;
  openedAt: number;
  firstFailureAt: number;
  closedAt: number | null;
  acknowledgedAt?: number | null;
  acknowledgedBy?: string | null;
}
export interface NotificationRecord {
  id: string;
  monitorId: string;
  type: "down" | "recovery" | "test" | "certificate";
  incidentId: string | null;
  occurredAt: number;
  url?: string;
  secret?: string;
  channel: "webhook" | "email";
  email?: { address: string };
  monitorName?: string;
  lastError: string | null;
  attemptBase?: number;
  certificate?: { validTo: number; observedAt: number };
  status: "pending" | "sending" | "delivered" | "failed";
  leaseToken: string | null;
  leaseUntil: number;
  attempts: number;
  nextAttemptAt: number;
  deliveredAt: number | null;
}
export interface StoredObservation { id: string; monitorId: string; monitorName?: string; scheduledAt: number; result: ProbeResult }
export type DisplayCheck = Exclude<Check, { kind: "http" }> | (Omit<Extract<Check, { kind: "http" }>, "headers"> & { headerNames: string[]; hasHeaders: boolean });
export interface CertificateView { validFrom: number; validTo: number; observedAt: number; daysRemaining: number; thresholdDays: number; status: "valid" | "expiring" | "expired"; stale: boolean }
export type MonitorView = Omit<MonitorRecord, "check" | "webhook" | "heartbeatTokenHash" | "certificate"> & { check: DisplayCheck; webhook?: { url: string }; effectiveState: MonitorState; freshUntil: number | null; certificate?: CertificateView };
export type NotificationView = Omit<NotificationRecord, "secret" | "leaseToken" | "leaseUntil" | "url" | "email" | "attemptBase">;
export interface CoverageSegment { monitorId: string; monitorName?: string; state: MonitorState; startedAt: number; endedAt: number | null }
export interface EngineSnapshot {
  mode: "self-host" | "hosted";
  creditEnforced: boolean;
  balance: number;
  reserved: number;
  usage: number;
  monitors: MonitorView[];
  jobs: Omit<ExecutionJob, "leaseToken" | "leaseUntil">[];
  incidents: Incident[];
  notifications: NotificationView[];
  observations: StoredObservation[];
  missedSlots: number;
  coverage: CoverageSegment[];
}

