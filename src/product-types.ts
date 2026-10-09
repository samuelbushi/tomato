import type { Check, MonitorState, Incident, StoredObservation, CoverageSegment, CertificateView } from "./types";

export type AccountRole = "owner" | "editor" | "viewer";
export type ApiKeyScope = "read" | "write" | "manage";
export interface MaintenanceWindow {
  id: string; monitorId: string; startsAt: number; endsAt: number; reason: string; createdAt: number;
  status: "scheduled" | "active" | "completed" | "cancelled";
}
export interface NotificationDefaultsView { revision: number; webhook?: { url: string }; email?: { address: string } }
export interface AvailabilityReport {
  monitorId: string; from: number; to: number; durationsMs: Record<MonitorState, number>;
  observedMs: number; excludedMs: number; coverageRatio: number; uptimeRatio: number | null;
  latency: { samples: number; averageMs: number | null; p95Ms: number | null }; generatedAt: number;
  requestedFrom?: number; requestedTo?: number; truncated?: boolean; retainedFrom?: number;
  legacyCoverageMs: number;
}
export interface ReadinessView {
  releaseMode: "self-host" | "hosted"; commercialSignup: false; payments: false; emailConfigured: boolean;
  signupEnabled: boolean; oauth: { github: boolean; google: boolean }; creditEnforced: boolean;
  limits: { minimumIntervalMs: number; maxMonitors: number; proberConcurrency: number | null; sqlHistoryDays: number };
  confirmation: "temporal"; geographicCoverage: "not-guaranteed"; capacity: "unmeasured";
  agent: { endpoint: string; transport: "streamable-http"; protocolVersions: string[] };
  blockers: string[];
}
export interface Actor { id: string; username: string }
export interface AccountSummary { id: string; name: string; role: AccountRole }
export interface Principal {
  actor: Actor; accounts: AccountSummary[]; account: AccountSummary | null;
  sessionId: string | null; csrfToken: string; apiKeyId: string | null; scope: ApiKeyScope; apiKeyExpiresAt?: number | null;
}
export type DisplayCheck = Exclude<Check, { kind: "http" }> | (Omit<Extract<Check, { kind: "http" }>, "headers"> & { headerNames: string[]; hasHeaders: boolean });
export interface DisplayMonitor {
  id: string; name: string; check: DisplayCheck; revision: number; state: MonitorState;
  effectiveState: MonitorState; paused: boolean; intervalMs: number; timeoutMs: number;
  confirmationDelayMs: number; executionWindowMs: number; nextDueAt: number;
  lastObservedAt: number | null; freshUntil: number | null; incidentId: string | null;
  webhook?: { url: string }; heartbeatDeadline?: number; email?: { address: string };
  certificateExpiryDays?: number;
  certificate?: CertificateView;
  maintenanceUntil?: number;
  heartbeatBlocked?: boolean;
}
export interface DeliveryView {
  id: string; monitorId: string; type: "down" | "recovery" | "test" | "certificate"; incidentId: string | null;
  status: "pending" | "sending" | "delivered" | "failed"; attempts: number; nextAttemptAt: number;
  deliveredAt: number | null; lastError: string | null; channel: "webhook" | "email";
  occurredAt?: number;
}
export interface CreditGrant { id: string; credits: number; reason: string; createdAt: number }
export interface WalletView {
  mode: "self-host" | "hosted"; creditEnforced: boolean;
  balance: number; reserved: number; available: number; usage: number; missedSlots: number;
  forecastChecksPerDay: number; estimatedDepletionAt: number | null;
  creditSource: "self-host" | "hosted-ledger"; grants: CreditGrant[];
  heartbeatCreditsUsed?: number; heartbeatReceipts?: number;
}
export interface PublicIncidentUpdate { id: string; incidentId: string; body: string; publishedAt: number }
export interface PublicPageConfig {
  revision: number;
  slug: string; title: string; published: boolean; components: { monitorId: string; label: string }[];
  updatedAt: number; updates: PublicIncidentUpdate[];
}
export interface PublicStatusView {
  slug: string; title: string; generatedAt: number; updatedAt: number;
  components: { label: string; state: MonitorState; lastObservedAt: number | null; freshUntil: number | null }[];
  incidents: { componentLabel: string; openedAt: number; closedAt: number | null; updates: { body: string; publishedAt: number }[] }[];
}
export interface MemberView { userId: string; username: string; role: AccountRole }
export interface InvitationView {
  id: string; username: string; role: AccountRole; createdAt: number; expiresAt: number;
  status: "pending" | "accepted" | "revoked" | "expired";
}
export interface SessionView { id: string; createdAt: number; expiresAt: number; current: boolean }
export interface ApiKeyView { id: string; name: string; scope: ApiKeyScope; createdAt: number; expiresAt: number; lastUsedAt: number | null; parentKeyId?: string | null }
export interface AuditView { id: string; actor: string; action: string; subject: string; occurredAt: number; apiKeyId?: string | null }
export interface AuthenticatedView {
  actor: Actor; accounts: AccountSummary[]; account: AccountSummary; csrfToken: string;
  generatedAt: number; emailConfigured: boolean; error?: string; notice?: string;
  origin?: string; mode?: "self-host" | "hosted";
}
export type UiPage =
  | { kind: "landing" }
  | { kind: "login"; csrfToken: string; error?: string; notice?: string; pilotOnly: true; mode?: "signup" | "forgot" | "reset" | "verify"; resetToken?: string; next?: string; signup?: boolean; email?: boolean; github?: boolean; google?: boolean }
  | { kind: "accounts"; actor: Actor; accounts: AccountSummary[]; csrfToken: string; error?: string }
  | (AuthenticatedView & { kind: "dashboard"; monitors: DisplayMonitor[]; wallet: WalletView; incidents: Incident[]; deliveries: DeliveryView[]; readiness?: ReadinessView; notificationDefaults?: NotificationDefaultsView })
  | (AuthenticatedView & { kind: "monitor-edit"; monitor: DisplayMonitor | null; entered?: Record<string, string>; notificationDefaults?: NotificationDefaultsView })
  | (AuthenticatedView & { kind: "monitor"; monitor: DisplayMonitor; observations: StoredObservation[]; incidents: Incident[]; deliveries: DeliveryView[]; coverage: CoverageSegment[]; maintenance?: MaintenanceWindow[]; report?: AvailabilityReport })
  | (AuthenticatedView & { kind: "reports"; report: AvailabilityReport; monitors: DisplayMonitor[] })
  | (AuthenticatedView & { kind: "heartbeat-token"; monitor: DisplayMonitor; heartbeatToken: string; heartbeatUrl: string })
  | (AuthenticatedView & { kind: "wallet"; wallet: WalletView })
  | (AuthenticatedView & { kind: "notifications"; deliveries: DeliveryView[]; monitors: DisplayMonitor[] })
  | (AuthenticatedView & { kind: "status-page-edit"; page: PublicPageConfig | null; pageRevision?: number; monitors: DisplayMonitor[]; incidents: Incident[] })
  | (AuthenticatedView & { kind: "settings"; sessions: SessionView[]; emailConfigured: boolean; notificationDefaults?: NotificationDefaultsView; readiness?: ReadinessView })
  | (AuthenticatedView & { kind: "team"; members: MemberView[]; invitations: InvitationView[] })
  | (AuthenticatedView & { kind: "invitation-reveal"; invitation: InvitationView; invitationUrl: string })
  | (AuthenticatedView & { kind: "api-keys"; keys: ApiKeyView[] })
  | (AuthenticatedView & { kind: "api-key-reveal"; key: ApiKeyView; apiKey: string })
  | (AuthenticatedView & { kind: "import-export"; importedCount?: number; importedHeartbeats?: { monitorId: string; name: string; token: string; url: string }[] })
  | (AuthenticatedView & { kind: "api-docs"; origin: string; tools?: { name: string; description: string }[] })
  | (AuthenticatedView & { kind: "audit"; entries: AuditView[] })
  | { kind: "invite"; invitationToken: string; accountName: string; username: string; role: AccountRole; expiresAt: number; existingUser: boolean; signedIn?: boolean; csrfToken: string; error?: string }
  | { kind: "public-status"; page: PublicStatusView }
  | { kind: "error"; status: number; error: string };
