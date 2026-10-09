import { ApiError, record } from "./validation";
import { executeManagement } from "./management";
import type { Env } from "./runtime-types";
import type { Principal } from "./product-types";

export async function accountManagement<T>(env: Env, actor: Principal, path: string, method: string, input: unknown, origin: string): Promise<T> {
  const url = new URL(`https://management.internal${path}`), suffix = url.pathname;
  const args: Record<string, unknown> = { ...(input === undefined ? {} : record(input)), accountId: actor.account!.id };
  let name: string | undefined;
  delete args.csrfToken;
  if (method === "GET") {
    const reads: Record<string, string> = { "/state": "state.get", "/usage": "usage.get", "/monitors": "monitors.list", "/history": "history.list", "/incidents": "incidents.list", "/notifications": "notifications.list", "/coverage": "coverage.list", "/reports": "report.get", "/export": "monitors.export", "/status-page": "status_page.get", "/notification-defaults": "notification_defaults.get", "/maintenance": "maintenance.list" };
    name = reads[suffix];
    for (const [key, value] of url.searchParams) args[key] = ["limit", "from", "to"].includes(key) ? Number(value) : value;
  }
  if (suffix === "/monitors" && method === "POST") name = "monitor.create";
  if (suffix === "/monitors/import" && method === "POST") name = "monitors.import";
  if (suffix === "/monitors/bulk" && method === "POST") name = "monitors.bulk";
  if (suffix === "/notifications/retry" && method === "POST") name = "notification.retry";
  if (suffix === "/notification-defaults" && method === "PUT") name = "notification_defaults.set";
  if (suffix === "/maintenance" && method === "POST") name = "maintenance.create";
  const window = suffix.match(/^\/maintenance\/([A-Za-z0-9_-]{1,64})$/);
  if (window && method === "DELETE") { name = "maintenance.cancel"; args.maintenanceId = window[1]; }
  if (suffix === "/incidents/acknowledgement" && method === "POST") { name = args.acknowledged ? "incident.acknowledge" : "incident.unacknowledge"; delete args.acknowledged; }
  const monitor = suffix.match(/^\/monitors\/([A-Za-z0-9_-]{1,64})(?:\/(pause|resume|heartbeat-token|notification-test|check-now))?$/);
  if (monitor && !name) {
    args.monitorId = monitor[1];
    name = monitor[2] === "check-now" ? "monitor.check_now" : monitor[2] === "heartbeat-token" ? "monitor.heartbeat_token_rotate" : monitor[2] === "notification-test" ? "notification.test" : monitor[2] ? `monitor.${monitor[2]}` : method === "GET" ? "monitor.get" : method === "PUT" ? "monitor.update" : method === "DELETE" ? "monitor.delete" : undefined;
    if (name === "monitor.update") delete args.id;
  }
  if (suffix === "/status-page") name = method === "GET" ? "status_page.get" : method === "PUT" ? "status_page.configure" : method === "DELETE" ? "status_page.unpublish" : undefined;
  if (suffix === "/status-page/updates") { name = method === "POST" ? "status_update.create" : method === "DELETE" ? "status_update.remove" : undefined; if (method === "DELETE") { args.updateId = args.id; delete args.id; } }
  if (!name) throw new ApiError(404, "not_found");
  // The finite service validates the complete external argument shape and all authorization.
  const result = await executeManagement(env, actor, `tomato.${name}`, args, origin);
  // T is the existing, redacted product DTO chosen by a fixed caller, never a user-selected route.
  return result as T;
}
