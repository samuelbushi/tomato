import { SecretCodec } from "./secrets";
import type { MonitorRecord, NotificationRecord } from "./types";

type Defaults = {revision?:number; webhook?:MonitorRecord["webhook"]; email?:MonitorRecord["email"]};

/** Storage encoding never changes the live domain DTO; secrets are opened only
 * inside the trusted app before redaction or authenticated prober dispatch.
 */
export class AccountSecrets {
  private readonly codec: SecretCodec;
  constructor(key: string, private readonly accountId: string) { this.codec = new SecretCodec(key); }
  encodeMonitor(monitor: MonitorRecord): string {
    const stored = { ...monitor };
    if (monitor.check.kind === "http" && monitor.check.headers) {
      stored.check = { ...monitor.check, headers: { "x-tomato-sealed": this.codec.seal(JSON.stringify(monitor.check.headers), `${this.accountId}:monitor:${monitor.id}:headers`) } };
    }
    if (monitor.webhook) stored.webhook = { ...monitor.webhook, secret: this.codec.seal(monitor.webhook.secret, `${this.accountId}:monitor:${monitor.id}:webhook`) };
    return JSON.stringify(stored);
  }
  decodeMonitor(data: string): MonitorRecord {
    const monitor = JSON.parse(data) as MonitorRecord;
    if (monitor.check.kind === "http" && monitor.check.headers) {
      const envelope = monitor.check.headers;
      if (Object.keys(envelope).length !== 1 || typeof envelope["x-tomato-sealed"] !== "string") throw new Error("unencrypted_monitor_headers");
      monitor.check.headers = JSON.parse(this.codec.open(envelope["x-tomato-sealed"], `${this.accountId}:monitor:${monitor.id}:headers`)) as Record<string,string>;
    }
    if (monitor.webhook) monitor.webhook.secret = this.codec.open(monitor.webhook.secret, `${this.accountId}:monitor:${monitor.id}:webhook`);
    return monitor;
  }
  encodeNotification(notification: NotificationRecord): string {
    return JSON.stringify({ ...notification, ...(notification.secret ? { secret: this.codec.seal(notification.secret, `${this.accountId}:notification:${notification.id}:webhook`) } : {}) });
  }
  decodeNotification(data: string): NotificationRecord {
    const notification = JSON.parse(data) as NotificationRecord;
    if (notification.secret) notification.secret = this.codec.open(notification.secret, `${this.accountId}:notification:${notification.id}:webhook`);
    return notification;
  }
  encodeDefaults(defaults: Defaults): string {
    return JSON.stringify({ ...defaults, ...(defaults.webhook ? { webhook: { ...defaults.webhook, secret: this.codec.seal(defaults.webhook.secret, `${this.accountId}:defaults:webhook`) } } : {}) });
  }
  decodeDefaults(data: string): Defaults {
    const defaults = JSON.parse(data) as Defaults;
    if (defaults.webhook) defaults.webhook.secret = this.codec.open(defaults.webhook.secret, `${this.accountId}:defaults:webhook`);
    return defaults;
  }
}
