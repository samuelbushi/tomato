import type { PgDatabase } from "./database";
import type { IdentityService } from "./identity";

export interface Fetcher { fetch(input: Request | string | URL, init?: RequestInit): Promise<Response> }
export interface ProbePolicy {
  allowLoopback: boolean;
  resolverUrl: string;
  egress?: Fetcher;
}
export interface Env {
  database: PgDatabase;
  accounts: { fetch(accountId: string, input: Request | string, init?: RequestInit): Promise<Response> };
  identity: IdentityService;
  PROBER?: Fetcher & { readonly concurrency: number };
  EMAIL?: { send(message: { from: { email: string; name: string }; to: string; subject: string; text: string; headers?: Record<string, string> }): Promise<unknown> };
  EMAIL_FROM?: string;
  AUTH_SECRET: string;
  DATA_KEY: string;
  ASSETS?: Fetcher;
  ENGINE_TOKEN: string;
  MODE: "self-host" | "hosted";
  ARCHIVE_RETENTION_DAYS?: number;
  /** Available only in isolated, locally owned protocol fixtures; never shared production. */
  TEST_MODE?: boolean;
  TEST_MIN_INTERVAL_MS?: string;
  TEST_DNS_RESOLVER?: string;
}
