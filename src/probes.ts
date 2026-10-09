import { setTimeout, clearTimeout } from "node:timers";
import ipaddr from "ipaddr.js";
import type { Check, ProbeResult } from "./types";
import type { ProbePolicy } from "./runtime-types";
import { ProbeFault, normalizeHostname, readBoundedBody, validateUrlSyntax } from "./network-policy";

const encoder = new TextEncoder();
const MAX_LITERAL_BYTES = 4096;
const MAX_RESPONSE_BYTES = 262_144;
// Bounded private-RPC admission/response margin; the prober is already running.
export const EGRESS_OVERHEAD_MS = 1_500;

function boundedInteger(value: unknown, fallback: number, minimum: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new ProbeFault("invalid_check_bounds");
  }
  return value;
}

function boundedLiteral(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_LITERAL_BYTES || encoder.encode(value).byteLength > MAX_LITERAL_BYTES) {
    throw new ProbeFault("invalid_check_literal");
  }
  return value;
}

function dnsName(value: unknown): string {
  if (typeof value !== "string" || value.length > 253 || !value) throw new ProbeFault("invalid_dns_name");
  const name = value.toLowerCase().replace(/\.$/, "");
  if (!name.split(".").every(label => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label))) {
    throw new ProbeFault("invalid_dns_name");
  }
  return name;
}

function canonicalDnsValue(type: Extract<Check, { kind: "dns" }>["recordType"], value: string): string {
  switch (type) {
    case "A": case "AAAA": {
      if (!ipaddr.isValid(value)) throw new ProbeFault("invalid_dns_answer");
      const address = ipaddr.parse(value);
      if (address.kind() !== (type === "A" ? "ipv4" : "ipv6")) throw new ProbeFault("invalid_dns_answer");
      return address.toString();
    }
    case "NS": case "CNAME": return dnsName(value);
    case "MX": {
      const match = /^(\d{1,5})\s+(\S+)$/.exec(value);
      if (!match || Number(match[1]) > 65535) throw new ProbeFault("invalid_dns_answer");
      return `${Number(match[1])} ${dnsName(match[2])}`;
    }
    case "TXT": return value;
  }
}

export function validateCheck(value: unknown, policy: ProbePolicy): Check {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ProbeFault("invalid_check");
  const input = value as Record<string, unknown>;
  const fields: Record<string, readonly string[]> = {
    http: ["kind", "url", "method", "headers", "status", "contains", "maxBodyBytes", "maxRedirects"],
    dns: ["kind", "name", "recordType", "expected", "resolverUrl"],
    websocket: ["kind", "url", "send", "expect", "maxMessageBytes"],
    tcp: ["kind", "hostname", "port", "send", "expect", "maxResponseBytes"],
    tls: ["kind", "hostname", "port", "send", "expect", "maxResponseBytes"],
    heartbeat: ["kind", "graceMs"],
  };
  if (typeof input.kind !== "string" || !Object.hasOwn(fields, input.kind) ||
      Object.keys(input).some(key => !fields[input.kind as string]!.includes(key))) throw new ProbeFault("invalid_check");
  switch (input.kind) {
    case "http": {
      const url = validateUrlSyntax(input.url, policy).href;
      if (input.method !== undefined && input.method !== "GET" && input.method !== "HEAD") throw new ProbeFault("invalid_http_method");
      const method = input.method === "HEAD" ? "HEAD" : "GET";
      let headers: Record<string, string> | undefined;
      if (input.headers !== undefined) {
        if (!input.headers || typeof input.headers !== "object" || Array.isArray(input.headers)) throw new ProbeFault("invalid_http_headers");
        headers = Object.create(null) as Record<string, string>;
        let bytes = 0;
        const entries = Object.entries(input.headers);
        if (entries.length > 32) throw new ProbeFault("invalid_http_headers");
        for (const [name, value] of entries) {
          if (name.length > 128 || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
              typeof value !== "string" || value.length > 8192 || /[^\t\x20-\x7e\x80-\xff]/.test(value) ||
              /^(?:host|connection|upgrade|content-length|transfer-encoding|proxy-.*|sec-.*|trailer|te|keep-alive)$/i.test(name)) {
            throw new ProbeFault("invalid_http_headers");
          }
          bytes += encoder.encode(name + value).byteLength;
          if (bytes > 8192 || Object.hasOwn(headers, name.toLowerCase())) throw new ProbeFault("invalid_http_headers");
          headers[name.toLowerCase()] = value;
        }
      }
      let status: number[] | undefined;
      if (input.status !== undefined) {
        if (!Array.isArray(input.status) || !input.status.length || input.status.length > 100 ||
            input.status.some(code => !Number.isInteger(code) || code < 100 || code > 599)) throw new ProbeFault("invalid_http_status");
        status = [...new Set(input.status as number[])].sort((a, b) => a - b);
      }
      const contains = boundedLiteral(input.contains);
      const maxBodyBytes = boundedInteger(input.maxBodyBytes, 65_536, 1, MAX_RESPONSE_BYTES);
      if (contains !== undefined && (method === "HEAD" || encoder.encode(contains).byteLength > maxBodyBytes)) throw new ProbeFault("invalid_http_content");
      return { kind: "http", url, method, headers, status, contains, maxBodyBytes,
        maxRedirects: boundedInteger(input.maxRedirects, 3, 0, 5) };
    }
    case "dns": {
      const types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"] as const;
      if (!types.includes(input.recordType as typeof types[number])) throw new ProbeFault("invalid_dns_type");
      const recordType = input.recordType as typeof types[number];
      if (input.resolverUrl !== undefined && input.resolverUrl !== policy.resolverUrl) throw new ProbeFault("untrusted_resolver");
      let expected: string[] | undefined;
      if (input.expected !== undefined) {
        if (!Array.isArray(input.expected) || input.expected.length > 32 || input.expected.some(answer =>
          typeof answer !== "string" || answer.length > 1024 || encoder.encode(answer).byteLength > 1024)) throw new ProbeFault("invalid_dns_expected");
        expected = [...new Set((input.expected as string[]).map(answer => canonicalDnsValue(recordType, answer)))].sort();
      }
      return { kind: "dns", name: dnsName(input.name), recordType, expected };
    }
    case "websocket": {
      const maxMessageBytes = boundedInteger(input.maxMessageBytes, 16_384, 1, 65_536);
      const send = boundedLiteral(input.send), expect = boundedLiteral(input.expect);
      if ((send !== undefined && encoder.encode(send).byteLength > maxMessageBytes) ||
          (expect !== undefined && encoder.encode(expect).byteLength > maxMessageBytes)) throw new ProbeFault("invalid_websocket_message");
      return { kind: "websocket", url: validateUrlSyntax(input.url, policy, true).href, send, expect, maxMessageBytes };
    }
    case "tcp": case "tls": {
      if (input.port === undefined) throw new ProbeFault("invalid_check_bounds");
      const send = boundedLiteral(input.send), expect = boundedLiteral(input.expect);
      const maxResponseBytes = boundedInteger(input.maxResponseBytes, 16_384, 1, 65_536);
      if (expect !== undefined && encoder.encode(expect).byteLength > maxResponseBytes) throw new ProbeFault("invalid_socket_message");
      return { kind: input.kind, hostname: normalizeHostname(input.hostname, policy),
        port: boundedInteger(input.port, 0, 1, 65535), send, expect, maxResponseBytes };
    }
    case "heartbeat":
      return { kind: "heartbeat", graceMs: input.graceMs === undefined ? undefined : boundedInteger(input.graceMs, 60_000, 0, 604_800_000) };
    default: throw new ProbeFault("invalid_check");
  }
}

async function callEgress(input: unknown, policy: ProbePolicy, signal: AbortSignal): Promise<Record<string, unknown>> {
  if (!policy.egress) throw new ProbeFault("egress_not_configured");
  const body = JSON.stringify(input);
  if (encoder.encode(body).byteLength > 65_536) throw new ProbeFault("request_too_large");
  let response: Response;
  try {
    response = await policy.egress.fetch("https://tomato-egress.internal/execute", {
      method: "POST", headers: { "Content-Type": "application/json" }, body, signal,
    });
  } catch { throw new ProbeFault("egress_unavailable"); }
  if (response.status !== 200) {
    await response.body?.cancel().catch(() => {});
    throw new ProbeFault(response.status === 429 ? "egress_overloaded" : "egress_unavailable");
  }
  try {
    const data: unknown = JSON.parse(new TextDecoder().decode(await readBoundedBody(response, 65536, signal)));
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error();
    const result = data as Record<string, unknown>;
    if (typeof result.code !== "string" || !/^[a-z_]{1,64}$/.test(result.code)) throw new Error();
    return result;
  } catch { throw new ProbeFault("egress_invalid_response"); }
}

async function egressProbe(check: Check, timeoutMs: number, policy: ProbePolicy, signal: AbortSignal):
  Promise<Pick<ProbeResult, "code" | "evidence" | "outcome">> {
  const result = await callEgress({ kind: "probe", check, timeoutMs }, policy, signal);
  if (!["success", "failure", "unknown"].includes(String(result.outcome))) throw new ProbeFault("egress_invalid_response");
  let evidence: ProbeResult["evidence"];
  if (result.evidence !== undefined) {
    if (!result.evidence || typeof result.evidence !== "object" || Array.isArray(result.evidence)) throw new ProbeFault("egress_invalid_response");
    const raw = result.evidence as Record<string, unknown>;
    if (Object.keys(raw).some(key => key !== "status" && key !== "bytes" && key !== "certificate" && key !== "answers") ||
        (raw.status !== undefined && (!Number.isInteger(raw.status) || Number(raw.status) < 100 || Number(raw.status) > 599)) ||
        (raw.bytes !== undefined && (!Number.isSafeInteger(raw.bytes) || Number(raw.bytes) < 0 || Number(raw.bytes) > MAX_RESPONSE_BYTES))) {
      throw new ProbeFault("egress_invalid_response");
    }
    evidence = { status: raw.status as number | undefined, bytes: raw.bytes as number | undefined };
    if (raw.answers !== undefined) {
      if (check.kind !== "dns" || !Array.isArray(raw.answers) || raw.answers.length > 32 || raw.answers.some(answer => typeof answer !== "string" || encoder.encode(answer).byteLength > 1024)) throw new ProbeFault("egress_invalid_response");
      evidence.answers = raw.answers as string[];
    }
    if (raw.certificate !== undefined) {
      if (!raw.certificate || typeof raw.certificate !== "object" || Array.isArray(raw.certificate)) {
        throw new ProbeFault("egress_invalid_response");
      }
      const certificate = raw.certificate as Record<string, unknown>;
      if (Object.keys(certificate).some(key => key !== "validFrom" && key !== "validTo") ||
          ![certificate.validFrom, certificate.validTo].every(value =>
            typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 8_640_000_000_000_000) ||
          Number(certificate.validFrom) > Number(certificate.validTo) ||
          !(check.kind === "tls" || check.kind === "http")) {
        throw new ProbeFault("egress_invalid_response");
      }
      evidence.certificate = { validFrom: certificate.validFrom as number, validTo: certificate.validTo as number };
    }
  }
  return { outcome: result.outcome as ProbeResult["outcome"], code: result.code as string, evidence };
}

/** Signed payload is created by the engine; neither transport exposes response bodies. */
export async function dispatchWebhook(url: string, payload: string, headers: Record<string, string>,
  timeoutMs: number, policy: ProbePolicy): Promise<{ status: number; code: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs + (policy.egress ? EGRESS_OVERHEAD_MS : 0));
  try {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000 ||
        encoder.encode(payload).byteLength > 16_384) throw new ProbeFault("invalid_request");
    const target = validateUrlSyntax(url, policy);
    const result = await callEgress({ kind: "webhook", url: target.href, payload, headers, timeoutMs }, policy, controller.signal);
    if (!Number.isInteger(result.status) || Number(result.status) < 0 || Number(result.status) > 599) throw new ProbeFault("egress_invalid_response");
    return { status: result.status as number, code: result.code as string };
  } catch (error) {
    return { status: 0, code: error instanceof ProbeFault ? error.code : "egress_unavailable" };
  } finally { clearTimeout(timer); controller.abort(); }
}

export async function runProbe(check: Exclude<Check, { kind: "heartbeat" }>, timeoutMs: number, policy: ProbePolicy): Promise<ProbeResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  let observation: Pick<ProbeResult, "outcome" | "code" | "evidence">;
  try {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) throw new ProbeFault("invalid_timeout");
    const checked = validateCheck(check, policy);
    if (checked.kind === "heartbeat") throw new ProbeFault("invalid_probe_kind");
    const deadline = Promise.withResolvers<never>();
    timer = setTimeout(() => {
      const error = new ProbeFault("timeout", "unknown");
      controller.abort(error); deadline.reject(error);
    }, timeoutMs + (policy.egress ? EGRESS_OVERHEAD_MS : 0));
    const operation = egressProbe(checked, timeoutMs, policy, controller.signal);
    observation = await Promise.race([operation, deadline.promise]);
  } catch (error) {
    observation = error instanceof ProbeFault ?
      { outcome: error.outcome,
        code: error.code === "destination_disallowed" ? "blocked_destination" : error.code } :
      { outcome: "unknown", code: "internal_error" };
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
  const finishedAt = Date.now();
  return { ...observation, startedAt, finishedAt, latencyMs: Math.max(0, finishedAt - startedAt) };
}
