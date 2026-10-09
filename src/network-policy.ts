import ipaddr from "ipaddr.js";
import type { ProbePolicy } from "./runtime-types";

export class ProbeFault extends Error {
  constructor(readonly code: string, readonly outcome: "failure" | "unknown" = "unknown") {
    super(code);
    this.name = "ProbeFault";
  }
}

export function literalAddress(hostname: string): string | null {
  const host = hostname.replace(/^\[|\]$/g, "");
  if (host.includes("%")) throw new ProbeFault("destination_disallowed");
  if (!ipaddr.isValid(host)) return null;
  return ipaddr.process(host).toString();
}

const blockedV4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"].map(value => ipaddr.parseCIDR(value));
const blockedV6 = ["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"].map(value => ipaddr.parseCIDR(value));

export function assertAllowedAddress(address: string, policy: ProbePolicy): string {
  if (!ipaddr.isValid(address) || address.includes("%")) throw new ProbeFault("destination_disallowed");
  const parsed = ipaddr.process(address);
  const range = parsed.range();
  // Mapped IPv6 is first converted to IPv4. Transition/tunnel ranges are not public destinations.
  if (range !== "unicast" && !(policy.allowLoopback && range === "loopback")) {
    throw new ProbeFault("destination_disallowed");
  }
  // ipaddr's unicast fallback includes IPv6 space not currently globally allocated.
  if (parsed.kind() === "ipv6" && range === "unicast" && !parsed.match(ipaddr.parse("2000::"), 3)) {
    throw new ProbeFault("destination_disallowed");
  }
  if (!(policy.allowLoopback && range === "loopback") &&
      (parsed.kind() === "ipv4" ? blockedV4.some(block => parsed.match(block)) : blockedV6.some(block => parsed.match(block)))) {
    throw new ProbeFault("destination_disallowed");
  }
  return parsed.toString();
}

export function normalizeHostname(value: unknown, policy: ProbePolicy): string {
  if (typeof value !== "string" || !value || value.length > 253 || /[\s/@?#\\%]/.test(value)) {
    throw new ProbeFault("invalid_hostname");
  }
  const literal = literalAddress(value);
  if (literal) return assertAllowedAddress(literal, policy);
  const name = value.toLowerCase().replace(/\.$/, "");
  if (!name.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new ProbeFault("invalid_hostname");
  }
  if (name === "localhost") {
    if (!policy.allowLoopback) throw new ProbeFault("destination_disallowed");
    return name;
  }
  if (!name.includes(".") || /(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|onion)$/.test(name) ||
      name === "metadata.google.internal" || name === "instance-data.ec2.internal") {
    throw new ProbeFault("destination_disallowed");
  }
  return name;
}

export function validateUrlSyntax(value: unknown, policy: ProbePolicy, websocket = false): URL {
  if (typeof value !== "string" || value.length > 4096 || /[\u0000-\u0020\u007f\\]/.test(value)) {
    throw new ProbeFault("invalid_url");
  }
  let url: URL;
  try { url = new URL(value); } catch { throw new ProbeFault("invalid_url"); }
  const schemes = websocket ? ["ws:", "wss:"] : ["http:", "https:"];
  if (!schemes.includes(url.protocol) || url.username || url.password || url.hash || !url.hostname ||
      (url.port && (Number(url.port) < 1 || Number(url.port) > 65535))) throw new ProbeFault("invalid_url");
  normalizeHostname(url.hostname, policy);
  return url;
}

export async function readBoundedBody(response: Response, limit: number, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  const declared = response.headers.get("content-length");
  if (declared && /^\d+$/.test(declared) && Number(declared) > limit) {
    await response.body?.cancel().catch(() => {});
    throw new ProbeFault("response_too_large", "failure");
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", abort, { once: true });
  try {
    while (true) {
      signal.throwIfAborted();
      const { value, done } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new ProbeFault("response_too_large", "failure");
      chunks.push(value);
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    return body;
  } finally {
    signal.removeEventListener("abort", abort);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

