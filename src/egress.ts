import { readBoundedBody } from "./network-policy";

export interface ProberService {
  fetch(input: Request | string | URL, init?: RequestInit): Promise<Response>;
  ready(): Promise<boolean>;
  readonly concurrency: number;
}

/** Fixed private RPC boundary; never forwards browser headers or credentials. */
export function createProber(endpoint: string, token: string): ProberService {
  const destination = new URL(endpoint);
  if (destination.protocol !== "http:" || destination.username || destination.password || destination.pathname !== "/execute" || destination.search || destination.hash || token.length < 32) {
    throw new Error("invalid_prober_configuration");
  }
  let active = 0;
  return {
    concurrency: 4,
    async fetch(input: Request | string | URL, init?: RequestInit): Promise<Response> {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (request.method !== "POST" || url.hostname !== "tomato-egress.internal" || url.pathname !== "/execute" || url.search || request.headers.get("content-type") !== "application/json") {
        return Response.json({ code: "invalid_request" }, { status: 400 });
      }
      if (active >= 4) return Response.json({ code: "egress_overloaded" }, { status: 429 });
      active++;
      const controller = new AbortController();
      let timer = setTimeout(() => controller.abort(), 5000);
      try {
        const body = await readBoundedBody(new Response(request.body), 65_536, controller.signal);
        const value = JSON.parse(new TextDecoder().decode(body)) as { timeoutMs?: unknown };
        if (!value || !Number.isSafeInteger(value.timeoutMs) || Number(value.timeoutMs) < 100 || Number(value.timeoutMs) > 30_000) return Response.json({ code: "invalid_request" }, { status: 400 });
        clearTimeout(timer);
        timer = setTimeout(() => controller.abort(), Number(value.timeoutMs) + 1500);
        const response = await fetch(destination, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body, signal: controller.signal, redirect: "error" });
        const result = await readBoundedBody(response, 65_536, controller.signal);
        return new Response(result, { status: response.status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
      } catch {
        return Response.json({ code: "egress_unavailable" }, { status: 503 });
      } finally { clearTimeout(timer); controller.abort(); active--; }
    },
    async ready(): Promise<boolean> {
      try {
        const response = await fetch(new URL("/ready", destination), { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(2000), redirect: "error" });
        return response.ok;
      } catch { return false; }
    },
  };
}
