export class NativeClient {
  readonly cookies = new Map<string, string>();
  constructor(readonly origin: string) {}
  async request(route: string, options: { method?: string; form?: URLSearchParams; json?: unknown; expected?: number; origin?: string; csrf?: string } = {}): Promise<{ response: Response; text: string }> {
    const method = options.method ?? (options.form || options.json ? "POST" : "GET");
    const headers: Record<string, string> = {};
    if (this.cookies.size) headers.Cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
    if (method !== "GET") headers.Origin = options.origin ?? this.origin;
    if (options.csrf) headers["X-CSRF-Token"] = options.csrf;
    if (options.form) headers["Content-Type"] = "application/x-www-form-urlencoded";
    if (options.json) headers["Content-Type"] = "application/json";
    const response = await fetch(new URL(route, this.origin), { method, headers, redirect: "manual", ...(options.form ? { body: options.form.toString() } : options.json ? { body: JSON.stringify(options.json) } : {}) });
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(";");
      const split = pair!.indexOf("=");
      const name = pair!.slice(0, split), value = pair!.slice(split + 1);
      if (value) this.cookies.set(name, value); else this.cookies.delete(name);
    }
    if (options.expected !== undefined && response.status !== options.expected) throw new Error(`Native ${method} ${route.split("?")[0]} returned HTTP${response.status}, expected HTTP${options.expected}; response content is not printed.`);
    return { response, text: await response.text() };
  }
  async login(email: string, password: string): Promise<void> {
    const page = await this.request("/login", { expected: 200 });
    const csrfToken = htmlCsrf(page.text);
    await this.request("/login", { form: new URLSearchParams({ csrfToken, email, password }), expected: 303 });
    await this.request("/app", { expected: 303 });
  }
}

export function htmlCsrf(html: string): string {
  const token = html.match(/<input\b[^>]*name="csrfToken"[^>]*value="([^"]+)"/);
  if (!token) throw new Error("Rendered native form is missing its CSRF token.");
  return token[1]!;
}
