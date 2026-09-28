import type { HangarConfig } from "./types.js";

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

const TIMEOUT_MS = 2000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const POSITIVE_TTL_MS = 10 * 60_000;
const NEGATIVE_TTL_MS = 60_000;
const MAX_ENTRIES = 1000;
const LOG_INTERVAL_MS = 60_000;
const EMAIL = /^[^\s@<>"]{1,128}@[^\s@<>".]+(?:\.[^\s@<>".]+)+$/;

export type UserinfoFailure =
  | "timeout"
  | "network"
  | "http_status"
  | "too_large"
  | "invalid_json"
  | "subject_mismatch"
  | "no_email";

export interface UserinfoDependencies {
  readonly fetch?: FetchLike;
  readonly now?: () => number;
  /** One line per failure class per minute; never receives the token. */
  readonly log?: (line: string) => void;
}

/**
 * Only an email the issuer marks as verified (`email_verified === true`) is
 * used. `preferred_username` is never used: a user can often choose it, so an
 * email-shaped username could impersonate someone else in the footer or "me".
 */
function emailFrom(claims: Record<string, unknown>): string | null {
  const email = claims.email;
  if (claims.email_verified === true && typeof email === "string" && EMAIL.test(email)) {
    return email.toLowerCase();
  }
  return null;
}

/**
 * Finds the caller's email through the OIDC userinfo endpoint with the
 * caller's own bearer token, for attribution and for assignee "me". Only
 * called lazily by write tools. Never throws: any failure resolves to null and
 * the caller falls back to the token subject.
 */
export class UserinfoEmailResolver {
  private readonly fetcher: FetchLike;
  private readonly now: () => number;
  private readonly log: (line: string) => void;
  private readonly cache = new Map<string, { email: string | null; expires: number }>();
  private readonly inFlight = new Map<string, Promise<string | null>>();
  private readonly lastLogged = new Map<UserinfoFailure, number>();

  constructor(
    private readonly config: HangarConfig,
    dependencies: UserinfoDependencies = {}
  ) {
    this.fetcher = dependencies.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.now = dependencies.now ?? Date.now;
    this.log = dependencies.log ?? ((line) => process.stderr.write(`${line}\n`));
  }

  async emailFor(subject: string, token: string): Promise<string | null> {
    if (!this.config.oidcUserinfoUrl || !subject || !token) return null;
    const cached = this.cache.get(subject);
    if (cached && cached.expires > this.now()) return cached.email;
    const pending = this.inFlight.get(subject);
    if (pending) return pending;
    const lookup = this.lookup(subject, token).finally(() => this.inFlight.delete(subject));
    this.inFlight.set(subject, lookup);
    return lookup;
  }

  private async lookup(subject: string, token: string): Promise<string | null> {
    const result = await this.fetchClaims(token);
    let email: string | null = null;
    if (typeof result === "string") {
      this.fail(result);
    } else if (result.sub !== subject) {
      this.fail("subject_mismatch");
    } else {
      email = emailFrom(result);
      if (!email) this.fail("no_email");
    }
    this.remember(subject, email);
    return email;
  }

  private async fetchClaims(token: string): Promise<Record<string, unknown> | UserinfoFailure> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const response = await this.fetcher(this.config.oidcUserinfoUrl!, {
        method: "GET",
        redirect: "error",
        headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
        signal: controller.signal,
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        return "http_status";
      }
      const declared = Number(response.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
        await response.body?.cancel().catch(() => {});
        return "too_large";
      }
      const text = await this.readCapped(response);
      if (text === null) return "too_large";
      try {
        const parsed: unknown = JSON.parse(text);
        return parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? (parsed as Record<string, unknown>)
          : "invalid_json";
      } catch {
        return "invalid_json";
      }
    } catch {
      return controller.signal.aborted ? "timeout" : "network";
    } finally {
      clearTimeout(timer);
    }
  }

  private async readCapped(response: Response): Promise<string | null> {
    if (!response.body) {
      const text = await response.text();
      return Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES ? null : text;
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      // Sequential stream read by design.
      // oxlint-disable-next-line no-await-in-loop
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        // oxlint-disable-next-line no-await-in-loop
        await reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  }

  private remember(subject: string, email: string | null): void {
    if (!this.cache.has(subject) && this.cache.size >= MAX_ENTRIES) {
      const now = this.now();
      for (const [key, entry] of this.cache) {
        if (entry.expires <= now) this.cache.delete(key);
      }
      // Still full: drop the oldest insertion.
      if (this.cache.size >= MAX_ENTRIES) {
        const oldest = this.cache.keys().next().value;
        if (oldest !== undefined) this.cache.delete(oldest);
      }
    }
    this.cache.delete(subject);
    this.cache.set(subject, { email, expires: this.now() + (email ? POSITIVE_TTL_MS : NEGATIVE_TTL_MS) });
  }

  private fail(kind: UserinfoFailure): void {
    const now = this.now();
    const last = this.lastLogged.get(kind);
    if (last !== undefined && now - last < LOG_INTERVAL_MS) return;
    this.lastLogged.set(kind, now);
    try {
      this.log(`hangar-mcp userinfo-email outcome=${kind} fallback=sub`);
    } catch {
      // Logging must never break a tool call.
    }
  }
}
