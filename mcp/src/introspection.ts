import { createHash, randomUUID } from "node:crypto";
import { SignJWT, type JWTPayload } from "jose";
import type { HangarConfig, OidcIntrospectionAuth } from "./types.js";

// RFC 7662 token introspection for access tokens that cannot be verified
// locally (ZITADEL's default "opaque" access token is a JWE). This module
// sends the client token only to the configured issuer's introspection
// endpoint and never logs it or uses it as a cache key. Once the authorizer
// has accepted the outcome (active, issuer, audience, org-bound role, enough
// lifetime left), the same token is forwarded verbatim to Hangar, which
// introspects it again with the same checks.

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export type IntrospectionOutcome =
  | { readonly status: "active"; readonly claims: JWTPayload }
  | { readonly status: "inactive" }
  | { readonly status: "error" }
  | { readonly status: "overloaded" };

export interface IntrospectionDependencies {
  readonly fetch?: FetchLike;
  readonly now?: () => number;
  /** Operational log sink; receives the outcome class and HTTP status only. */
  readonly log?: (line: string) => void;
}

export type Introspector = (token: string) => Promise<IntrospectionOutcome>;

const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_POSITIVE_ENTRIES = 1000;
const MAX_NEGATIVE_ENTRIES = 1000;
// Inactive answers are cached just long enough to absorb a retry burst.
const NEGATIVE_CACHE_MS = 5_000;
const ASSERTION_LIFETIME_SECONDS = 60;
const ASSERTION_REUSE_MS = 50_000;
const ASSERTION_BACKDATE_SECONDS = 5;
const LOG_INTERVAL_MS = 60_000;
const JWT_BEARER_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// ZITADEL opaque access tokens are JWE compact with alg A256GCMKW / enc
// A256GCM: the wrapped 32-byte CEK is 43 base64url chars, the 12-byte IV
// 16 chars and the 16-byte tag 22 chars.
const JWE_ENCRYPTED_KEY_LENGTH = 43;
const JWE_IV_LENGTH = 16;
const JWE_TAG_LENGTH = 22;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

function b64(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

/**
 * A fixed, syntactically valid ZITADEL-shaped JWE that the issuer cannot have
 * produced. Introspecting it proves client authentication: ZITADEL answers
 * 200 {"active":false} for an unknown token and an error for bad client
 * credentials.
 */
export const SELF_CHECK_TOKEN = [
  b64(
    JSON.stringify({
      alg: "A256GCMKW",
      enc: "A256GCM",
      kid: "hangar-mcp-self-check",
      iv: "A".repeat(JWE_IV_LENGTH),
      tag: "A".repeat(JWE_TAG_LENGTH),
    })
  ),
  "A".repeat(JWE_ENCRYPTED_KEY_LENGTH),
  "A".repeat(JWE_IV_LENGTH),
  "AAAA",
  "A".repeat(JWE_TAG_LENGTH),
].join(".");

/** True only for the exact compact-JWE shape ZITADEL issues as opaque access token. */
export function isZitadelOpaqueToken(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 5 || !parts.every((part) => BASE64URL.test(part))) return false;
  const [headerSegment, encryptedKey, iv, ciphertext, tag] = parts as [string, string, string, string, string];
  if (
    encryptedKey.length !== JWE_ENCRYPTED_KEY_LENGTH ||
    iv.length !== JWE_IV_LENGTH ||
    tag.length !== JWE_TAG_LENGTH ||
    ciphertext.length === 0
  ) {
    return false;
  }
  try {
    const header: unknown = JSON.parse(Buffer.from(headerSegment, "base64url").toString("utf8"));
    if (!header || typeof header !== "object" || Array.isArray(header)) return false;
    const { alg, enc, kid } = header as Record<string, unknown>;
    return alg === "A256GCMKW" && enc === "A256GCM" && typeof kid === "string" && kid.length > 0;
  } catch {
    return false;
  }
}

function tokenKey(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function formEncode(value: string): string {
  // RFC 6749 section 2.3.1: client_id/client_secret are form-encoded before Basic.
  return encodeURIComponent(value).replace(/%20/g, "+");
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > MAX_RESPONSE_BYTES) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("introspection response too large");
  }
  if (!response.body) throw new Error("introspection response has no body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    // Sequential stream read by design.
    // oxlint-disable-next-line no-await-in-loop
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > MAX_RESPONSE_BYTES) {
      // oxlint-disable-next-line no-await-in-loop
      await reader.cancel().catch(() => undefined);
      throw new Error("introspection response too large");
    }
    chunks.push(value);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function boundedSet<T extends { expiresAt: number }>(
  map: Map<string, T>,
  key: string,
  value: T,
  max: number,
  current: number
): void {
  if (map.size >= max) {
    for (const [entryKey, entry] of map) {
      if (entry.expiresAt <= current) map.delete(entryKey);
    }
    while (map.size >= max) {
      const oldest = map.keys().next().value;
      if (oldest === undefined) break;
      map.delete(oldest);
    }
  }
  map.set(key, value);
}

async function signAssertion(
  auth: Extract<OidcIntrospectionAuth, { method: "private_key_jwt" }>,
  issuer: string,
  nowMs: number
): Promise<string> {
  // iat is backdated for clock skew; exp stays 60s after the signing time.
  const current = Math.floor(nowMs / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256", kid: auth.keyId })
    .setIssuer(auth.clientId)
    .setSubject(auth.clientId)
    .setAudience(issuer)
    .setIssuedAt(current - ASSERTION_BACKDATE_SECONDS)
    .setExpirationTime(current + ASSERTION_LIFETIME_SECONDS)
    .setJti(randomUUID())
    .sign(auth.privateKey);
}

export function createIntrospector(
  config: HangarConfig,
  issuer: string,
  dependencies: IntrospectionDependencies = {}
): Introspector {
  const url = config.oidcIntrospectionUrl;
  const auth = config.oidcIntrospectionAuth;
  if (!url || !auth) throw new Error("OIDC introspection configuration is incomplete");
  const fetcher: FetchLike = dependencies.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const now = dependencies.now ?? Date.now;
  const log =
    dependencies.log ??
    ((line: string) => {
      process.stderr.write(`${line}\n`);
    });
  const positiveCacheMs = config.oidcIntrospectionCacheSeconds * 1000;
  // Separate maps: a flood of unknown tokens can only evict other negatives.
  const positive = new Map<string, { claims: JWTPayload; expiresAt: number }>();
  const negative = new Map<string, { expiresAt: number }>();
  const inFlight = new Map<string, Promise<IntrospectionOutcome>>();

  // Process-wide limiter on issuer calls: concurrency cap plus token bucket.
  const maxInFlight = config.oidcIntrospectionMaxInFlight;
  const ratePerSecond = config.oidcIntrospectionRatePerSecond;
  let running = 0;
  let bucket = ratePerSecond;
  let bucketUpdatedAt = now();

  function acquire(): boolean {
    const current = now();
    const elapsed = Math.max(0, current - bucketUpdatedAt);
    bucket = Math.min(ratePerSecond, bucket + (elapsed / 1000) * ratePerSecond);
    bucketUpdatedAt = current;
    if (running >= maxInFlight || bucket < 1) return false;
    bucket -= 1;
    running += 1;
    return true;
  }

  // One line per outcome class per minute, with the count suppressed since.
  const lastLogged = new Map<string, { at: number; suppressed: number }>();
  function report(outcomeClass: string, httpStatus?: number): void {
    const current = now();
    const previous = lastLogged.get(outcomeClass);
    if (previous && current - previous.at < LOG_INTERVAL_MS) {
      previous.suppressed += 1;
      return;
    }
    lastLogged.set(outcomeClass, { at: current, suppressed: 0 });
    const status = httpStatus === undefined ? "" : ` status=${httpStatus}`;
    const suppressed = previous && previous.suppressed > 0 ? ` suppressed=${previous.suppressed}` : "";
    try {
      log(`hangar-mcp oidc-introspection outcome=${outcomeClass}${status}${suppressed}`);
    } catch {
      // Logging must never change the authorization outcome.
    }
  }

  let assertion: { value: string; createdAt: number } | null = null;
  async function clientAuthentication(): Promise<{ headers: Record<string, string>; form: Record<string, string> }> {
    const authentication = auth!;
    if (authentication.method === "client_secret_basic") {
      const credentials = Buffer.from(
        `${formEncode(authentication.clientId)}:${formEncode(authentication.clientSecret)}`,
        "utf8"
      ).toString("base64");
      return { headers: { authorization: `Basic ${credentials}` }, form: {} };
    }
    const current = now();
    if (!assertion || current < assertion.createdAt || current - assertion.createdAt >= ASSERTION_REUSE_MS) {
      assertion = { value: await signAssertion(authentication, issuer, current), createdAt: current };
    }
    return {
      headers: {},
      form: { client_assertion_type: JWT_BEARER_ASSERTION, client_assertion: assertion.value },
    };
  }

  async function introspect(token: string): Promise<IntrospectionOutcome> {
    const signal = AbortSignal.timeout(config.oidcIntrospectionTimeoutMs);
    try {
      const authentication = await clientAuthentication();
      const body = new URLSearchParams({
        token,
        token_type_hint: "access_token",
        ...authentication.form,
      });
      const response = await fetcher(url!, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
          ...authentication.headers,
        },
        body: body.toString(),
        redirect: "error",
        signal,
      });
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => undefined);
        report("http_error", response.status);
        return { status: "error" };
      }
      let payload: unknown;
      try {
        payload = await readBoundedJson(response);
      } catch {
        report(signal.aborted ? "timeout" : "invalid_response", response.status);
        return { status: "error" };
      }
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        report("invalid_response", response.status);
        return { status: "error" };
      }
      const claims = payload as JWTPayload & { active?: unknown };
      if (claims.active !== true) return { status: "inactive" };
      return { status: "active", claims };
    } catch {
      report(signal.aborted ? "timeout" : "request_failed");
      return { status: "error" };
    }
  }

  function remember(key: string, outcome: IntrospectionOutcome): void {
    const current = now();
    if (outcome.status === "active") {
      const exp = typeof outcome.claims.exp === "number" ? outcome.claims.exp * 1000 : current;
      const expiresAt = Math.min(current + positiveCacheMs, exp);
      if (expiresAt > current) {
        boundedSet(positive, key, { claims: outcome.claims, expiresAt }, MAX_POSITIVE_ENTRIES, current);
      }
    } else if (outcome.status === "inactive") {
      const expiresAt = current + Math.min(NEGATIVE_CACHE_MS, positiveCacheMs);
      if (expiresAt > current) boundedSet(negative, key, { expiresAt }, MAX_NEGATIVE_ENTRIES, current);
    }
  }

  return async (token) => {
    const key = tokenKey(token);
    const current = now();
    const hit = positive.get(key);
    if (hit) {
      if (hit.expiresAt > current) return { status: "active", claims: hit.claims };
      positive.delete(key);
    }
    const miss = negative.get(key);
    if (miss) {
      if (miss.expiresAt > current) return { status: "inactive" };
      negative.delete(key);
    }
    const pending = inFlight.get(key);
    if (pending) return pending;
    if (!acquire()) {
      report("overloaded");
      return { status: "overloaded" };
    }
    const request = introspect(token)
      .then((outcome) => {
        remember(key, outcome);
        return outcome;
      })
      .finally(() => {
        running -= 1;
        inFlight.delete(key);
      });
    inFlight.set(key, request);
    return request;
  };
}

export type SelfCheckResult =
  | { readonly ok: true; readonly httpStatus: number }
  | { readonly ok: false; readonly reason: string; readonly httpStatus: number | null };

/**
 * Deploy-time check: introspect SELF_CHECK_TOKEN with the configured client
 * authentication and require HTTP 200 with active=false. The result carries
 * only an outcome class and the HTTP status.
 */
export async function introspectionSelfCheck(
  config: HangarConfig,
  fetcher: FetchLike = (input, init) => globalThis.fetch(input, init)
): Promise<SelfCheckResult> {
  if (!config.oidcIssuer || !config.oidcIntrospectionUrl || !config.oidcIntrospectionAuth) {
    return { ok: false, reason: "not_configured", httpStatus: null };
  }
  const issuerPath = config.oidcIssuer.pathname && config.oidcIssuer.pathname !== "/" ? config.oidcIssuer.pathname : "";
  let httpStatus: number | null = null;
  const introspect = createIntrospector(
    { ...config, oidcIntrospectionCacheSeconds: 0 },
    `${config.oidcIssuer.origin}${issuerPath}`,
    {
      log: () => undefined,
      fetch: async (input, init) => {
        const response = await fetcher(input, init);
        httpStatus = response.status;
        return response;
      },
    }
  );
  const outcome = await introspect(SELF_CHECK_TOKEN);
  if (outcome.status === "inactive") return { ok: true, httpStatus: httpStatus ?? 200 };
  if (outcome.status === "active") return { ok: false, reason: "unexpected_active", httpStatus };
  if (httpStatus === null) return { ok: false, reason: "request_failed", httpStatus };
  return { ok: false, reason: httpStatus === 200 ? "invalid_response" : "http_error", httpStatus };
}
