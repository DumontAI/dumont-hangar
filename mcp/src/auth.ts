import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { IncomingMessage } from "node:http";
import { createIntrospector, isZitadelOpaqueToken, type IntrospectionDependencies } from "./introspection.js";
import { zitadelRoleScope } from "./config.js";
import type { HangarConfig, Principal } from "./types.js";

const MAX_BEARER_BYTES = 16 * 1024;
// Small allowance for clock skew between this host and the issuer on `nbf`.
const NOT_BEFORE_TOLERANCE_SECONDS = 30;
/**
 * Every accepted access token (a verified JWS, or an opaque token that passed
 * introspection) is forwarded to Hangar, so it must still be valid there for
 * the whole tool call: a token with at most this many seconds left (its JWT
 * `exp`, or the introspection `exp`) is answered with the regular 401
 * challenge (the client refreshes) instead of being forwarded and failing
 * upstream.
 */
export const MIN_TOKEN_LIFETIME_SECONDS = 30;
const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]*$/;
const ACCESS_TOKEN_TYPES = new Set(["bearer", "access_token", "urn:ietf:params:oauth:token-type:access_token"]);

function canonicalUrl(url: URL): string {
  return `${url.origin}${url.pathname && url.pathname !== "/" ? url.pathname : ""}`;
}

export type AuthorizationFailure =
  | "missing_credentials"
  | "invalid_credentials"
  | "insufficient_scope"
  | "temporarily_unavailable"
  | "request_origin_not_allowed"
  | "request_host_not_allowed";

export interface AuthorizationResult {
  readonly failure: AuthorizationFailure | null;
  readonly subject: string | null;
  /** Set only when failure is null: the verified caller handed to the tools. */
  readonly principal?: Principal | null;
  /**
   * Set only when failure is null: the caller's bearer, verbatim, to forward
   * to Hangar. Only a token that passed this MCP's own validation (a locally
   * verified RS256 JWS, or an opaque token introspected as active with our
   * issuer, audience, org-bound role and enough lifetime left) is ever set
   * here. Never logged.
   */
  readonly upstreamToken?: string | null;
  /** Set only when failure is null: the token `exp` (epoch seconds). */
  readonly expiresAt?: number;
}

function requestHost(req: IncomingMessage): string {
  const raw = req.headers.host?.trim().toLowerCase() ?? "";
  if (!raw) return "";
  if (raw.startsWith("[")) return raw.slice(1, raw.indexOf("]"));
  return raw.split(":", 1)[0] ?? raw;
}

function requestHostAllowed(req: IncomingMessage, config: HangarConfig): boolean {
  const host = requestHost(req);
  const configuredHosts = config.allowedHosts.length > 0 ? config.allowedHosts : ["127.0.0.1", "localhost", "::1"];
  return (
    Boolean(host) && configuredHosts.some((allowed) => allowed === host || allowed === req.headers.host?.toLowerCase())
  );
}

function requestOriginAllowed(req: IncomingMessage, config: HangarConfig): boolean {
  if (config.allowedOrigins.length === 0) return true;
  const origin = req.headers.origin;
  return !origin || config.allowedOrigins.includes(origin);
}

export function bearerToken(req: IncomingMessage): string | null {
  const authorization = req.headers.authorization ?? "";
  const match = /^Bearer[ \t]+([^ \t]+)$/i.exec(authorization);
  const token = match?.[1] ?? "";
  if (!token || Buffer.byteLength(token, "utf8") > MAX_BEARER_BYTES) return null;
  return token;
}

function tokenScopes(payload: JWTPayload): Set<string> {
  const values: string[] = [];
  if (typeof payload.scope === "string") values.push(...payload.scope.split(" ").filter(Boolean));
  if (Array.isArray(payload.scp)) {
    values.push(...payload.scp.filter((value): value is string => typeof value === "string"));
  }
  return new Set(values);
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * ZITADEL's role map `{ <role>: { <orgId>: <orgDomain> } }`: the role counts
 * only when it was granted in the allowed organization, i.e. `claim[role]` is
 * an object with the allowed org id as an own key.
 */
function roleGrantedInOrg(claimValue: unknown, role: string, organizationId: string): boolean {
  if (!isJsonObject(claimValue) || !Object.hasOwn(claimValue, role)) return false;
  const organizations = claimValue[role];
  return isJsonObject(organizations) && Object.hasOwn(organizations, organizationId);
}

/**
 * Role sources, all on a token already bound to our issuer and audience. The
 * ZITADEL instance is shared with other products and their organizations, so
 * a role name alone proves nothing: any organization can define a project
 * role called `hangar_writer`, and any organization's Actions can set the
 * legacy claims. Every role is therefore bound to MCP_OIDC_ALLOWED_ORG_ID:
 *
 * - `urn:zitadel:iam:org:project:<audience>:roles` and
 *   `urn:zitadel:iam:org:project:roles` in ZITADEL's object form count only
 *   when `claim[role]` is an object keyed by the allowed org id (the role was
 *   granted in our organization). A grant of a different role in our org
 *   never vouches for this role.
 * - Any other form (an array of these claims, the legacy flat `roles` claim,
 *   the `my:zitadel:grants` Action claim as the exact `<audience>:<role>`)
 *   counts only when the user belongs to the allowed organization:
 *   `urn:zitadel:iam:user:resourceowner:id` equal to it. `org_id` is never
 *   used (it names the org of the request context, not of the user).
 *
 * The same rules apply to JWS and introspected (opaque) tokens, and Hangar
 * applies them to the forwarded token.
 */
function hasRole(payload: JWTPayload, config: HangarConfig, role: string): boolean {
  const organizationId = config.oidcAllowedOrgId;
  if (!organizationId) return false;
  const userInAllowedOrg = payload["urn:zitadel:iam:user:resourceowner:id"] === organizationId;

  const projectRoleClaims = [
    `urn:zitadel:iam:org:project:${config.oidcAudience}:roles`,
    "urn:zitadel:iam:org:project:roles",
  ];
  for (const claimName of projectRoleClaims) {
    if (!Object.hasOwn(payload, claimName)) continue;
    const claimValue = payload[claimName];
    if (isJsonObject(claimValue)) {
      if (roleGrantedInOrg(claimValue, role, organizationId)) return true;
    } else if (userInAllowedOrg && Array.isArray(claimValue) && claimValue.some((value) => value === role)) {
      return true;
    }
  }

  if (!userInAllowedOrg) return false;

  const legacyRoles = payload.roles;
  if (Array.isArray(legacyRoles) && legacyRoles.some((value) => value === role)) return true;
  if (isJsonObject(legacyRoles) && Object.hasOwn(legacyRoles, role)) return true;

  // Custom claim from a ZITADEL Action (`<projectId>:<role>` strings). A bare
  // role, or a role of another project, is never enough: only the exact
  // `<configured audience project>:<role>` entry counts.
  const grants = payload["my:zitadel:grants"];
  const scoped = `${config.oidcAudience}:${role}`;
  return Boolean(config.oidcAudience) && Array.isArray(grants) && grants.some((grant) => grant === scoped);
}

/** The configured Hangar roles (reader, writer) this token carries, in that order. */
export function grantedRoles(payload: JWTPayload, config: HangarConfig): string[] {
  return [config.oidcReaderRole, config.oidcWriterRole].filter((role) => hasRole(payload, config, role));
}

/**
 * The default required scope is a ZITADEL reserved role scope. ZITADEL JWT
 * access tokens do not necessarily echo it in `scope`/`scp`, so the role claim
 * is what gets checked. Only a custom MCP_OIDC_REQUIRED_SCOPE must be literal.
 */
function usesZitadelRoleScope(config: HangarConfig): boolean {
  return (
    config.oidcRequiredScope === zitadelRoleScope(config.oidcReaderRole) ||
    config.oidcRequiredScope === zitadelRoleScope(config.oidcWriterRole)
  );
}

function invalidCredentials(): AuthorizationResult {
  return { failure: "invalid_credentials", subject: null };
}

/**
 * The single authorization policy for OIDC access-token claims, whether they
 * came from a locally verified JWS or from an RFC 7662 introspection response.
 * Binding failures (issuer, audience, lifetime, subject) are 401; a valid token
 * without the required role/scope/org/subject is 403.
 */
export function evaluateAccessClaims(
  claims: JWTPayload,
  config: HangarConfig,
  nowSeconds: number
): AuthorizationResult {
  if (!config.oidcIssuer || claims.iss !== canonicalUrl(config.oidcIssuer)) return invalidCredentials();
  const audiences = typeof claims.aud === "string" ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : [];
  if (!config.oidcAudience || !audiences.includes(config.oidcAudience)) return invalidCredentials();
  if (typeof claims.exp !== "number" || claims.exp <= nowSeconds) return invalidCredentials();
  if (
    claims.nbf !== undefined &&
    (typeof claims.nbf !== "number" || claims.nbf > nowSeconds + NOT_BEFORE_TOLERANCE_SECONDS)
  ) {
    return invalidCredentials();
  }
  if (typeof claims.sub !== "string" || claims.sub.length === 0) return invalidCredentials();
  const failure = oidcAccessAllowed(claims, config);
  if (failure) return { failure, subject: claims.sub, principal: null };
  return {
    failure: null,
    subject: claims.sub,
    principal: { sub: claims.sub, roles: grantedRoles(claims, config) },
    expiresAt: claims.exp,
  };
}

type TokenShape = "jws" | "jwe" | "other";

function protectedHeader(segment: string): Record<string, unknown> | null {
  if (!segment) return null;
  try {
    const header: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return header && typeof header === "object" && !Array.isArray(header) ? (header as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * JWS compact tokens are only ever verified locally (so ID tokens and forged
 * JWTs never reach the issuer). Only the exact JWE shape ZITADEL issues as
 * opaque access token is eligible for introspection, which keeps arbitrary
 * bearers from turning into issuer calls. Anything else is rejected locally.
 */
function tokenShape(token: string): TokenShape {
  if (isZitadelOpaqueToken(token)) return "jwe";
  const parts = token.split(".");
  if (parts.length !== 3 || !parts.every((part) => BASE64URL_SEGMENT.test(part))) return "other";
  const header = protectedHeader(parts[0] ?? "");
  if (!header || typeof header.alg !== "string" || header.enc !== undefined) return "other";
  return "jws";
}

function isAccessTokenType(value: unknown): boolean {
  return value === undefined || (typeof value === "string" && ACCESS_TOKEN_TYPES.has(value.toLowerCase()));
}

function oidcAccessAllowed(payload: JWTPayload, config: HangarConfig): AuthorizationFailure | null {
  const scopes = tokenScopes(payload);
  // Server-level gate: the reader or the writer role (writer implies reader).
  // Per-tool checks happen in the tool layer, so a reader calling a write tool
  // gets a tool error instead of a 401/403 that would restart the login.
  // This is also the organization gate: `hasRole` only counts a role bound to
  // MCP_OIDC_ALLOWED_ORG_ID (no separate, looser org check).
  if (grantedRoles(payload, config).length === 0) {
    return "insufficient_scope";
  }
  // ZITADEL uses the reserved role scopes to request/assert the role claim;
  // its JWT access tokens do not necessarily echo them in `scope`/`scp`. A
  // role claim remains mandatory, while other OIDC scopes still require a
  // literal scope claim.
  if (!scopes.has(config.oidcRequiredScope) && !usesZitadelRoleScope(config)) {
    return "insufficient_scope";
  }
  if (
    config.oidcAllowedSubjects.length > 0 &&
    (typeof payload.sub !== "string" || !config.oidcAllowedSubjects.includes(payload.sub))
  ) {
    return "insufficient_scope";
  }
  return null;
}

export type AuthorizerDependencies = IntrospectionDependencies;

function createOidcVerifier(config: HangarConfig, dependencies: AuthorizerDependencies) {
  if (!config.oidcIssuer || !config.oidcJwksUrl) {
    throw new Error("OIDC verifier configuration is incomplete");
  }
  const issuer = canonicalUrl(config.oidcIssuer);
  const jwks = createRemoteJWKSet(config.oidcJwksUrl);
  const now = dependencies.now ?? Date.now;
  const introspect =
    config.oidcIntrospectionUrl && config.oidcIntrospectionAuth
      ? createIntrospector(config, issuer, dependencies)
      : null;

  async function verifyJws(token: string): Promise<AuthorizationResult> {
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer,
        audience: config.oidcAudience,
        algorithms: ["RS256"],
        currentDate: new Date(now()),
      });
      // `nonce`/`at_hash` only appear in ID tokens; never accept one as an access token.
      if (payload.nonce !== undefined || payload.at_hash !== undefined) return invalidCredentials();
      const nowSeconds = Math.floor(now() / 1000);
      // About to expire: 401 now, so the client refreshes before anything is forwarded.
      if (typeof payload.exp !== "number" || payload.exp <= nowSeconds + MIN_TOKEN_LIFETIME_SECONDS) {
        return invalidCredentials();
      }
      const result = evaluateAccessClaims(payload, config, nowSeconds);
      // Only a locally verified RS256 JWS access token is ever forwarded to Hangar.
      return result.failure ? result : { ...result, upstreamToken: token };
    } catch {
      return invalidCredentials();
    }
  }

  async function verifyByIntrospection(token: string): Promise<AuthorizationResult> {
    if (!introspect) return invalidCredentials();
    const outcome = await introspect(token);
    // Local overload is not a credential problem: answer 503 so clients retry
    // instead of restarting an OAuth login loop.
    if (outcome.status === "overloaded") return { failure: "temporarily_unavailable", subject: null };
    if (outcome.status !== "active" || !isAccessTokenType(outcome.claims.token_type)) {
      return invalidCredentials();
    }
    const nowSeconds = Math.floor(now() / 1000);
    // Same near-expiry rule as the JWS path, on the introspection `exp`.
    const exp = outcome.claims.exp;
    if (typeof exp !== "number" || exp <= nowSeconds + MIN_TOKEN_LIFETIME_SECONDS) {
      return invalidCredentials();
    }
    const result = evaluateAccessClaims(outcome.claims, config, nowSeconds);
    // Passed introspection and the same claims policy as a JWS: forwarded to
    // Hangar verbatim (Hangar introspects it again with the same checks).
    return result.failure ? result : { ...result, upstreamToken: token };
  }

  return async (token: string): Promise<AuthorizationResult> => {
    const shape = tokenShape(token);
    if (shape === "jws") return verifyJws(token);
    if (shape === "jwe") return verifyByIntrospection(token);
    return invalidCredentials();
  };
}

export function metadataUrl(config: HangarConfig): URL | null {
  if (!config.resourceUrl) return null;
  return new URL("/.well-known/oauth-protected-resource", config.resourceUrl.origin);
}

export function protectedResourceMetadata(config: HangarConfig): Record<string, unknown> | null {
  if (!config.resourceUrl || !config.oidcIssuer) return null;
  return {
    resource: canonicalUrl(config.resourceUrl),
    authorization_servers: [canonicalUrl(config.oidcIssuer)],
    scopes_supported: [...config.oidcScopesSupported],
    bearer_methods_supported: ["header"],
  };
}

export function protectedResourceMetadataPaths(config: HangarConfig): string[] {
  if (!config.resourceUrl) return [];
  const paths = new Set(["/.well-known/oauth-protected-resource"]);
  if (config.resourceUrl.pathname && config.resourceUrl.pathname !== "/") {
    paths.add(`/.well-known/oauth-protected-resource${config.resourceUrl.pathname}`);
  }
  return [...paths];
}

function quote(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

export function authorizationChallenge(config: HangarConfig, failure: AuthorizationFailure): string | null {
  if (failure === "temporarily_unavailable") return null;
  const metadata = metadataUrl(config);
  if (!metadata) return null;
  // RFC 6750 scope is space-delimited: ask for both role scopes so a new login
  // can carry the writer role when the user has it.
  const scope = quote(config.oidcScopesSupported.join(" "));
  const resourceMetadata = quote(metadata.href);
  if (failure === "insufficient_scope") {
    return `Bearer error="insufficient_scope", scope=${scope}, resource_metadata=${resourceMetadata}`;
  }
  return `Bearer resource_metadata=${resourceMetadata}, scope=${scope}`;
}

export function createAuthorizer(
  config: HangarConfig,
  dependencies: AuthorizerDependencies = {}
): (req: IncomingMessage) => Promise<AuthorizationResult> {
  const verifyOidc = createOidcVerifier(config, dependencies);
  return async (req) => {
    if (!requestOriginAllowed(req, config)) {
      return { failure: "request_origin_not_allowed", subject: null };
    }
    if (!requestHostAllowed(req, config)) {
      return { failure: "request_host_not_allowed", subject: null };
    }

    const token = bearerToken(req);
    if (!token) return { failure: "missing_credentials", subject: null };

    return verifyOidc(token);
  };
}
