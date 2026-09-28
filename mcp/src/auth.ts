import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { IncomingMessage } from "node:http";
import { createIntrospector, isZitadelOpaqueToken, type IntrospectionDependencies } from "./introspection.js";
import { zitadelRoleScope } from "./config.js";
import type { HangarConfig, Principal } from "./types.js";

const MAX_BEARER_BYTES = 16 * 1024;
// Small allowance for clock skew between this host and the issuer on `nbf`.
const NOT_BEFORE_TOLERANCE_SECONDS = 30;
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
   * Set only when failure is null: the caller's verified bearer to forward to
   * Hangar, or null when it must not be forwarded (an opaque/JWE token that
   * passed introspection; Hangar only accepts JWTs). Never logged.
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

function containsString(value: unknown, wanted: string): boolean {
  if (value === wanted) return true;
  if (Array.isArray(value)) return value.some((item) => containsString(item, wanted));
  if (value && typeof value === "object") {
    return Object.entries(value).some(([key, item]) => key === wanted || containsString(item, wanted));
  }
  return false;
}

/**
 * Role sources, all on a token already bound to our issuer and audience:
 * - `urn:zitadel:iam:org:project:<audience>:roles`: ZITADEL's project-scoped
 *   claim; only roles of the audience project can appear under it.
 * - `urn:zitadel:iam:org:project:roles`: ZITADEL puts the roles of the
 *   project of the requesting application here. Our clients (the pinned
 *   public client and DCR apps) live in the audience project, so these are
 *   audience-project roles. A client of ANOTHER project that also requests
 *   our audience would carry its own project's roles here; same-named roles
 *   there would be accepted, so role names must stay unique per instance and
 *   no other project may define `hangar_reader`/`hangar_writer`.
 * - `roles`: legacy flat claim, same caveat.
 * - `my:zitadel:grants`: custom Action claim, only the exact
 *   `<audience>:<role>` entry.
 */
function hasRole(payload: JWTPayload, config: HangarConfig, role: string): boolean {
  const roleClaims = new Set([
    "roles",
    "urn:zitadel:iam:org:project:roles",
    `urn:zitadel:iam:org:project:${config.oidcAudience}:roles`,
  ]);
  for (const [claimName, claimValue] of Object.entries(payload)) {
    if (!roleClaims.has(claimName)) continue;
    if (Array.isArray(claimValue) && claimValue.some((value) => value === role)) return true;
    if (claimValue && typeof claimValue === "object" && Object.prototype.hasOwnProperty.call(claimValue, role)) {
      return true;
    }
  }

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

function hasAllowedOrganization(payload: JWTPayload, organizationId: string): boolean {
  return (
    containsString(payload["urn:zitadel:iam:user:resourceowner"], organizationId) ||
    payload["urn:zitadel:iam:user:resourceowner:id"] === organizationId ||
    containsString(payload["urn:zitadel:iam:org:id"], organizationId) ||
    containsString(payload.org_id, organizationId) ||
    Object.entries(payload)
      .filter(([claimName]) => claimName.endsWith(":roles"))
      .some(([, claimValue]) => containsString(claimValue, organizationId))
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
  if (config.oidcAllowedOrgId && !hasAllowedOrganization(payload, config.oidcAllowedOrgId)) {
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
      const result = evaluateAccessClaims(payload, config, Math.floor(now() / 1000));
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
    const result = evaluateAccessClaims(outcome.claims, config, Math.floor(now() / 1000));
    // Hangar accepts only JWTs: an opaque token is valid for this MCP but is
    // never forwarded (the tools answer TOKEN_NOT_FORWARDABLE).
    return result.failure ? result : { ...result, upstreamToken: null };
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
