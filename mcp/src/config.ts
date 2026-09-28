import { createPrivateKey } from "node:crypto";
import type { HangarConfig, OidcIntrospectionAuth } from "./types.js";

const DEFAULT_BASE_URL = "https://hangar.getdumont.ai";
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
const WORKSPACE_SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const PROJECT_IDENTIFIER_PATTERN = /^[A-Z][A-Z0-9]{1,9}$/;
const PROJECT_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OIDC_SCOPE_PATTERN = /^\S{1,200}$/;

export class HangarConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HangarConfigError";
  }
}

function boundedInt(env: NodeJS.ProcessEnv, name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new HangarConfigError(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function parseCsv(env: NodeJS.ProcessEnv, name: string): string[] {
  return (env[name] ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function parseWorkspaceSlug(env: NodeJS.ProcessEnv): string {
  const slug = env.HANGAR_WORKSPACE_SLUG?.trim() ?? "";
  if (!WORKSPACE_SLUG_PATTERN.test(slug)) {
    throw new HangarConfigError("HANGAR_WORKSPACE_SLUG is required and must be a lowercase workspace slug");
  }
  return slug;
}

function parseProjectList(env: NodeJS.ProcessEnv, name: string): string[] {
  const normalized = parseCsv(env, name).map((value) => {
    if (PROJECT_UUID_PATTERN.test(value)) return value.toLowerCase();
    const identifier = value.toUpperCase();
    if (PROJECT_IDENTIFIER_PATTERN.test(identifier)) return identifier;
    throw new HangarConfigError(`${name} must contain only project identifiers (like HGR) or project UUIDs`);
  });
  return [...new Set(normalized)];
}

/**
 * Optional ceiling on the projects reachable through the MCP. Empty or unset =
 * no ceiling: whatever Hangar lets the calling user see.
 */
function parseAllowedProjects(env: NodeJS.ProcessEnv): string[] {
  return parseProjectList(env, "HANGAR_ALLOWED_PROJECTS");
}

const MIN_CURSOR_SECRET_BYTES = 32;

/** Error messages must never echo the value. */
function parseCursorSecret(env: NodeJS.ProcessEnv): string {
  const value = env.MCP_CURSOR_SECRET?.trim() ?? "";
  if (/[\r\n]/.test(value) || Buffer.byteLength(value, "utf8") < MIN_CURSOR_SECRET_BYTES) {
    throw new HangarConfigError(
      `MCP_CURSOR_SECRET is required and must be at least ${MIN_CURSOR_SECRET_BYTES} bytes on one line (for example: openssl rand -hex 32)`
    );
  }
  return value;
}

/**
 * Keys of the retired bot-token model. Present at all (even empty) = startup
 * error, so a stale env file is noticed instead of silently ignored.
 */
const RETIRED_VARIABLES: ReadonlyArray<readonly [string, string]> = [
  [
    "HANGAR_API_KEY",
    "HANGAR_API_KEY is retired, remove it: the MCP now calls Hangar as the logged-in user with the caller's own Dumont (ZITADEL) token, so the bot API key is no longer used",
  ],
  [
    "HANGAR_WRITE_PROJECTS",
    "HANGAR_WRITE_PROJECTS is retired, remove it: Hangar project membership now decides where each user may write (the hangar_writer role still gates the write tools); HANGAR_ALLOWED_PROJECTS remains as an optional ceiling",
  ],
];

function rejectRetiredVariables(env: NodeJS.ProcessEnv): void {
  for (const [name, message] of RETIRED_VARIABLES) {
    if (env[name] !== undefined) throw new HangarConfigError(message);
  }
}

function parseRoleName(env: NodeJS.ProcessEnv, name: string): string {
  const value = parseOptionalToken(env, name);
  if (/\s/.test(value) || value.length > 200) {
    throw new HangarConfigError(`${name} must be one role name without whitespace`);
  }
  return value;
}

function parseRoles(env: NodeJS.ProcessEnv): { readerRole: string; writerRole: string } {
  const reader = parseRoleName(env, "MCP_OIDC_READER_ROLE");
  // MCP_OIDC_REQUIRED_ROLE is the pre-HGR-6 name of the reader role.
  const legacy = parseRoleName(env, "MCP_OIDC_REQUIRED_ROLE");
  if (reader && legacy && reader !== legacy) {
    throw new HangarConfigError(
      "MCP_OIDC_READER_ROLE and the legacy MCP_OIDC_REQUIRED_ROLE disagree; keep only MCP_OIDC_READER_ROLE"
    );
  }
  const readerRole = reader || legacy || "hangar_reader";
  const writerRole = parseRoleName(env, "MCP_OIDC_WRITER_ROLE") || "hangar_writer";
  if (readerRole === writerRole) {
    throw new HangarConfigError("MCP_OIDC_READER_ROLE and MCP_OIDC_WRITER_ROLE must be different roles");
  }
  return { readerRole, writerRole };
}

export function zitadelRoleScope(role: string): string {
  return `urn:zitadel:iam:org:project:role:${role}`;
}

function validateBaseUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new HangarConfigError("HANGAR_BASE_URL must be a valid URL");
  }
  const loopbackHttp = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !loopbackHttp) {
    throw new HangarConfigError("HANGAR_BASE_URL must use HTTPS or loopback HTTP");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new HangarConfigError("HANGAR_BASE_URL must not contain credentials or query parameters");
  }
  if (url.pathname !== "" && url.pathname !== "/") {
    throw new HangarConfigError("HANGAR_BASE_URL must point to the Hangar host root");
  }
  url.pathname = "";
  return url;
}

function parseOrigins(env: NodeJS.ProcessEnv): string[] {
  const origins = parseCsv(env, "MCP_ALLOWED_ORIGINS");
  for (const origin of origins) {
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new HangarConfigError("MCP_ALLOWED_ORIGINS must contain valid origins");
    }
    if (
      (url.protocol !== "http:" && url.protocol !== "https:") ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      url.username ||
      url.password
    ) {
      throw new HangarConfigError("MCP_ALLOWED_ORIGINS must contain origin-only URLs");
    }
  }
  return origins.map((origin) => new URL(origin).origin);
}

function parseHosts(env: NodeJS.ProcessEnv): string[] {
  return [...new Set(parseCsv(env, "MCP_ALLOWED_HOSTS").map((host) => host.toLowerCase()))];
}

function validateHttpsUrl(raw: string, name: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new HangarConfigError(`${name} must be a valid URL`);
  }
  if (url.protocol !== "https:") {
    throw new HangarConfigError(`${name} must use HTTPS`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new HangarConfigError(`${name} must not contain credentials, query parameters, or fragments`);
  }
  if (url.pathname === "/") url.pathname = "";
  return url;
}

function parseOptionalHttpsUrl(env: NodeJS.ProcessEnv, name: string): URL | null {
  const raw = env[name]?.trim();
  return raw ? validateHttpsUrl(raw, name) : null;
}

function parseOidcAudience(env: NodeJS.ProcessEnv): string {
  const audience = env.MCP_OIDC_AUDIENCE?.trim() ?? "";
  if (!audience || /\s/.test(audience) || audience.length > 200) {
    throw new HangarConfigError("MCP_OIDC_AUDIENCE is required and must be one non-empty value without whitespace");
  }
  return audience;
}

/**
 * The ZITADEL instance is shared with other products' organizations, so every
 * Hangar role is bound to this organization (see `hasRole` in auth.ts).
 * Without it no token could be accepted, so it is a startup error.
 */
function parseAllowedOrgId(env: NodeJS.ProcessEnv): string {
  const value = parseOptionalToken(env, "MCP_OIDC_ALLOWED_ORG_ID");
  if (!value) {
    throw new HangarConfigError(
      "MCP_OIDC_ALLOWED_ORG_ID is required: the ZITADEL organization id whose role grants count (the ZITADEL instance is shared with other organizations)"
    );
  }
  if (/\s/.test(value) || value.length > 200) {
    throw new HangarConfigError("MCP_OIDC_ALLOWED_ORG_ID must be one organization id without whitespace");
  }
  return value;
}

function parseOidcScope(env: NodeJS.ProcessEnv, fallback: string): string {
  const scope = env.MCP_OIDC_REQUIRED_SCOPE?.trim() || fallback;
  if (!OIDC_SCOPE_PATTERN.test(scope)) {
    throw new HangarConfigError("MCP_OIDC_REQUIRED_SCOPE must be one non-empty OAuth scope without whitespace");
  }
  return scope;
}

function parseOptionalToken(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim() ?? "";
  if (value && /[\r\n]/.test(value)) {
    throw new HangarConfigError(`${name} must not contain newlines`);
  }
  return value;
}

const INTROSPECTION_CREDENTIAL_VARIABLES = [
  "MCP_OIDC_INTROSPECTION_CLIENT_ID",
  "MCP_OIDC_INTROSPECTION_CLIENT_SECRET",
  "MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON",
] as const;

function parseIntrospectionPrivateKey(raw: string, clientId: string): OidcIntrospectionAuth {
  // ZITADEL's downloadable API-application key: {"type":"application","keyId","key","appId","clientId"}.
  // Error messages must never echo the value.
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new HangarConfigError(
      "MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON must be the JSON key file of a ZITADEL API application"
    );
  }
  const record = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  const { type, keyId, key, clientId: keyClientId } = record;
  if (
    type !== "application" ||
    typeof keyId !== "string" ||
    !keyId ||
    typeof key !== "string" ||
    !key ||
    typeof keyClientId !== "string" ||
    !keyClientId
  ) {
    throw new HangarConfigError(
      "MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON must be the JSON key file of a ZITADEL API application"
    );
  }
  if (clientId && clientId !== keyClientId) {
    throw new HangarConfigError(
      "MCP_OIDC_INTROSPECTION_CLIENT_ID does not match the client of MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON"
    );
  }
  let privateKey;
  try {
    privateKey = createPrivateKey(key);
  } catch {
    throw new HangarConfigError("MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON does not contain a readable private key");
  }
  if (privateKey.asymmetricKeyType !== "rsa") {
    throw new HangarConfigError("MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON must contain an RSA private key");
  }
  return { method: "private_key_jwt", clientId: keyClientId, keyId, privateKey };
}

function parseIntrospection(
  env: NodeJS.ProcessEnv,
  oidcIssuer: URL | null
): Pick<HangarConfig, "oidcIntrospectionUrl" | "oidcIntrospectionAuth"> {
  const url = parseOptionalHttpsUrl(env, "MCP_OIDC_INTROSPECTION_URL");
  if (!url) {
    const stray = INTROSPECTION_CREDENTIAL_VARIABLES.find((name) => env[name]?.trim());
    if (stray) {
      throw new HangarConfigError(`MCP_OIDC_INTROSPECTION_URL is required when ${stray} is set`);
    }
    return { oidcIntrospectionUrl: null, oidcIntrospectionAuth: null };
  }
  // Client tokens are posted to this URL, so it must belong to the configured issuer.
  if (!oidcIssuer || url.origin !== oidcIssuer.origin) {
    throw new HangarConfigError("MCP_OIDC_INTROSPECTION_URL must be on the same origin as MCP_OIDC_ISSUER");
  }
  const clientId = parseOptionalToken(env, "MCP_OIDC_INTROSPECTION_CLIENT_ID");
  const clientSecret = parseOptionalToken(env, "MCP_OIDC_INTROSPECTION_CLIENT_SECRET");
  const privateKeyJson = env.MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON?.trim() ?? "";
  if (/\s/.test(clientId) || clientId.length > 200) {
    throw new HangarConfigError("MCP_OIDC_INTROSPECTION_CLIENT_ID must be one value without whitespace");
  }
  if (Boolean(clientSecret) === Boolean(privateKeyJson)) {
    throw new HangarConfigError(
      "MCP_OIDC_INTROSPECTION_URL requires exactly one of MCP_OIDC_INTROSPECTION_CLIENT_SECRET or MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON"
    );
  }
  if (clientSecret) {
    if (!clientId) {
      throw new HangarConfigError(
        "MCP_OIDC_INTROSPECTION_CLIENT_ID is required with MCP_OIDC_INTROSPECTION_CLIENT_SECRET"
      );
    }
    return {
      oidcIntrospectionUrl: url,
      oidcIntrospectionAuth: { method: "client_secret_basic", clientId, clientSecret },
    };
  }
  return { oidcIntrospectionUrl: url, oidcIntrospectionAuth: parseIntrospectionPrivateKey(privateKeyJson, clientId) };
}

export function loadHangarConfig(env: NodeJS.ProcessEnv = process.env): HangarConfig {
  rejectRetiredVariables(env);

  const httpHost = env.MCP_HTTP_HOST?.trim() || "127.0.0.1";
  const allowedHosts = parseHosts(env);
  if (!LOOPBACK_HOSTS.has(httpHost) && allowedHosts.length === 0) {
    throw new HangarConfigError("MCP_ALLOWED_HOSTS is required for non-loopback HTTP binding");
  }

  if (env.MCP_AUTH_MODE?.trim().toLowerCase() === "static" || env.MCP_AUTH_TOKEN?.trim()) {
    throw new HangarConfigError("Static MCP authentication is retired; use ZITADEL OIDC");
  }
  if (env.MCP_AUTH_MODE && env.MCP_AUTH_MODE.trim().toLowerCase() !== "oidc") {
    throw new HangarConfigError("MCP_AUTH_MODE must be oidc");
  }
  const oidcIssuer = parseOptionalHttpsUrl(env, "MCP_OIDC_ISSUER");
  const oidcJwksUrl = parseOptionalHttpsUrl(env, "MCP_OIDC_JWKS_URL");
  const resourceUrl = parseOptionalHttpsUrl(env, "MCP_RESOURCE_URL");
  const oidcAudience = env.MCP_OIDC_AUDIENCE?.trim() ?? "";
  const { readerRole, writerRole } = parseRoles(env);
  const oidcRequiredScope = parseOidcScope(env, zitadelRoleScope(readerRole));
  // ZITADEL only asserts the roles a client asked for, so clients must request
  // both role scopes. `openid email` are kept as advertised so existing client
  // logins and consents do not change; neither is required on the token.
  const oidcScopesSupported = [
    ...new Set(["openid", "email", oidcRequiredScope, zitadelRoleScope(readerRole), zitadelRoleScope(writerRole)]),
  ];
  const allowedProjects = parseAllowedProjects(env);
  const oidcAllowedSubjects = parseCsv(env, "MCP_OIDC_ALLOWED_SUBJECTS");
  const introspection = parseIntrospection(env, oidcIssuer);
  const cursorSecret = parseCursorSecret(env);

  if (!oidcIssuer) throw new HangarConfigError("MCP_OIDC_ISSUER is required");
  if (!oidcJwksUrl) throw new HangarConfigError("MCP_OIDC_JWKS_URL is required");
  if (!resourceUrl) throw new HangarConfigError("MCP_RESOURCE_URL is required");
  parseOidcAudience(env);
  const oidcAllowedOrgId = parseAllowedOrgId(env);

  return {
    baseUrl: validateBaseUrl(env.HANGAR_BASE_URL?.trim() || DEFAULT_BASE_URL),
    workspaceSlug: parseWorkspaceSlug(env),
    allowedProjects,
    cursorSecret,
    writeRateLimit: boundedInt(env, "HANGAR_WRITE_RATE_LIMIT", 20, 1, 120),
    timeoutMs: boundedInt(env, "HANGAR_TIMEOUT_MS", 7500, 100, 30000),
    maxResponseBytes: boundedInt(env, "HANGAR_MAX_RESPONSE_BYTES", 2 * 1024 * 1024, 1024, 8 * 1024 * 1024),
    maxSearchPages: boundedInt(env, "HANGAR_MAX_SEARCH_PAGES", 3, 1, 10),
    projectCacheSeconds: boundedInt(env, "HANGAR_PROJECT_CACHE_SECONDS", 60, 0, 600),
    httpPort: boundedInt(env, "MCP_HTTP_PORT", 3000, 1, 65535),
    httpHost,
    allowedOrigins: parseOrigins(env),
    allowedHosts,
    oidcIssuer,
    oidcJwksUrl,
    oidcAudience,
    oidcRequiredScope,
    oidcReaderRole: readerRole,
    oidcWriterRole: writerRole,
    oidcScopesSupported,
    oidcAllowedOrgId,
    oidcAllowedSubjects,
    resourceUrl,
    ...introspection,
    oidcIntrospectionTimeoutMs: boundedInt(env, "MCP_OIDC_INTROSPECTION_TIMEOUT_MS", 3000, 100, 10000),
    oidcIntrospectionCacheSeconds: boundedInt(env, "MCP_OIDC_INTROSPECTION_CACHE_SECONDS", 30, 0, 60),
    oidcIntrospectionMaxInFlight: boundedInt(env, "MCP_OIDC_INTROSPECTION_MAX_IN_FLIGHT", 8, 1, 64),
    oidcIntrospectionRatePerSecond: boundedInt(env, "MCP_OIDC_INTROSPECTION_RATE_PER_SECOND", 20, 1, 200),
  };
}

export function assertHttpAuthConfigured(config: HangarConfig): void {
  if (
    !config.oidcIssuer ||
    !config.oidcJwksUrl ||
    !config.oidcAudience ||
    !config.oidcAllowedOrgId ||
    !config.resourceUrl
  ) {
    throw new HangarConfigError("OIDC configuration is incomplete for Streamable HTTP");
  }
}
