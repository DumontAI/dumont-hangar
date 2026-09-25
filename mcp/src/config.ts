import { createPrivateKey } from "node:crypto";
import type { HangarConfig, OidcIntrospectionAuth } from "./types.js";

const DEFAULT_BASE_URL = "https://hangar.getdumont.ai";
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
const API_KEY_PATTERN = /^plane_api_[0-9a-f]{32}$/;
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

function parseAllowedProjects(env: NodeJS.ProcessEnv): string[] {
  const values = parseCsv(env, "HANGAR_ALLOWED_PROJECTS");
  if (values.length === 0) {
    throw new HangarConfigError("HANGAR_ALLOWED_PROJECTS is required");
  }
  const normalized = values.map((value) => {
    if (PROJECT_UUID_PATTERN.test(value)) return value.toLowerCase();
    const identifier = value.toUpperCase();
    if (PROJECT_IDENTIFIER_PATTERN.test(identifier)) return identifier;
    throw new HangarConfigError(
      "HANGAR_ALLOWED_PROJECTS must contain only project identifiers (like HGR) or project UUIDs"
    );
  });
  return [...new Set(normalized)];
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
  const apiKey = env.HANGAR_API_KEY?.trim() ?? "";
  if (!API_KEY_PATTERN.test(apiKey)) {
    throw new HangarConfigError(
      "HANGAR_API_KEY is required and must be a Hangar API token (plane_api_ followed by 32 lowercase hexadecimal characters)"
    );
  }

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
  const oidcRequiredRole = parseOptionalToken(env, "MCP_OIDC_REQUIRED_ROLE") || "hangar_reader";
  if (/\s/.test(oidcRequiredRole)) {
    throw new HangarConfigError("MCP_OIDC_REQUIRED_ROLE must not contain whitespace");
  }
  const oidcRequiredScope = parseOidcScope(env, `urn:zitadel:iam:org:project:role:${oidcRequiredRole}`);
  const oidcAllowedOrgId = parseOptionalToken(env, "MCP_OIDC_ALLOWED_ORG_ID");
  const oidcAllowedSubjects = parseCsv(env, "MCP_OIDC_ALLOWED_SUBJECTS");
  const introspection = parseIntrospection(env, oidcIssuer);

  if (!oidcIssuer) throw new HangarConfigError("MCP_OIDC_ISSUER is required");
  if (!oidcJwksUrl) throw new HangarConfigError("MCP_OIDC_JWKS_URL is required");
  if (!resourceUrl) throw new HangarConfigError("MCP_RESOURCE_URL is required");
  parseOidcAudience(env);

  return {
    baseUrl: validateBaseUrl(env.HANGAR_BASE_URL?.trim() || DEFAULT_BASE_URL),
    apiKey,
    workspaceSlug: parseWorkspaceSlug(env),
    allowedProjects: parseAllowedProjects(env),
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
    oidcRequiredRole,
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
  if (!config.oidcIssuer || !config.oidcJwksUrl || !config.oidcAudience || !config.resourceUrl) {
    throw new HangarConfigError("OIDC configuration is incomplete for Streamable HTTP");
  }
}

export function isApiKey(value: string): boolean {
  return API_KEY_PATTERN.test(value);
}
