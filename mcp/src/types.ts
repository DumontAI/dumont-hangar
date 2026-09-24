import type { KeyObject } from "node:crypto";

export type JsonRecord = Record<string, unknown>;

export type McpAuthMode = "static" | "oidc";

export type OidcIntrospectionAuth =
  | {
      readonly method: "client_secret_basic";
      readonly clientId: string;
      readonly clientSecret: string;
    }
  | {
      readonly method: "private_key_jwt";
      readonly clientId: string;
      readonly keyId: string;
      readonly privateKey: KeyObject;
    };

export interface HangarConfig {
  readonly baseUrl: URL;
  readonly apiKey: string;
  readonly workspaceSlug: string;
  readonly allowedProjects: readonly string[];
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly maxSearchPages: number;
  readonly projectCacheSeconds: number;
  readonly httpPort: number;
  readonly httpHost: string;
  readonly authMode: McpAuthMode;
  readonly mcpAuthToken: string;
  readonly allowedOrigins: readonly string[];
  readonly allowedHosts: readonly string[];
  readonly oidcIssuer: URL | null;
  readonly oidcJwksUrl: URL | null;
  readonly oidcAudience: string;
  readonly oidcRequiredScope: string;
  readonly oidcRequiredRole: string;
  readonly oidcAllowedOrgId: string;
  readonly oidcAllowedSubjects: readonly string[];
  readonly resourceUrl: URL | null;
  readonly oidcIntrospectionUrl: URL | null;
  readonly oidcIntrospectionAuth: OidcIntrospectionAuth | null;
  readonly oidcIntrospectionTimeoutMs: number;
  readonly oidcIntrospectionCacheSeconds: number;
  readonly oidcIntrospectionMaxInFlight: number;
  readonly oidcIntrospectionRatePerSecond: number;
}

export interface HangarPage<T> {
  readonly results: T[];
  readonly nextCursor: string | null;
}

export class HangarError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly retryable = false
  ) {
    super(message);
    this.name = "HangarError";
  }
}

export type ResourceName =
  | "projects"
  | "work_items"
  | "search_work_items"
  | "comments"
  | "states"
  | "labels"
  | "members";

export interface RawPage {
  readonly results: JsonRecord[];
  readonly nextCursor: string | null;
}
