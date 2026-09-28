import type { KeyObject } from "node:crypto";

export type JsonRecord = Record<string, unknown>;

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
  /** Subset of allowedProjects where write tools may act. Empty = writes disabled. */
  readonly writeProjects: readonly string[];
  /** Per-subject write tool calls allowed per fixed 60 s window. */
  readonly writeRateLimit: number;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly maxSearchPages: number;
  readonly projectCacheSeconds: number;
  readonly httpPort: number;
  readonly httpHost: string;
  readonly allowedOrigins: readonly string[];
  readonly allowedHosts: readonly string[];
  readonly oidcIssuer: URL | null;
  readonly oidcJwksUrl: URL | null;
  readonly oidcAudience: string;
  /**
   * Scope that must be literally present on the token. When it is the ZITADEL
   * reserved role scope of the reader or writer role (the default), the role
   * claim is checked instead, because ZITADEL does not echo reserved scopes.
   */
  readonly oidcRequiredScope: string;
  /** Role that grants the read tools (MCP_OIDC_READER_ROLE, legacy MCP_OIDC_REQUIRED_ROLE). */
  readonly oidcReaderRole: string;
  /** Role that grants the write tools and implies the reader role. */
  readonly oidcWriterRole: string;
  /** Scopes advertised in protected-resource metadata and in the 401/403 challenge. */
  readonly oidcScopesSupported: readonly string[];
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

/**
 * The verified caller of one MCP HTTP request. `roles` holds only the
 * configured Hangar roles (reader and/or writer) the token actually carries.
 * `email` is null when the token has no (verified) email claim.
 */
export interface Principal {
  readonly sub: string;
  readonly email: string | null;
  readonly roles: readonly string[];
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
