import { describe, expect, it } from "vitest";
import { HangarConfigError, assertHttpAuthConfigured, isApiKey, loadHangarConfig } from "../src/config.js";

const VALID_KEY = "plane_api_" + "a".repeat(32);

function env(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    HANGAR_API_KEY: VALID_KEY,
    HANGAR_WORKSPACE_SLUG: "dumont",
    HANGAR_ALLOWED_PROJECTS: "HGR",
    MCP_OIDC_ISSUER: "https://auth.getdumont.ai",
    MCP_OIDC_JWKS_URL: "https://auth.getdumont.ai/oauth/v2/keys",
    MCP_RESOURCE_URL: "https://hangar.getdumont.ai/mcp",
    MCP_OIDC_AUDIENCE: "390213468206137347",
    ...overrides,
  };
}

describe("Hangar configuration", () => {
  it("loads a valid OIDC-only configuration with safe defaults", () => {
    const config = loadHangarConfig(env());
    expect(config.baseUrl.toString()).toBe("https://hangar.getdumont.ai/");
    expect(config.workspaceSlug).toBe("dumont");
    expect(config.allowedProjects).toEqual(["HGR"]);
    expect(config.oidcRequiredRole).toBe("hangar_reader");
    expect(config.oidcRequiredScope).toBe("urn:zitadel:iam:org:project:role:hangar_reader");
    expect(isApiKey(config.apiKey)).toBe(true);
  });

  it("fails closed without a well-formed API key", () => {
    expect(() => loadHangarConfig(env({ HANGAR_API_KEY: undefined }))).toThrow(HangarConfigError);
    expect(() => loadHangarConfig(env({ HANGAR_API_KEY: "plane_api_" + "A".repeat(32) }))).toThrow(HangarConfigError);
    expect(() => loadHangarConfig(env({ HANGAR_API_KEY: "a".repeat(41) }))).toThrow(HangarConfigError);
  });

  it("requires a workspace slug and an explicit project allowlist", () => {
    expect(() => loadHangarConfig(env({ HANGAR_WORKSPACE_SLUG: "Dumont" }))).toThrow(HangarConfigError);
    expect(() => loadHangarConfig(env({ HANGAR_ALLOWED_PROJECTS: undefined }))).toThrow(HangarConfigError);
    expect(() => loadHangarConfig(env({ HANGAR_ALLOWED_PROJECTS: "HGR, not a project!" }))).toThrow(HangarConfigError);
  });

  it("normalizes identifiers to uppercase and keeps project UUIDs", () => {
    const config = loadHangarConfig(
      env({
        HANGAR_ALLOWED_PROJECTS: "hgr, ac913f1a-fa7f-4c98-848b-b0ae826f7117",
      })
    );
    expect(config.allowedProjects).toEqual(["HGR", "ac913f1a-fa7f-4c98-848b-b0ae826f7117"]);
  });

  it("rejects insecure base URLs", () => {
    expect(() => loadHangarConfig(env({ HANGAR_BASE_URL: "http://hangar.getdumont.ai" }))).toThrow(HangarConfigError);
    expect(() => loadHangarConfig(env({ HANGAR_BASE_URL: "https://user:pass@hangar.getdumont.ai" }))).toThrow(
      HangarConfigError
    );
    expect(loadHangarConfig(env({ HANGAR_BASE_URL: "http://127.0.0.1:8080" })).baseUrl.port).toBe("8080");
  });

  it("fails closed when OIDC mode is incomplete and validates the role scope", () => {
    const oidc = {
      MCP_AUTH_MODE: "oidc",
      MCP_OIDC_ISSUER: "https://auth.getdumont.ai",
      MCP_OIDC_JWKS_URL: "https://auth.getdumont.ai/oauth/v2/keys",
      MCP_RESOURCE_URL: "https://hangar.getdumont.ai/mcp",
      MCP_OIDC_AUDIENCE: "390213468206137347",
    };
    const config = loadHangarConfig(env(oidc));
    expect(() => assertHttpAuthConfigured(config)).not.toThrow();
    expect(() => loadHangarConfig(env({ ...oidc, MCP_OIDC_REQUIRED_SCOPE: "two scopes" }))).toThrow(HangarConfigError);
    for (const missing of ["MCP_OIDC_ISSUER", "MCP_OIDC_JWKS_URL", "MCP_RESOURCE_URL", "MCP_OIDC_AUDIENCE"]) {
      expect(() => loadHangarConfig(env({ ...oidc, [missing]: undefined }))).toThrow(HangarConfigError);
    }
    expect(() => assertHttpAuthConfigured(loadHangarConfig(env()))).not.toThrow();
  });

  it("rejects the retired static MCP credential even with valid OIDC settings", () => {
    expect(() => loadHangarConfig(env({ MCP_AUTH_MODE: "static", MCP_AUTH_TOKEN: "old-token" }))).toThrow(/retired/);
    expect(() => loadHangarConfig(env({ MCP_AUTH_TOKEN: "old-token" }))).toThrow(/retired/);
    expect(() => loadHangarConfig(env({ MCP_AUTH_MODE: "oidc" }))).not.toThrow();
  });

  it("requires introspection credentials to pair with a same-origin URL", () => {
    const oidc = {
      MCP_AUTH_MODE: "oidc",
      MCP_OIDC_ISSUER: "https://auth.getdumont.ai",
      MCP_OIDC_JWKS_URL: "https://auth.getdumont.ai/oauth/v2/keys",
      MCP_RESOURCE_URL: "https://hangar.getdumont.ai/mcp",
      MCP_OIDC_AUDIENCE: "390213468206137347",
    };
    expect(() =>
      loadHangarConfig(
        env({
          ...oidc,
          MCP_OIDC_INTROSPECTION_CLIENT_SECRET: "secret",
        })
      )
    ).toThrow(HangarConfigError);
    expect(() =>
      loadHangarConfig(
        env({
          ...oidc,
          MCP_OIDC_INTROSPECTION_URL: "https://auth.getdumont.ai/oauth/v2/introspect",
          MCP_OIDC_INTROSPECTION_CLIENT_ID: "client-1",
          MCP_OIDC_INTROSPECTION_CLIENT_SECRET: "secret",
          MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON: '{"type":"application"}',
        })
      )
    ).toThrow(HangarConfigError);
    expect(() =>
      loadHangarConfig(
        env({
          ...oidc,
          MCP_OIDC_INTROSPECTION_URL: "https://another.example.test/oauth/v2/introspect",
          MCP_OIDC_INTROSPECTION_CLIENT_ID: "client-1",
          MCP_OIDC_INTROSPECTION_CLIENT_SECRET: "secret",
        })
      )
    ).toThrow(HangarConfigError);
    const config = loadHangarConfig(
      env({
        ...oidc,
        MCP_OIDC_INTROSPECTION_URL: "https://auth.getdumont.ai/oauth/v2/introspect",
        MCP_OIDC_INTROSPECTION_CLIENT_ID: "client-1",
        MCP_OIDC_INTROSPECTION_CLIENT_SECRET: "secret",
      })
    );
    expect(config.oidcIntrospectionAuth).toMatchObject({ method: "client_secret_basic", clientId: "client-1" });
  });

  it("requires allowed hosts for a non-loopback bind", () => {
    expect(() => loadHangarConfig(env({ MCP_HTTP_HOST: "0.0.0.0" }))).toThrow(HangarConfigError);
    expect(() =>
      loadHangarConfig(env({ MCP_HTTP_HOST: "0.0.0.0", MCP_ALLOWED_HOSTS: "hangar.getdumont.ai" }))
    ).not.toThrow();
  });
});
