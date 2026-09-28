import { describe, expect, it } from "vitest";
import { createAuthorizer } from "../src/auth.js";
import { SELF_CHECK_TOKEN } from "../src/introspection.js";
import { jsonResponse, testConfig } from "./fixtures.js";

const ISSUER = "https://issuer.example.test";
const AUDIENCE = "hangar-mcp-project";
const ROLE_SCOPE = "urn:zitadel:iam:org:project:role:hangar_reader";

function introspectionConfig() {
  return testConfig({
    oidcIssuer: new URL(ISSUER),
    oidcJwksUrl: new URL(`${ISSUER}/oauth/v2/keys`),
    oidcAudience: AUDIENCE,
    oidcRequiredScope: ROLE_SCOPE,
    oidcReaderRole: "hangar_reader",
    oidcAllowedOrgId: "",
    oidcAllowedSubjects: [],
    resourceUrl: new URL("https://mcp-hangar.example.test/mcp"),
    oidcIntrospectionUrl: new URL(`${ISSUER}/oauth/v2/introspect`),
    oidcIntrospectionAuth: { method: "client_secret_basic", clientId: "introspector", clientSecret: "test-secret" },
    oidcIntrospectionCacheSeconds: 30,
  });
}

function activeClaims(overrides: Record<string, unknown> = {}) {
  return {
    active: true,
    sub: "user-1",
    iss: ISSUER,
    aud: AUDIENCE,
    exp: Math.floor(Date.now() / 1000) + 300,
    iat: Math.floor(Date.now() / 1000),
    scope: ROLE_SCOPE,
    "urn:zitadel:iam:org:project:roles": { hangar_reader: { "dumont-org": "dumont.example.test" } },
    ...overrides,
  };
}

function request(token: string) {
  return { headers: { host: "127.0.0.1", authorization: `Bearer ${token}` } } as never;
}

describe("opaque token introspection", () => {
  it("accepts an active opaque token and binds the subject from the introspection response", async () => {
    const calls: URL[] = [];
    const authorize = createAuthorizer(introspectionConfig(), {
      fetch: async (input) => {
        calls.push(new URL(String(input)));
        return jsonResponse(activeClaims());
      },
    });
    const result = await authorize(request(SELF_CHECK_TOKEN));
    expect(result).toMatchObject({ failure: null, subject: "user-1" });
    expect(calls[0]?.pathname).toBe("/oauth/v2/introspect");
  });

  it("rejects inactive and errored introspection outcomes", async () => {
    const inactive = createAuthorizer(introspectionConfig(), {
      fetch: async () => jsonResponse({ active: false }),
    });
    expect((await inactive(request(SELF_CHECK_TOKEN))).failure).toBe("invalid_credentials");

    const errored = createAuthorizer(introspectionConfig(), {
      fetch: async () => jsonResponse({ error: "server_error" }, 500),
    });
    expect((await errored(request(SELF_CHECK_TOKEN))).failure).toBe("invalid_credentials");
  });

  it("enforces the same claims policy on introspected tokens", async () => {
    const withoutRole = createAuthorizer(introspectionConfig(), {
      fetch: async () => jsonResponse(activeClaims({ "urn:zitadel:iam:org:project:roles": {} })),
    });
    expect((await withoutRole(request(SELF_CHECK_TOKEN))).failure).toBe("insufficient_scope");

    const wrongAudience = createAuthorizer(introspectionConfig(), {
      fetch: async () => jsonResponse(activeClaims({ aud: "another-project" })),
    });
    expect((await wrongAudience(request(SELF_CHECK_TOKEN))).failure).toBe("invalid_credentials");
  });

  it("never introspects JWS-shaped tokens and caches repeated introspection results", async () => {
    const calls: string[] = [];
    const fetcher = async (input: string | URL) => {
      calls.push(String(input));
      return jsonResponse(activeClaims());
    };
    const authorize = createAuthorizer(introspectionConfig(), { fetch: fetcher });
    const jwsShaped = [
      Buffer.from(JSON.stringify({ alg: "RS256", kid: "k1" })).toString("base64url"),
      Buffer.from(JSON.stringify({ sub: "user-1" })).toString("base64url"),
      "signature",
    ].join(".");
    expect((await authorize(request(jwsShaped))).failure).toBe("invalid_credentials");
    expect(calls).toHaveLength(0);

    expect(await authorize(request(SELF_CHECK_TOKEN))).toMatchObject({ failure: null, subject: "user-1" });
    expect(await authorize(request(SELF_CHECK_TOKEN))).toMatchObject({ failure: null, subject: "user-1" });
    expect(calls).toHaveLength(1);
  });
});
