import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthorizer } from "../src/auth.js";
import { createHangarHttpServer } from "../src/http.js";
import { SELF_CHECK_TOKEN } from "../src/introspection.js";
import { jsonResponse, testConfig } from "./fixtures.js";

const openServers: Server[] = [];
afterEach(async () => {
  await Promise.all(openServers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))));
});

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
    oidcAllowedOrgId: "dumont-org",
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
    // Valid for this MCP, but never forwarded to Hangar (Hangar accepts only JWTs).
    expect(result.upstreamToken).toBeNull();
    expect(calls[0]?.pathname).toBe("/oauth/v2/introspect");
  });

  it("answers tool calls made with an opaque token with TOKEN_NOT_FORWARDABLE and never calls Hangar", async () => {
    const hangarCalls: string[] = [];
    const server = createHangarHttpServer(
      introspectionConfig(),
      undefined,
      { fetch: async () => jsonResponse(activeClaims()) },
      {
        fetch: async (input) => {
          hangarCalls.push(String(input));
          return jsonResponse({});
        },
      }
    );
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    openServers.push(server);
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("server did not bind");
    const response = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${SELF_CHECK_TOKEN}`,
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "hangar_list_projects", arguments: { limit: 1 } },
      }),
    });
    expect(response.status).toBe(200);
    const payload = (await response.json()) as { result: { isError: boolean; structuredContent: unknown } };
    expect(payload.result.isError).toBe(true);
    expect(payload.result.structuredContent).toMatchObject({ error: { code: "TOKEN_NOT_FORWARDABLE" } });
    expect(hangarCalls).toHaveLength(0);
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

    // Same organization binding as the JWS path: a role granted in another org is refused.
    const foreignOrg = createAuthorizer(introspectionConfig(), {
      fetch: async () =>
        jsonResponse(
          activeClaims({
            "urn:zitadel:iam:org:project:roles": { hangar_reader: { "foreign-org": "foreign.example.test" } },
            "urn:zitadel:iam:user:resourceowner:id": "dumont-org",
          })
        ),
    });
    expect((await foreignOrg(request(SELF_CHECK_TOKEN))).failure).toBe("insufficient_scope");

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
