import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthorizer, MIN_TOKEN_LIFETIME_SECONDS } from "../src/auth.js";
import { createHangarHttpServer } from "../src/http.js";
import { SELF_CHECK_TOKEN } from "../src/introspection.js";
import { hangarFetch, jsonResponse, testConfig } from "./fixtures.js";

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

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  openServers.push(server);
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("server did not bind");
  return address.port;
}

function callTool(port: number, token: string): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
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
    // Passed introspection and the claims policy: forwarded to Hangar verbatim.
    expect(result.upstreamToken).toBe(SELF_CHECK_TOKEN);
    expect(result.expiresAt).toBe(activeClaims().exp);
    expect(calls[0]?.pathname).toBe("/oauth/v2/introspect");
  });

  it("forwards an introspected opaque token verbatim to Hangar as Authorization: Bearer", async () => {
    const hangarCalls: URL[] = [];
    const authorizations: Array<string | undefined> = [];
    const fake = hangarFetch(hangarCalls);
    const server = createHangarHttpServer(
      introspectionConfig(),
      undefined,
      { fetch: async () => jsonResponse(activeClaims()) },
      {
        fetch: async (input, init) => {
          const headers = (init?.headers ?? {}) as Record<string, string>;
          authorizations.push(headers.Authorization);
          expect(Object.keys(headers).map((name) => name.toLowerCase())).not.toContain("x-api-key");
          return fake(input, init);
        },
      }
    );
    const response = await callTool(await listen(server), SELF_CHECK_TOKEN);
    expect(response.status).toBe(200);
    const payload = (await response.json()) as { result: { isError?: boolean } };
    expect(payload.result.isError).not.toBe(true);
    expect(hangarCalls.length).toBeGreaterThan(0);
    expect(authorizations.length).toBe(hangarCalls.length);
    for (const authorization of authorizations) expect(authorization).toBe(`Bearer ${SELF_CHECK_TOKEN}`);
  });

  it("never forwards a token that failed introspection or the claims policy", async () => {
    const outcomes: Array<[string, () => Response, number]> = [
      ["inactive", () => jsonResponse({ active: false }), 401],
      ["introspection error", () => jsonResponse({ error: "server_error" }, 500), 401],
      ["another audience", () => jsonResponse(activeClaims({ aud: "another-project" })), 401],
      ["another issuer", () => jsonResponse(activeClaims({ iss: "https://other-issuer.example.test" })), 401],
      ["ID token type", () => jsonResponse(activeClaims({ token_type: "id_token" })), 401],
      [
        "near expiry",
        () => jsonResponse(activeClaims({ exp: Math.floor(Date.now() / 1000) + MIN_TOKEN_LIFETIME_SECONDS })),
        401,
      ],
      ["no role", () => jsonResponse(activeClaims({ "urn:zitadel:iam:org:project:roles": {} })), 403],
      [
        "role in a foreign org",
        () =>
          jsonResponse(
            activeClaims({
              "urn:zitadel:iam:org:project:roles": { hangar_reader: { "foreign-org": "foreign.example.test" } },
            })
          ),
        403,
      ],
    ];
    for (const [label, introspection, status] of outcomes) {
      const hangarCalls: string[] = [];
      const server = createHangarHttpServer(
        introspectionConfig(),
        undefined,
        { fetch: async () => introspection() },
        {
          fetch: async (input) => {
            hangarCalls.push(String(input));
            return jsonResponse({});
          },
        }
      );
      // oxlint-disable-next-line no-await-in-loop
      const response = await callTool(await listen(server), SELF_CHECK_TOKEN);
      expect({ label, status: response.status }).toEqual({ label, status });
      expect({ label, hangarCalls }).toEqual({ label, hangarCalls: [] });
    }
  });

  it("applies the near-expiry rule to the introspection exp", async () => {
    const nowMs = Date.now();
    const nowSeconds = Math.floor(nowMs / 1000);
    const authorizeWithExp = (exp: number) =>
      createAuthorizer(introspectionConfig(), {
        now: () => nowMs,
        fetch: async () => jsonResponse(activeClaims({ exp })),
      })(request(SELF_CHECK_TOKEN));
    expect((await authorizeWithExp(nowSeconds + MIN_TOKEN_LIFETIME_SECONDS)).failure).toBe("invalid_credentials");
    expect((await authorizeWithExp(nowSeconds + 1)).failure).toBe("invalid_credentials");
    const fresh = await authorizeWithExp(nowSeconds + MIN_TOKEN_LIFETIME_SECONDS + 1);
    expect(fresh).toMatchObject({ failure: null, upstreamToken: SELF_CHECK_TOKEN });

    const withoutExp = createAuthorizer(introspectionConfig(), {
      fetch: async () => {
        const { exp: _exp, ...claims } = activeClaims();
        return jsonResponse(claims);
      },
    });
    expect((await withoutExp(request(SELF_CHECK_TOKEN))).failure).toBe("invalid_credentials");
  });

  it("maps Hangar's answers to an opaque token like those to a JWS", async () => {
    const upstream: Array<[number, Record<string, unknown>, Record<string, string>, string, boolean]> = [
      [503, { error_code: "DUMONT_AUTH_UNAVAILABLE", error: "x" }, {}, "UPSTREAM_AUTH_UNAVAILABLE", true],
      [
        401,
        { error_code: "DUMONT_INVALID_TOKEN", error: "x" },
        { "www-authenticate": 'Bearer realm="api", error="invalid_token"' },
        "UPSTREAM_UNAUTHORIZED",
        false,
      ],
      [401, { error_code: "DUMONT_ACCOUNT_NOT_LINKED", error: "x" }, {}, "ACCOUNT_NOT_LINKED", false],
      [403, { error_code: "DUMONT_USER_NOT_ALLOWED", error: "x" }, {}, "USER_NOT_ALLOWED", false],
    ];
    for (const [status, body, headers, code, retryable] of upstream) {
      const server = createHangarHttpServer(
        introspectionConfig(),
        undefined,
        { fetch: async () => jsonResponse(activeClaims()) },
        {
          fetch: async () => {
            const response = jsonResponse(body, status);
            for (const [name, value] of Object.entries(headers)) response.headers.set(name, value);
            return response;
          },
        }
      );
      // oxlint-disable-next-line no-await-in-loop
      const response = await callTool(await listen(server), SELF_CHECK_TOKEN);
      // Never this MCP's 401/403: that would restart the client's login loop.
      expect(response.status).toBe(200);
      expect(response.headers.get("www-authenticate")).toBeNull();
      // oxlint-disable-next-line no-await-in-loop
      const payload = (await response.json()) as { result: { isError: boolean; structuredContent: unknown } };
      expect(payload.result.isError).toBe(true);
      expect(payload.result.structuredContent).toMatchObject({ error: { code, retryable } });
    }
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
