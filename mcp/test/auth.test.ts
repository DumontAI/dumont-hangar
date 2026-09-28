import { createServer, type Server } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthorizer, protectedResourceMetadata } from "../src/auth.js";
import { HangarClient } from "../src/client.js";
import { createHangarHttpServer } from "../src/http.js";
import { createHangarServer } from "../src/tools.js";
import type { AuditRecord } from "../src/access.js";
import { hangarFetch, jsonResponse, meUserIdFor, PROJECT_HGR, testConfig } from "./fixtures.js";

const openServers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    openServers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => {
            if (error) reject(error);
            else resolve();
          });
        })
    )
  );
});

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) =>
    server.listen(0, "127.0.0.1", (error) => {
      if (error) reject(error);
      else resolve();
    })
  );
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("server did not bind");
  openServers.push(server);
  return address.port;
}

async function setupOidc() {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  const keyId = "test-key";
  const jwksServer = createServer((req, res) => {
    if (req.url !== "/jwks") {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ keys: [{ ...jwk, kid: keyId, alg: "RS256", use: "sig" }] }));
  });
  const jwksPort = await listen(jwksServer);
  const issuer = new URL("https://issuer.example.test");
  const roleScope = "urn:zitadel:iam:org:project:role:hangar_reader";
  const config = testConfig({
    allowedHosts: [],
    oidcIssuer: issuer,
    oidcJwksUrl: new URL(`http://127.0.0.1:${jwksPort}/jwks`),
    oidcAudience: "hangar-mcp-project",
    oidcRequiredScope: roleScope,
    oidcReaderRole: "hangar_reader",
    oidcWriterRole: "hangar_writer",
    oidcAllowedOrgId: "dumont-org",
    oidcAllowedSubjects: [],
    resourceUrl: new URL("https://mcp-hangar.example.test/mcp"),
  });
  const token = (
    overrides: Record<string, unknown> = {},
    audience = "hangar-mcp-project",
    tokenIssuer = issuer.origin,
    expiration = "5m"
  ) =>
    new SignJWT({
      scope: roleScope,
      "urn:zitadel:iam:org:project:roles": { hangar_reader: { "dumont-org": "dumont.example.test" } },
      ...overrides,
    })
      .setProtectedHeader({ alg: "RS256", kid: keyId })
      .setIssuer(tokenIssuer)
      .setAudience(audience)
      .setSubject(typeof overrides.sub === "string" ? overrides.sub : "user-1")
      .setIssuedAt()
      .setExpirationTime(expiration)
      .sign(privateKey);
  return { config, token };
}

describe("OIDC authorization", () => {
  it("publishes protected resource metadata for MCP clients", async () => {
    const { config } = await setupOidc();
    expect(protectedResourceMetadata(config)).toEqual({
      resource: "https://mcp-hangar.example.test/mcp",
      authorization_servers: ["https://issuer.example.test"],
      scopes_supported: [
        "openid",
        "email",
        "urn:zitadel:iam:org:project:role:hangar_reader",
        "urn:zitadel:iam:org:project:role:hangar_writer",
      ],
      bearer_methods_supported: ["header"],
    });
  });

  it("accepts a correctly bound access token and rejects a wrong audience", async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    const validRequest = { headers: { host: "127.0.0.1", authorization: `Bearer ${await token()}` } } as never;
    expect(await authorize(validRequest)).toMatchObject({ failure: null, subject: "user-1" });

    const wrongAudience = await token({}, "another-project");
    const invalidRequest = { headers: { host: "127.0.0.1", authorization: `Bearer ${wrongAudience}` } } as never;
    expect((await authorize(invalidRequest)).failure).toBe("invalid_credentials");

    const wrongIssuer = await token({}, "hangar-mcp-project", "https://another-issuer.example.test");
    const issuerRequest = { headers: { host: "127.0.0.1", authorization: `Bearer ${wrongIssuer}` } } as never;
    expect((await authorize(issuerRequest)).failure).toBe("invalid_credentials");

    const expired = await token({}, "hangar-mcp-project", "https://issuer.example.test", "0s");
    const expiredRequest = { headers: { host: "127.0.0.1", authorization: `Bearer ${expired}` } } as never;
    expect((await authorize(expiredRequest)).failure).toBe("invalid_credentials");

    // Valid but with 30 s or less left: 401 now, so the client refreshes
    // before the token is forwarded to Hangar.
    const expiring = await token({}, "hangar-mcp-project", "https://issuer.example.test", "20s");
    const expiringRequest = { headers: { host: "127.0.0.1", authorization: `Bearer ${expiring}` } } as never;
    expect((await authorize(expiringRequest)).failure).toBe("invalid_credentials");
    const fresh = await token({}, "hangar-mcp-project", "https://issuer.example.test", "45s");
    const freshRequest = { headers: { host: "127.0.0.1", authorization: `Bearer ${fresh}` } } as never;
    expect((await authorize(freshRequest)).failure).toBeNull();
  });

  it("rejects ID tokens (nonce or at_hash) on the JWS path", async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    const idTokens = await Promise.all([{ nonce: "n-1" }, { at_hash: "abc" }].map((claims) => token(claims)));
    const outcomes = await Promise.all(
      idTokens.map((idToken) => {
        const request = { headers: { host: "127.0.0.1", authorization: `Bearer ${idToken}` } } as never;
        return authorize(request);
      })
    );
    for (const outcome of outcomes) {
      expect(outcome.failure).toBe("invalid_credentials");
    }
  });

  it("accepts the ZITADEL role claim when the reserved role scope is not echoed", async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    const zitadelToken = await token({ scope: "openid" });
    const request = { headers: { host: "127.0.0.1", authorization: `Bearer ${zitadelToken}` } } as never;
    expect(await authorize(request)).toMatchObject({ failure: null, subject: "user-1" });
  });

  it("accepts reader-only and writer-only tokens and hands roles and the forwardable token to the tools", async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    const request = async (claims: Record<string, unknown>) => {
      const bearer = await token(claims);
      return {
        bearer,
        outcome: await authorize({ headers: { host: "127.0.0.1", authorization: `Bearer ${bearer}` } } as never),
      };
    };

    const reader = await request({});
    expect(reader.outcome).toMatchObject({ failure: null, principal: { sub: "user-1", roles: ["hangar_reader"] } });
    // The verified JWS itself is what gets forwarded to Hangar, with its exp.
    expect(reader.outcome.upstreamToken).toBe(reader.bearer);
    expect(reader.outcome.expiresAt).toBeGreaterThan(Date.now() / 1000);
    expect(reader.outcome.principal).not.toHaveProperty("email");
    expect(
      (
        await request({
          "urn:zitadel:iam:org:project:roles": { hangar_writer: { "dumont-org": "dumont.example.test" } },
        })
      ).outcome
    ).toMatchObject({ failure: null, principal: { roles: ["hangar_writer"] } });
    expect(
      (
        await request({
          "urn:zitadel:iam:org:project:roles": {
            hangar_reader: { "dumont-org": "d" },
            hangar_writer: { "dumont-org": "d" },
          },
        })
      ).outcome
    ).toMatchObject({ failure: null, principal: { roles: ["hangar_reader", "hangar_writer"] } });
    const denied = (await request({ "urn:zitadel:iam:org:project:roles": { some_other_role: { "dumont-org": "d" } } }))
      .outcome;
    expect(denied.failure).toBe("insufficient_scope");
    expect(denied.upstreamToken).toBeUndefined();
  });

  it("accepts my:zitadel:grants only as <audience project>:<role>", async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    const rolesOf = async (grants: unknown) => {
      const outcome = await authorize({
        headers: {
          host: "127.0.0.1",
          authorization: `Bearer ${await token({ "urn:zitadel:iam:org:project:roles": {}, "urn:zitadel:iam:user:resourceowner:id": "dumont-org", "my:zitadel:grants": grants })}`,
        },
      } as never);
      return outcome.failure ?? outcome.principal?.roles;
    };
    expect(await rolesOf(["hangar-mcp-project:hangar_writer"])).toEqual(["hangar_writer"]);
    expect(await rolesOf(["hangar_writer"])).toBe("insufficient_scope");
    expect(await rolesOf(["other-project:hangar_writer"])).toBe("insufficient_scope");
    expect(await rolesOf(["x:hangar-mcp-project:hangar_writer"])).toBe("insufficient_scope");
    expect(await rolesOf("hangar-mcp-project:hangar_writer")).toBe("insufficient_scope");
  });

  it("accepts the project-scoped ZITADEL role claim only for the audience project", async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    const outcome = async (claims: Record<string, unknown>) =>
      authorize({
        headers: {
          host: "127.0.0.1",
          authorization: `Bearer ${await token({ "urn:zitadel:iam:org:project:roles": {}, "urn:zitadel:iam:user:resourceowner:id": "dumont-org", ...claims })}`,
        },
      } as never);
    expect(
      (
        await outcome({
          "urn:zitadel:iam:org:project:hangar-mcp-project:roles": { hangar_writer: { "dumont-org": "d" } },
        })
      ).principal?.roles
    ).toEqual(["hangar_writer"]);
    expect(
      (await outcome({ "urn:zitadel:iam:org:project:other-project:roles": { hangar_writer: { "dumont-org": "d" } } }))
        .failure
    ).toBe("insufficient_scope");
  });

  describe("binds every role to MCP_OIDC_ALLOWED_ORG_ID (shared ZITADEL instance)", () => {
    const rolesFor = async (claims: Record<string, unknown>) => {
      const { config, token } = await setupOidc();
      const authorize = createAuthorizer(config);
      const outcome = await authorize({
        headers: {
          host: "127.0.0.1",
          authorization: `Bearer ${await token({ "urn:zitadel:iam:org:project:roles": undefined, ...claims })}`,
        },
      } as never);
      return outcome.failure ?? outcome.principal?.roles;
    };

    it("refuses a role map granted in a foreign organization, with our audience", async () => {
      for (const claimName of [
        "urn:zitadel:iam:org:project:hangar-mcp-project:roles",
        "urn:zitadel:iam:org:project:roles",
      ]) {
        // oxlint-disable-next-line no-await-in-loop
        expect(await rolesFor({ [claimName]: { hangar_writer: { "foreign-org": "foreign.example.test" } } })).toBe(
          "insufficient_scope"
        );
        // Belonging to our org does not rescue a role map granted elsewhere.
        expect(
          // oxlint-disable-next-line no-await-in-loop
          await rolesFor({
            [claimName]: { hangar_writer: { "foreign-org": "foreign.example.test" } },
            "urn:zitadel:iam:user:resourceowner:id": "dumont-org",
          })
        ).toBe("insufficient_scope");
      }
    });

    it("refuses role maps whose org entry is not an object keyed by our org id", async () => {
      const claim = "urn:zitadel:iam:org:project:roles";
      expect(await rolesFor({ [claim]: { hangar_writer: ["dumont-org"] } })).toBe("insufficient_scope");
      expect(await rolesFor({ [claim]: { hangar_writer: "dumont-org" } })).toBe("insufficient_scope");
      expect(await rolesFor({ [claim]: { hangar_writer: { "foreign-org": "dumont-org" } } })).toBe(
        "insufficient_scope"
      );
      expect(await rolesFor({ [claim]: { hangar_writer: null } })).toBe("insufficient_scope");
    });

    it("does not make our-org guest plus a foreign hangar_writer a writer", async () => {
      const claim = "urn:zitadel:iam:org:project:roles";
      expect(
        await rolesFor({
          [claim]: {
            "hangar.project.hgr.guest": { "dumont-org": "dumont.example.test" },
            hangar_writer: { "foreign-org": "foreign.example.test" },
          },
          "urn:zitadel:iam:user:resourceowner:id": "dumont-org",
        })
      ).toBe("insufficient_scope");
      expect(
        await rolesFor({
          [claim]: {
            hangar_reader: { "dumont-org": "dumont.example.test" },
            hangar_writer: { "foreign-org": "foreign.example.test" },
          },
        })
      ).toEqual(["hangar_reader"]);
    });

    it("counts array forms, legacy roles and my:zitadel:grants only for users of our organization", async () => {
      const unbound = [
        { roles: ["hangar_writer"] },
        { roles: { hangar_writer: {} } },
        { "urn:zitadel:iam:org:project:roles": ["hangar_writer"] },
        { "urn:zitadel:iam:org:project:hangar-mcp-project:roles": ["hangar_writer"] },
        { "my:zitadel:grants": ["hangar-mcp-project:hangar_writer"] },
      ];
      for (const claims of unbound) {
        // No resourceowner, a foreign one, or only org_id: refused.
        // oxlint-disable-next-line no-await-in-loop
        expect(await rolesFor(claims)).toBe("insufficient_scope");
        // oxlint-disable-next-line no-await-in-loop
        expect(await rolesFor({ ...claims, "urn:zitadel:iam:user:resourceowner:id": "foreign-org" })).toBe(
          "insufficient_scope"
        );
        // oxlint-disable-next-line no-await-in-loop
        expect(await rolesFor({ ...claims, org_id: "dumont-org", "urn:zitadel:iam:org:id": "dumont-org" })).toBe(
          "insufficient_scope"
        );
        // oxlint-disable-next-line no-await-in-loop
        expect(await rolesFor({ ...claims, "urn:zitadel:iam:user:resourceowner:id": ["dumont-org"] })).toBe(
          "insufficient_scope"
        );
        // oxlint-disable-next-line no-await-in-loop
        expect(await rolesFor({ ...claims, "urn:zitadel:iam:user:resourceowner:id": "dumont-org" })).toEqual([
          "hangar_writer",
        ]);
      }
    });

    it("accepts our-org hangar_reader and hangar_writer in ZITADEL's real shape", async () => {
      for (const claimName of [
        "urn:zitadel:iam:org:project:hangar-mcp-project:roles",
        "urn:zitadel:iam:org:project:roles",
      ]) {
        // oxlint-disable-next-line no-await-in-loop
        expect(await rolesFor({ [claimName]: { hangar_reader: { "dumont-org": "dumont.example.test" } } })).toEqual([
          "hangar_reader",
        ]);
        expect(
          // oxlint-disable-next-line no-await-in-loop
          await rolesFor({
            [claimName]: {
              hangar_writer: { "foreign-org": "foreign.example.test", "dumont-org": "dumont.example.test" },
            },
          })
        ).toEqual(["hangar_writer"]);
      }
    });
  });

  it("answers a reader calling a write tool with a tool error, not an HTTP 401/403", async () => {
    const { config, token } = await setupOidc();
    const calls: URL[] = [];
    const server = createHangarHttpServer(config, (principal, caller) =>
      createHangarServer(config, new HangarClient(config, caller, { fetch: hangarFetch(calls) }), {
        principal,
        audit: () => {},
      })
    );
    const port = await listen(server);
    const unauthorized = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", body: "{}" });
    expect(unauthorized.headers.get("www-authenticate")).toContain(
      'scope="openid email urn:zitadel:iam:org:project:role:hangar_reader urn:zitadel:iam:org:project:role:hangar_writer"'
    );
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await token()}`,
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "hangar_add_comment", arguments: { work_item: "HGR-5", body: "hi" } },
      }),
    });
    expect(response.status).toBe(200);
    const payload = (await response.json()) as { result: { isError: boolean; structuredContent: unknown } };
    expect(payload.result.isError).toBe(true);
    expect(payload.result.structuredContent).toMatchObject({ error: { code: "FORBIDDEN" } });
    expect(calls).toHaveLength(0);
  });

  it("forwards each request's own bearer to Hangar and writes the '— via MCP' footer", async () => {
    const { config, token } = await setupOidc();
    const writerRoles = { "urn:zitadel:iam:org:project:roles": { hangar_writer: { "dumont-org": "d" } } };
    const aliceToken = await token({ ...writerRoles, sub: "alice" });
    const bobToken = await token({ ...writerRoles, sub: "bob" });
    const upstream: Array<{ path: string; authorization: string }> = [];
    const comments: string[] = [];
    const reads = hangarFetch([]);
    const fetch = async (input: string | URL, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      upstream.push({ path: new URL(String(input)).pathname, authorization: headers.Authorization ?? "" });
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { comment_html: string };
        comments.push(body.comment_html);
        return jsonResponse({ id: "c-1", comment_html: body.comment_html }, 201);
      }
      return reads(input, init);
    };
    const audit: AuditRecord[] = [];
    const server = createHangarHttpServer(config, undefined, {}, { fetch, audit: (record) => audit.push(record) });
    const port = await listen(server);
    const post = (bearer: string, id: number, name: string, args: Record<string, unknown>) =>
      globalThis.fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${bearer}`,
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }),
      });
    // get_project resolves through (and fills) Alice's per-subject project cache.
    expect((await post(aliceToken, 1, "hangar_get_project", { project: "HGR" })).status).toBe(200);
    expect(upstream.map((call) => call.path)).toContain("/api/v1/workspaces/dumont/projects/");
    const aliceCalls = upstream.length;
    expect(aliceCalls).toBeGreaterThan(0);
    expect(upstream.every((call) => call.authorization === `Bearer ${aliceToken}`)).toBe(true);

    const response = await post(bobToken, 2, "hangar_add_comment", { work_item: "HGR-5", body: "hello" });
    expect(response.status).toBe(200);
    expect(comments).toEqual(["<p>hello</p><p>— via MCP</p>"]);
    const bobCalls = upstream.slice(aliceCalls);
    expect(bobCalls.length).toBeGreaterThan(0);
    // Bob's request never reuses Alice's token (nor Alice's cached project list).
    expect(bobCalls.every((call) => call.authorization === `Bearer ${bobToken}`)).toBe(true);
    expect(bobCalls.map((call) => call.path)).toContain("/api/v1/workspaces/dumont/projects/");
    expect(upstream.some((call) => /x-api-key/i.test(call.authorization))).toBe(false);
    // Each audit line names the Hangar user behind that request's own token,
    // even though both requests share the process-wide per-subject cache.
    expect(audit.map((record) => [record.sub, record.plane_user_id])).toEqual([
      ["alice", meUserIdFor(`Bearer ${aliceToken}`)],
      ["bob", meUserIdFor(`Bearer ${bobToken}`)],
    ]);
    expect(meUserIdFor(`Bearer ${aliceToken}`)).not.toBe(meUserIdFor(`Bearer ${bobToken}`));
  });

  it("turns Hangar's 'account not linked' 401 into a tool error, not an MCP 401", async () => {
    const { config, token } = await setupOidc();
    const server = createHangarHttpServer(
      config,
      undefined,
      {},
      {
        fetch: async () => jsonResponse({ error_code: "DUMONT_ACCOUNT_NOT_LINKED", error: "Sign in once" }, 401),
      }
    );
    const port = await listen(server);
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await token()}`,
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
    expect(response.headers.get("www-authenticate")).toBeNull();
    const payload = (await response.json()) as { result: { isError: boolean; structuredContent: unknown } };
    expect(payload.result.isError).toBe(true);
    expect(payload.result.structuredContent).toMatchObject({
      error: { code: "ACCOUNT_NOT_LINKED", message: expect.stringContaining("with Dumont login") },
    });
  });

  it("never turns Hangar's user-not-allowed, auth-unavailable or invalid_token answers into an MCP 401/403", async () => {
    const { config, token } = await setupOidc();
    const upstream: Array<[number, Record<string, unknown>, Record<string, string>, string, boolean]> = [
      [403, { error_code: "DUMONT_USER_NOT_ALLOWED", error: "x" }, {}, "USER_NOT_ALLOWED", false],
      [503, { error_code: "DUMONT_AUTH_UNAVAILABLE", error: "x" }, {}, "UPSTREAM_AUTH_UNAVAILABLE", true],
      [
        401,
        { error_code: "DUMONT_INVALID_TOKEN", error: "x" },
        { "www-authenticate": 'Bearer realm="api", error="invalid_token"' },
        "UPSTREAM_UNAUTHORIZED",
        false,
      ],
    ];
    for (const [status, body, headers, code, retryable] of upstream) {
      const server = createHangarHttpServer(
        config,
        undefined,
        {},
        {
          fetch: async () => {
            const response = jsonResponse(body, status);
            for (const [name, value] of Object.entries(headers)) response.headers.set(name, value);
            return response;
          },
        }
      );
      // oxlint-disable-next-line no-await-in-loop
      const port = await listen(server);
      // oxlint-disable-next-line no-await-in-loop
      const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: {
          // oxlint-disable-next-line no-await-in-loop
          authorization: `Bearer ${await token()}`,
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
      expect(response.headers.get("www-authenticate")).toBeNull();
      // oxlint-disable-next-line no-await-in-loop
      const payload = (await response.json()) as { result: { isError: boolean; structuredContent: unknown } };
      expect(payload.result.isError).toBe(true);
      expect(payload.result.structuredContent).toMatchObject({ error: { code, retryable } });
    }
  });

  it("returns 401 metadata challenge and 403 for a valid token without the role", async () => {
    const { config, token } = await setupOidc();
    const calls: URL[] = [];
    const server = createHangarHttpServer(config, (principal, caller) =>
      createHangarServer(config, new HangarClient(config, caller, { fetch: hangarFetch(calls) }), {
        principal,
        audit: () => {},
      })
    );
    const port = await listen(server);
    const baseUrl = `http://127.0.0.1:${port}`;

    const metadataResponse = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    expect(metadataResponse.status).toBe(200);
    expect(await metadataResponse.json()).toMatchObject({ resource: "https://mcp-hangar.example.test/mcp" });
    const pathMetadataResponse = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(pathMetadataResponse.status).toBe(200);

    const unauthorized = await fetch(`${baseUrl}/mcp`, { method: "POST", body: "{}" });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("www-authenticate")).toContain(
      'resource_metadata="https://mcp-hangar.example.test/.well-known/oauth-protected-resource"'
    );

    const withoutRole = await token({
      scope: "openid",
      "urn:zitadel:iam:org:project:roles": {},
    });
    const forbidden = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${withoutRole}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    expect(forbidden.status).toBe(403);
    expect(forbidden.headers.get("www-authenticate")).toContain("insufficient_scope");

    const accessToken = await token();
    const authorized = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "initialize",
        params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "oidc-test", version: "1" } },
      }),
    });
    expect(authorized.status).toBe(200);

    const call = async (id: number, method: string, params: Record<string, unknown>) => {
      const response = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      });
      expect(response.status).toBe(200);
      return (await response.json()) as Record<string, unknown>;
    };
    const listed = await call(3, "tools/list", {});
    // Nine read tools plus three write tools (gated per call by the writer role).
    expect((listed.result as { tools: unknown[] }).tools).toHaveLength(12);
    const result = await call(4, "tools/call", {
      name: "hangar_list_projects",
      arguments: { limit: 10, response_format: "json" },
    });
    expect(result.result).toMatchObject({ structuredContent: { results: [{ id: PROJECT_HGR }] } });
    expect(calls.map((url) => url.pathname)).toEqual(["/api/v1/users/me/", "/api/v1/workspaces/dumont/projects/"]);
  });
});
