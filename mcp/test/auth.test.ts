import { createServer, type Server } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthorizer, protectedResourceMetadata } from "../src/auth.js";
import { HangarClient } from "../src/client.js";
import { createHangarHttpServer } from "../src/http.js";
import { createHangarServer } from "../src/tools.js";
import { hangarFetch, jsonResponse, PROJECT_HGR, testConfig } from "./fixtures.js";

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
      .setSubject("user-1")
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

  it("accepts reader-only and writer-only tokens and hands roles and email to the tools", async () => {
    const { config, token } = await setupOidc();
    const authorize = createAuthorizer(config);
    const request = async (claims: Record<string, unknown>) =>
      authorize({ headers: { host: "127.0.0.1", authorization: `Bearer ${await token(claims)}` } } as never);

    expect(await request({})).toMatchObject({
      failure: null,
      principal: { sub: "user-1", email: null, roles: ["hangar_reader"] },
    });
    expect(
      await request({
        email: "Cristian@Example.test",
        "urn:zitadel:iam:org:project:roles": { hangar_writer: { "dumont-org": "dumont.example.test" } },
      })
    ).toMatchObject({ failure: null, principal: { email: "cristian@example.test", roles: ["hangar_writer"] } });
    expect(
      await request({
        email: "x@example.test",
        email_verified: false,
        "urn:zitadel:iam:org:project:roles": {
          hangar_reader: { "dumont-org": "d" },
          hangar_writer: { "dumont-org": "d" },
        },
      })
    ).toMatchObject({ failure: null, principal: { email: null, roles: ["hangar_reader", "hangar_writer"] } });
    expect(
      (await request({ "urn:zitadel:iam:org:project:roles": { some_other_role: { "dumont-org": "d" } } })).failure
    ).toBe("insufficient_scope");
  });

  it("answers a reader calling a write tool with a tool error, not an HTTP 401/403", async () => {
    const { config: base, token } = await setupOidc();
    const config = { ...base, writeProjects: ["HGR"] };
    const calls: URL[] = [];
    const server = createHangarHttpServer(config, (principal) =>
      createHangarServer(config, new HangarClient(config, hangarFetch(calls)), { principal, audit: () => {} })
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

  it("resolves a missing email through userinfo with the caller's own bearer on writes", async () => {
    const { config: base, token } = await setupOidc();
    const config = {
      ...base,
      writeProjects: ["HGR"],
      oidcUserinfoUrl: new URL("https://issuer.example.test/oidc/v1/userinfo"),
    };
    const writerToken = await token({
      "urn:zitadel:iam:org:project:roles": { hangar_writer: { "dumont-org": "dumont.example.test" } },
    });
    const userinfoCalls: string[] = [];
    const comments: string[] = [];
    const reads = hangarFetch([]);
    const upstream = async (input: string | URL, init?: RequestInit) => {
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { comment_html: string };
        comments.push(body.comment_html);
        return jsonResponse({ id: "c-1", comment_html: body.comment_html }, 201);
      }
      return reads(input, init);
    };
    const server = createHangarHttpServer(
      config,
      (principal, resolveEmail) =>
        createHangarServer(config, new HangarClient(config, upstream), { principal, resolveEmail, audit: () => {} }),
      {},
      {
        fetch: async (_input, init) => {
          userinfoCalls.push(((init?.headers ?? {}) as Record<string, string>).Authorization ?? "");
          return jsonResponse({ sub: "user-1", email: "camila@example.test", email_verified: true });
        },
        log: () => {},
      }
    );
    const port = await listen(server);
    const post = (id: number, name: string, args: Record<string, unknown>) =>
      fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${writerToken}`,
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }),
      });
    expect((await post(1, "hangar_list_projects", { limit: 1 })).status).toBe(200);
    expect(userinfoCalls).toHaveLength(0);
    const response = await post(2, "hangar_add_comment", { work_item: "HGR-5", body: "hello" });
    expect(response.status).toBe(200);
    expect(comments).toEqual(["<p>hello</p><p>— via MCP por camila@example.test</p>"]);
    expect(userinfoCalls).toEqual([`Bearer ${writerToken}`]);
    await post(3, "hangar_add_comment", { work_item: "HGR-5", body: "again" });
    expect(userinfoCalls).toHaveLength(1); // cached by sub across requests
  });

  it("returns 401 metadata challenge and 403 for a valid token without the role", async () => {
    const { config, token } = await setupOidc();
    const calls: URL[] = [];
    const hangar = new HangarClient(config, hangarFetch(calls));
    const server = createHangarHttpServer(config, (principal) =>
      createHangarServer(config, hangar, { principal, audit: () => {} })
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
    expect((listed.result as { tools: unknown[] }).tools).toHaveLength(12);
    const result = await call(4, "tools/call", {
      name: "hangar_list_projects",
      arguments: { limit: 10, response_format: "json" },
    });
    expect(result.result).toMatchObject({ structuredContent: { results: [{ id: PROJECT_HGR }] } });
    expect(calls[0]?.pathname).toBe("/api/v1/workspaces/dumont/projects/");
  });
});
