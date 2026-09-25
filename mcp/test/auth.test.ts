import { createServer, type Server } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthorizer, protectedResourceMetadata } from "../src/auth.js";
import { HangarClient } from "../src/client.js";
import { createHangarHttpServer } from "../src/http.js";
import { createHangarServer } from "../src/tools.js";
import { hangarFetch, PROJECT_HGR, testConfig } from "./fixtures.js";

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
    oidcRequiredRole: "hangar_reader",
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
      scopes_supported: ["urn:zitadel:iam:org:project:role:hangar_reader"],
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

  it("returns 401 metadata challenge and 403 for a valid token without the role", async () => {
    const { config, token } = await setupOidc();
    const calls: URL[] = [];
    const hangar = new HangarClient(config, hangarFetch(calls));
    const server = createHangarHttpServer(config, () => createHangarServer(config, hangar));
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
    expect((listed.result as { tools: unknown[] }).tools).toHaveLength(9);
    const result = await call(4, "tools/call", {
      name: "hangar_list_projects",
      arguments: { limit: 10, response_format: "json" },
    });
    expect(result.result).toMatchObject({ structuredContent: { results: [{ id: PROJECT_HGR }] } });
    expect(calls[0]?.pathname).toBe("/api/v1/workspaces/dumont/projects/");
  });
});
