import { InMemoryTransport, type JSONRPCMessage } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { HangarClient } from "../src/client.js";
import { createHangarHttpServer } from "../src/http.js";
import { createHangarServer, HANGAR_TOOL_NAMES } from "../src/tools.js";
import { PROJECT_HGR, hangarFetch, testConfig } from "./fixtures.js";

const openServers: Array<ReturnType<typeof createHangarHttpServer>> = [];

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

function isResponse(message: JSONRPCMessage, id: number): message is JSONRPCMessage & { id: number } {
  return "id" in message && message.id === id;
}

async function rpc(
  transport: InMemoryTransport,
  message: JSONRPCMessage & { id: number }
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const previous = transport.onmessage;
    // The SDK transport exposes onmessage setters instead of addEventListener.
    // oxlint-disable-next-line prefer-add-event-listener
    transport.onmessage = (response) => {
      if (!isResponse(response, message.id)) return;
      // oxlint-disable-next-line prefer-add-event-listener
      transport.onmessage = previous;
      resolve(response as Record<string, unknown>);
    };
    void transport.send(message).catch(reject);
  });
}

const forbiddenUpstream: (input: string | URL, init?: RequestInit) => Promise<Response> = async () =>
  new Response(JSON.stringify({ error: "upstream secret detail" }), {
    status: 403,
    headers: { "content-type": "application/json" },
  });

async function readLine(stream: PassThrough): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      // Node streams are EventEmitters; the addEventListener hint does not apply.
      // oxlint-disable-next-line prefer-add-event-listener
      stream.off("data", onData);
      try {
        resolve(JSON.parse(buffer.slice(0, newline)) as Record<string, unknown>);
      } catch (error) {
        reject(error);
      }
    };
    // oxlint-disable-next-line prefer-add-event-listener
    stream.on("data", onData);
  });
}

async function postMcp(url: string, token: string, message: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(message),
  });
  const text = await response.text();
  const body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  expect(response.ok).toBe(true);
  return body;
}

describe("MCP protocol catalog and in-memory transport", () => {
  it("lists exactly the deterministic read-only Hangar tools and calls one tool", async () => {
    const config = testConfig();
    const calls: URL[] = [];
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createHangarServer(config, new HangarClient(config, hangarFetch(calls)));
    try {
      await server.connect(serverTransport);
      await clientTransport.start();
      const initialize = await rpc(clientTransport, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "in-memory-test", version: "1" },
        },
      });
      expect(initialize.id).toBe(1);
      await clientTransport.send({ jsonrpc: "2.0", method: "notifications/initialized" });

      const listed = await rpc(clientTransport, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
      const tools = (listed.result as { tools: Array<Record<string, unknown>> }).tools;
      expect(tools.map((tool) => tool.name)).toEqual([...HANGAR_TOOL_NAMES]);
      expect(tools.every((tool) => String(tool.name).startsWith("hangar_"))).toBe(true);
      expect(tools.every((tool) => (tool.inputSchema as Record<string, unknown>).type === "object")).toBe(true);
      expect(tools.every((tool) => (tool.outputSchema as Record<string, unknown>).type === "object")).toBe(true);
      expect(
        tools.every(
          (tool) =>
            (tool.annotations as Record<string, unknown>).readOnlyHint === true &&
            (tool.annotations as Record<string, unknown>).destructiveHint === false
        )
      ).toBe(true);

      const result = await rpc(clientTransport, {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "hangar_list_projects", arguments: { limit: 10, response_format: "json" } },
      });
      expect(result.error).toBeUndefined();
      expect(result.result).toMatchObject({
        structuredContent: { results: [{ id: PROJECT_HGR, identifier: "HGR", name: "Hangar" }] },
      });
      expect(calls[0]?.pathname).toBe("/api/v1/workspaces/dumont/projects/");
    } finally {
      await clientTransport.close();
      await server.close();
    }
  });

  it("returns a tool error without leaking upstream details when the read fails", async () => {
    const config = testConfig();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createHangarServer(config, new HangarClient(config, forbiddenUpstream));
    try {
      await server.connect(serverTransport);
      await clientTransport.start();
      await rpc(clientTransport, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "in-memory-test", version: "1" },
        },
      });
      await clientTransport.send({ jsonrpc: "2.0", method: "notifications/initialized" });
      const result = await rpc(clientTransport, {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "hangar_list_projects", arguments: { limit: 10, response_format: "json" } },
      });
      const payload = JSON.stringify(result.result);
      expect(payload).toContain("UPSTREAM_FORBIDDEN");
      expect(payload).not.toContain("upstream secret detail");
    } finally {
      await clientTransport.close();
      await server.close();
    }
  });
});

describe("stdio transport", () => {
  it("answers initialize and tools/list without writing non-protocol stdout", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const server = createHangarServer(testConfig());
    await server.connect(new StdioServerTransport(input, output));
    try {
      const initializeResponse = readLine(output);
      input.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "stdio-test", version: "1" } },
        })}\n`
      );
      const initialize = await initializeResponse;
      expect(initialize.id).toBe(1);
      expect(initialize.result).toMatchObject({ serverInfo: { name: "hangar-mcp-server", version: "0.1.0" } });

      input.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
      const toolsResponse = readLine(output);
      input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })}\n`);
      const tools = await toolsResponse;
      expect(tools.id).toBe(2);
      expect((tools.result as { tools: unknown[] }).tools).toHaveLength(HANGAR_TOOL_NAMES.length);
      expect(output.readableLength).toBe(0);
    } finally {
      await server.close();
    }
  });
});

describe("Streamable HTTP transport", () => {
  it("answers initialize, tools/list, and tools/call over authenticated stateless HTTP", async () => {
    const config = testConfig();
    const calls: URL[] = [];
    const hangar = new HangarClient(config, hangarFetch(calls));
    const server = createHangarHttpServer(config, () => createHangarServer(config, hangar));
    openServers.push(server);
    await new Promise<void>((resolve, reject) =>
      server.listen(0, "127.0.0.1", (error) => {
        if (error) reject(error);
        else resolve();
      })
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");
    const url = `http://127.0.0.1:${address.port}/mcp`;

    const initialize = await postMcp(url, config.mcpAuthToken, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "http-test", version: "1" } },
    });
    expect(initialize.result).toMatchObject({ serverInfo: { name: "hangar-mcp-server" } });
    await postMcp(url, config.mcpAuthToken, { jsonrpc: "2.0", method: "notifications/initialized" });
    const listed = await postMcp(url, config.mcpAuthToken, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    expect((listed.result as { tools: unknown[] }).tools).toHaveLength(HANGAR_TOOL_NAMES.length);
    const result = await postMcp(url, config.mcpAuthToken, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "hangar_list_projects", arguments: { limit: 10, response_format: "json" } },
    });
    expect(result.result).toMatchObject({ structuredContent: { results: [{ id: PROJECT_HGR }] } });
    expect(calls[0]?.pathname).toBe("/api/v1/workspaces/dumont/projects/");
  });

  it("rejects missing MCP authorization before invoking the SDK transport", async () => {
    const config = testConfig();
    const server = createHangarHttpServer(config);
    openServers.push(server);
    await new Promise<void>((resolve, reject) =>
      server.listen(0, "127.0.0.1", (error) => {
        if (error) reject(error);
        else resolve();
      })
    );
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");
    const response = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
      headers: { "content-type": "application/json" },
    });
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain(config.mcpAuthToken);
  });
});
