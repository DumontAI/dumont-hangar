import { InMemoryTransport, type JSONRPCMessage } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import { HangarClient } from "../src/client.js";
import {
  createHangarServer,
  HANGAR_READ_TOOL_NAMES,
  HANGAR_TOOL_NAMES,
  HANGAR_WRITE_TOOL_NAMES,
} from "../src/tools.js";
import { PROJECT_HGR, READER, hangarFetch, testConfig } from "./fixtures.js";

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

describe("MCP protocol catalog and in-memory transport", () => {
  it("lists the deterministic Hangar tool catalog and calls one tool", async () => {
    // Write tools are registered only when writes are enabled.
    const config = testConfig({ writeProjects: ["HGR"] });
    const calls: URL[] = [];
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createHangarServer(config, new HangarClient(config, hangarFetch(calls)), {
      principal: READER,
      audit: () => {},
    });
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
      const readOnly = new Set<string>(HANGAR_READ_TOOL_NAMES);
      for (const tool of tools) {
        const annotations = tool.annotations as Record<string, unknown>;
        expect(annotations.destructiveHint).toBe(false);
        expect(annotations.readOnlyHint).toBe(readOnly.has(String(tool.name)));
      }
      expect(tools.filter((tool) => !readOnly.has(String(tool.name))).map((tool) => tool.name)).toEqual([
        ...HANGAR_WRITE_TOOL_NAMES,
      ]);

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
    const server = createHangarServer(config, new HangarClient(config, forbiddenUpstream), {
      principal: READER,
      audit: () => {},
    });
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
