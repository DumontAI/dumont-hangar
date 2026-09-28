import { InMemoryTransport, type JSONRPCMessage } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";
import { WriteRateLimiter, type AuditRecord } from "../src/access.js";
import { HangarClient } from "../src/client.js";
import { HangarConfigError, loadHangarConfig } from "../src/config.js";
import { htmlWithFooter, textToHtml } from "../src/markup.js";
import { containsCredential } from "../src/redaction.js";
import { createHangarServer, HANGAR_TOOL_NAMES, IDEMPOTENCY_EXTERNAL_SOURCE } from "../src/tools.js";
import type { HangarConfig, Principal } from "../src/types.js";
import {
  HGR_WORK_ITEM,
  ME_USER_ID,
  PROJECT_HGR,
  PROJECT_SEC,
  READER,
  TEST_ACCESS_TOKEN,
  WORK_ITEM_HGR_5,
  WRITER,
  callerFor,
  hangarFetch,
  jsonResponse,
  testConfig,
} from "./fixtures.js";

const CREATED_ID = "5d0c8f5e-7a41-4f8e-9d0b-0a1f3b3c2d11";
const EXISTING_ID = "9a3e2f10-1111-4c5d-8e9f-222233334444";
const COMMENT_ID = "c0ffee00-1234-4abc-8def-555566667777";
// A value that must never reach the audit log.
const SENTINEL = "SENTINEL-BODY-7f3a9c";

interface WriteCall {
  readonly method: string;
  readonly path: string;
  readonly body: Record<string, unknown>;
}

interface WriteFetchOptions {
  conflict?: boolean;
  workItem?: Record<string, unknown>;
  commentProject?: string;
  /** Body of a 403 Hangar answers to every write. */
  forbidWrites?: Record<string, unknown>;
  /** Every upstream call, reads included. */
  seen?: Array<{ method: string; path: string }>;
}

function writeFetch(writes: WriteCall[], options: WriteFetchOptions = {}) {
  const reads = hangarFetch([]);
  return async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    options.seen?.push({ method, path: url.pathname });
    if (method === "GET") {
      if (url.pathname.endsWith("/workspaces/dumont/members/")) {
        return jsonResponse([
          { id: "user-1", display_name: "Cristian", email: "cristian@example.test", role: 20 },
          { id: "user-2", display_name: "Camila", email: "camila@example.test", role: 15 },
        ]);
      }
      if (url.pathname.endsWith(`/issues/${EXISTING_ID}/`)) {
        return jsonResponse({ ...HGR_WORK_ITEM, id: EXISTING_ID, sequence_id: 7, name: "Existing" });
      }
      if (options.workItem && /\/(?:work-items\/HGR-5|issues\/[0-9a-f-]{36})\/$/.test(url.pathname)) {
        return jsonResponse(options.workItem);
      }
      if (/\/projects\/[0-9a-f-]+\/$/.test(url.pathname) && url.pathname.includes(PROJECT_SEC)) {
        return jsonResponse({ id: PROJECT_SEC, identifier: "SEC", name: "Dumont Secrets" });
      }
      return reads(input, init);
    }
    if (options.forbidWrites) return jsonResponse(options.forbidWrites, 403);
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    writes.push({ method, path: url.pathname, body });
    if (method === "POST" && url.pathname.endsWith("/comments/")) {
      return jsonResponse(
        {
          id: COMMENT_ID,
          comment_html: body.comment_html,
          created_by: "bot",
          created_at: "2026-09-28T00:00:00Z",
          ...(options.commentProject ? { project: options.commentProject } : {}),
        },
        201
      );
    }
    if (method === "POST" && url.pathname.endsWith("/issues/")) {
      if (options.conflict) {
        return jsonResponse(
          { error: "Issue with the same external id and external source already exists", id: EXISTING_ID },
          409
        );
      }
      return jsonResponse(
        { ...body, id: CREATED_ID, project: PROJECT_HGR, sequence_id: 12, created_at: "2026-09-28T00:00:00Z" },
        201
      );
    }
    if (method === "PATCH") {
      return jsonResponse({ ...HGR_WORK_ITEM, ...body });
    }
    return jsonResponse({ error: "unexpected" }, 405);
  };
}

function isResponse(message: JSONRPCMessage, id: number): message is JSONRPCMessage & { id: number } {
  return "id" in message && message.id === id;
}

const open: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(open.splice(0).map((close) => close()));
});

interface Harness {
  call(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>>;
  callRaw(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>>;
  toolNames(): Promise<string[]>;
  readonly writes: WriteCall[];
  readonly audit: AuditRecord[];
}

async function harness(
  principal: Principal | null,
  configOverrides: Partial<HangarConfig> = {},
  options: WriteFetchOptions & { rateLimiter?: WriteRateLimiter; accessToken?: string | null } = {}
): Promise<Harness> {
  const config = testConfig({ allowedProjects: ["HGR", "SEC"], ...configOverrides });
  const writes: WriteCall[] = [];
  const audit: AuditRecord[] = [];
  const caller = callerFor(
    principal ?? { sub: "anonymous" },
    options.accessToken === undefined ? TEST_ACCESS_TOKEN : options.accessToken
  );
  const client = new HangarClient(config, caller, { fetch: writeFetch(writes, options) });
  const server = createHangarServer(config, client, {
    principal,
    audit: (record) => audit.push(record),
    ...(options.rateLimiter ? { rateLimiter: options.rateLimiter } : {}),
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await clientTransport.start();
  open.push(async () => {
    await clientTransport.close();
    await server.close();
  });
  let nextId = 1;
  const rpc = (message: JSONRPCMessage & { id: number }) =>
    new Promise<Record<string, unknown>>((resolve, reject) => {
      const previous = clientTransport.onmessage;
      // oxlint-disable-next-line prefer-add-event-listener
      clientTransport.onmessage = (response) => {
        if (!isResponse(response, message.id)) return;
        // oxlint-disable-next-line prefer-add-event-listener
        clientTransport.onmessage = previous;
        resolve(response as Record<string, unknown>);
      };
      void clientTransport.send(message).catch(reject);
    });
  await rpc({
    jsonrpc: "2.0",
    id: nextId++,
    method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "write-test", version: "1" } },
  });
  await clientTransport.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  return {
    writes,
    audit,
    async callRaw(name, args) {
      return rpc({
        jsonrpc: "2.0",
        id: nextId++,
        method: "tools/call",
        params: { name, arguments: { response_format: "json", ...args } },
      });
    },
    async toolNames() {
      const listed = await rpc({ jsonrpc: "2.0", id: nextId++, method: "tools/list", params: {} });
      return (listed.result as { tools: Array<{ name: string }> }).tools.map((tool) => tool.name);
    },
    async call(name, args) {
      const response = await rpc({
        jsonrpc: "2.0",
        id: nextId++,
        method: "tools/call",
        params: { name, arguments: { response_format: "json", ...args } },
      });
      expect(response.error).toBeUndefined();
      return response.result as Record<string, unknown>;
    },
  };
}

function errorCode(result: Record<string, unknown>): string | undefined {
  return (result.structuredContent as { error?: { code?: string } } | undefined)?.error?.code;
}

describe("Hangar write tools: authorization and gates", () => {
  it("refuses a write tool for a reader-only token with FORBIDDEN and writes nothing", async () => {
    const h = await harness(READER);
    const result = await h.call("hangar_create_work_item", { project: "HGR", name: "x" });
    expect(result.isError).toBe(true);
    expect(errorCode(result)).toBe("FORBIDDEN");
    expect(h.writes).toHaveLength(0);
    expect(h.audit.at(-1)).toMatchObject({
      tool: "hangar_create_work_item",
      outcome: "denied",
      error_code: "FORBIDDEN",
    });
  });

  it("still serves read tools to a reader-only token and to a writer-only token", async () => {
    const reader = await harness(READER);
    const read = await reader.call("hangar_get_work_item", { work_item: "HGR-5" });
    expect(read.isError).toBeUndefined();
    expect(reader.audit.at(-1)).toMatchObject({ outcome: "success", roles_used: ["hangar_reader"] });

    const writerOnly = await harness({ sub: "w", roles: ["hangar_writer"] });
    const readByWriter = await writerOnly.call("hangar_list_projects", { limit: 5 });
    expect(readByWriter.isError).toBeUndefined();
    expect(writerOnly.audit.at(-1)).toMatchObject({ roles_used: ["hangar_writer"] });
  });

  it("denies every tool when there is no principal", async () => {
    const h = await harness(null);
    expect(errorCode(await h.call("hangar_list_projects", { limit: 5 }))).toBe("FORBIDDEN");
  });

  it("always registers the write tools; the writer role gates them per call", async () => {
    await expect((await harness(READER)).toolNames()).resolves.toEqual([...HANGAR_TOOL_NAMES]);
  });

  it("maps a Hangar 403 on a write to PROJECT_ACCESS_DENIED naming the ZITADEL role", async () => {
    const h = await harness(WRITER, {}, { forbidWrites: { detail: "You do not have permission" } });
    const result = await h.call("hangar_add_comment", { work_item: "HGR-5", body: "hi" });
    expect(result.structuredContent).toMatchObject({
      error: {
        code: "PROJECT_ACCESS_DENIED",
        message: "No write access to project HGR in Hangar; ask for the role hangar.project.hgr.member in Dumont Auth",
      },
    });
    expect(h.audit.at(-1)).toMatchObject({ outcome: "denied", error_code: "PROJECT_ACCESS_DENIED" });
  });

  it("maps Hangar's writer-role 403 to WRITER_ROLE_REQUIRED", async () => {
    const h = await harness(WRITER, {}, { forbidWrites: { error_code: "DUMONT_WRITER_ROLE_REQUIRED" } });
    const result = await h.call("hangar_create_work_item", { project: "HGR", name: "x" });
    expect(errorCode(result)).toBe("WRITER_ROLE_REQUIRED");
    expect(h.audit.at(-1)).toMatchObject({ outcome: "denied" });
  });

  it("answers a non-forwardable (opaque) token with a tool error and never calls Hangar", async () => {
    const seen: Array<{ method: string; path: string }> = [];
    const h = await harness(WRITER, {}, { accessToken: null, seen });
    for (const [tool, args] of [
      ["hangar_list_projects", { limit: 1 }],
      ["hangar_add_comment", { work_item: "HGR-5", body: "hi" }],
    ] as const) {
      // oxlint-disable-next-line no-await-in-loop
      const result = await h.call(tool, args);
      expect(errorCode(result)).toBe("TOKEN_NOT_FORWARDABLE");
    }
    expect(seen).toHaveLength(0);
    expect(h.audit.map((record) => [record.outcome, record.plane_user_id])).toEqual([
      ["denied", null],
      ["denied", null],
    ]);
  });

  it("refuses a project outside the ceiling with PROJECT_NOT_ALLOWED", async () => {
    const h = await harness(WRITER, { allowedProjects: ["HGR"] });
    expect(errorCode(await h.call("hangar_create_work_item", { project: "SEC", name: "x" }))).toBe(
      "PROJECT_NOT_ALLOWED"
    );
  });

  it("refuses credential-looking input with SECRET_DETECTED without writing or echoing it", async () => {
    const h = await harness(WRITER);
    const token = "plane_api_" + "0123456789abcdef".repeat(2);
    const result = await h.call("hangar_add_comment", { work_item: "HGR-5", body: `use ${token} for now` });
    expect(errorCode(result)).toBe("SECRET_DETECTED");
    expect(JSON.stringify(result)).not.toContain(token);
    expect(h.writes).toHaveLength(0);
    expect(JSON.stringify(h.audit)).not.toContain(token);

    const inName = await h.call("hangar_create_work_item", {
      project: "HGR",
      name: "db postgres://app:hunter22@db:5432/x",
    });
    expect(errorCode(inName)).toBe("SECRET_DETECTED");
  });

  it("rate-limits write calls per subject with a retryable RATE_LIMITED", async () => {
    const limiter = new WriteRateLimiter(2);
    const h = await harness(WRITER, {}, { rateLimiter: limiter });
    expect((await h.call("hangar_add_comment", { work_item: "HGR-5", body: "one" })).isError).toBeUndefined();
    expect((await h.call("hangar_add_comment", { work_item: "HGR-5", body: "two" })).isError).toBeUndefined();
    const third = await h.call("hangar_add_comment", { work_item: "HGR-5", body: "three" });
    expect(errorCode(third)).toBe("RATE_LIMITED");
    expect((third.structuredContent as { error: { retryable: boolean } }).error.retryable).toBe(true);
    expect(h.writes).toHaveLength(2);
    // Reads are not rate-limited, and another subject has its own window.
    expect((await h.call("hangar_list_projects", { limit: 1 })).isError).toBeUndefined();
    const other = await harness({ ...WRITER, sub: "someone-else" }, {}, { rateLimiter: limiter });
    expect((await other.call("hangar_add_comment", { work_item: "HGR-5", body: "ok" })).isError).toBeUndefined();
  });

  it("opens a new window after 60 seconds", () => {
    let now = 1_000_000;
    const limiter = new WriteRateLimiter(1, () => now);
    limiter.consume("a");
    expect(() => limiter.consume("a")).toThrowError(/Too many/);
    now += 60_000;
    expect(() => limiter.consume("a")).not.toThrow();
  });
});

describe("Hangar write tools: behavior", () => {
  it("creates a work item with resolved ids, safe HTML and one '— via MCP' footer", async () => {
    const h = await harness(WRITER);
    const result = await h.call("hangar_create_work_item", {
      project: "hgr",
      name: "New MCP item",
      description: "Hello <script>alert(1)</script>\n\n- one\n- **two**",
      state: "done",
      priority: "high",
      labels: ["bug"],
      assignees: ["me", "Camila"],
      parent: "HGR-5",
      start_date: "2026-09-28",
      target_date: "2026-10-01",
    });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({ id: CREATED_ID, identifier: "HGR-12", idempotent_replay: false });
    expect(h.writes).toHaveLength(1);
    const write = h.writes[0]!;
    expect(write.method).toBe("POST");
    expect(write.path).toBe(`/api/v1/workspaces/dumont/projects/${PROJECT_HGR}/issues/`);
    expect(write.body).toMatchObject({
      name: "New MCP item",
      state: "state-2",
      priority: "high",
      labels: ["label-1"],
      assignees: [ME_USER_ID, "user-2"],
      parent: WORK_ITEM_HGR_5,
      start_date: "2026-09-28",
      target_date: "2026-10-01",
    });
    const html = String(write.body.description_html);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("<ul><li><p>one</p></li><li><p><strong>two</strong></p></li></ul>");
    expect(html.endsWith("<p>— via MCP</p>")).toBe(true);
    expect(html.match(/via MCP/g)).toHaveLength(1);
    expect(write.body.external_id).toBeUndefined();
    expect(h.audit.at(-1)).toMatchObject({
      tool: "hangar_create_work_item",
      sub: WRITER.sub,
      plane_user_id: ME_USER_ID,
      roles_used: ["hangar_writer"],
      project: "HGR",
      work_item: "HGR-12",
      outcome: "success",
      error_code: null,
    });
    expect(h.audit.at(-1)?.fields_changed).toEqual([
      "name",
      "description",
      "state",
      "priority",
      "labels",
      "assignees",
      "parent",
      "start_date",
      "target_date",
    ]);
  });

  it("adds the footer on an empty description, naming nobody", async () => {
    const h = await harness({ sub: "sub-123", roles: ["hangar_writer"] });
    await h.call("hangar_create_work_item", { project: "HGR", name: "No description" });
    expect(h.writes[0]!.body.description_html).toBe("<p>— via MCP</p>");
  });

  it('resolves assignee "me" to the Hangar user behind the token', async () => {
    const seen: Array<{ method: string; path: string }> = [];
    const h = await harness({ sub: "sub-123", roles: ["hangar_writer"] }, {}, { seen });
    const result = await h.call("hangar_create_work_item", { project: "HGR", name: "x", assignees: ["me"] });
    expect(result.isError).toBeUndefined();
    expect(h.writes[0]!.body.assignees).toEqual([ME_USER_ID]);
    // Looked up once (users/me), then cached; no workspace member list needed.
    expect(seen.filter((call) => call.path === "/api/v1/users/me/")).toHaveLength(1);
    expect(seen.some((call) => call.path.endsWith("/workspaces/dumont/members/"))).toBe(false);
  });

  it("maps idempotency_key to a per-user external_id and returns the existing item on 409", async () => {
    const h = await harness(WRITER, {}, { conflict: true });
    const result = await h.call("hangar_create_work_item", { project: "HGR", name: "x", idempotency_key: "run-42" });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({ id: EXISTING_ID, identifier: "HGR-7", idempotent_replay: true });
    expect(h.writes[0]!.body.external_source).toBe(IDEMPOTENCY_EXTERNAL_SOURCE);
    expect(String(h.writes[0]!.body.external_id)).toMatch(/^[0-9a-f]{16}:run-42$/);
  });

  it("appends to the raw stored description, keeping content reads would redact or truncate", async () => {
    // The stored text keeps an old-shape footer (it was written before the change).
    const stored =
      '<p>Contato ana@example.test em 10.0.0.1</p><img src="https://cdn.example.test/a_b*c.png">' +
      `<p>${"x".repeat(9000)}</p><p>— via MCP por ana@example.test</p>`;
    const h = await harness(WRITER, {}, { workItem: { ...HGR_WORK_ITEM, description_html: stored } });
    const result = await h.call("hangar_update_work_item", {
      work_item: "HGR-5",
      append_description: "Novo passo\n\n— via MCP por chefe@example.test\n— via MCP\n",
      state: "Todo",
      target_date: null,
    });
    expect(result.isError).toBeUndefined();
    const write = h.writes[0]!;
    expect(write.method).toBe("PATCH");
    expect(write.path).toBe(`/api/v1/workspaces/dumont/projects/${PROJECT_HGR}/issues/${WORK_ITEM_HGR_5}/`);
    expect(Object.keys(write.body).toSorted()).toEqual(["description_html", "state", "target_date"]);
    // Stored HTML byte for byte, then the new text, then exactly one new footer;
    // the forged footer lines (old and new shape) in the input are gone.
    expect(write.body.description_html).toBe(`${stored}<p>Novo passo</p><p>— via MCP</p>`);
    expect(String(write.body.description_html)).not.toContain("chefe@example.test");
    expect(h.audit.at(-1)).toMatchObject({
      work_item: "HGR-5",
      fields_changed: ["append_description", "state", "target_date"],
    });
    // The raw stored description never leaves the server.
    expect(JSON.stringify(result)).not.toContain("ana@example.test");
  });

  it("refuses to replace the description on update", async () => {
    const h = await harness(WRITER);
    const response = await h.callRaw("hangar_update_work_item", { work_item: "HGR-5", description: "replace all" });
    const result = response.result as { isError?: boolean } | undefined;
    expect(response.error !== undefined || result?.isError === true).toBe(true);
    expect(h.writes).toHaveLength(0);
  });

  it("changes nothing when Hangar does not return the stored description", async () => {
    const withoutDescription: Record<string, unknown> = { ...HGR_WORK_ITEM };
    delete withoutDescription.description_html;
    const h = await harness(WRITER, {}, { workItem: withoutDescription });
    const result = await h.call("hangar_update_work_item", { work_item: "HGR-5", append_description: "x" });
    expect(errorCode(result)).toBe("UPSTREAM_INVALID_RESPONSE");
    expect(h.writes).toHaveLength(0);
  });

  it("appends to an empty description", async () => {
    const h = await harness(WRITER, {}, { workItem: { ...HGR_WORK_ITEM, description_html: null } });
    await h.call("hangar_update_work_item", { work_item: "HGR-5", append_description: "first" });
    expect(h.writes[0]!.body.description_html).toBe("<p>first</p><p>— via MCP</p>");
  });

  it("rejects an update without fields and a UUID without project", async () => {
    const h = await harness(WRITER);
    expect(errorCode(await h.call("hangar_update_work_item", { work_item: "HGR-5" }))).toBe("INVALID_ARGUMENT");
    expect(errorCode(await h.call("hangar_update_work_item", { work_item: WORK_ITEM_HGR_5, name: "x" }))).toBe(
      "INVALID_ARGUMENT"
    );
    expect(h.writes).toHaveLength(0);
  });

  it("adds a comment with the footer", async () => {
    const h = await harness(WRITER);
    const result = await h.call("hangar_add_comment", { work_item: "HGR-5", body: "Looks good" });
    expect(result.isError).toBeUndefined();
    expect(h.writes[0]).toMatchObject({
      method: "POST",
      path: `/api/v1/workspaces/dumont/projects/${PROJECT_HGR}/issues/${WORK_ITEM_HGR_5}/comments/`,
      body: { comment_html: "<p>Looks good</p><p>— via MCP</p>" },
    });
    expect(result.structuredContent).toMatchObject({ id: COMMENT_ID, work_item: "HGR-5" });
  });

  it("reports a comment that Hangar returns for another project", async () => {
    const h = await harness(WRITER, {}, { commentProject: PROJECT_SEC });
    expect(errorCode(await h.call("hangar_add_comment", { work_item: "HGR-5", body: "x" }))).toBe(
      "PROJECT_SCOPE_MISMATCH"
    );
  });

  it("never writes text bodies or tokens into the audit line", async () => {
    const h = await harness(WRITER);
    await h.call("hangar_create_work_item", { project: "HGR", name: SENTINEL, description: SENTINEL });
    await h.call("hangar_update_work_item", { work_item: "HGR-5", name: SENTINEL, append_description: SENTINEL });
    await h.call("hangar_add_comment", { work_item: "HGR-5", body: SENTINEL });
    await h.call("hangar_search_work_items", { query: SENTINEL });
    await h.call("hangar_get_project", { project: SENTINEL.slice(0, 20) });
    expect(h.audit).toHaveLength(5);
    const serialized = JSON.stringify(h.audit);
    expect(serialized).not.toContain(SENTINEL);
    expect(serialized).not.toContain(SENTINEL.slice(0, 20));
    expect(serialized).not.toContain(TEST_ACCESS_TOKEN);
    for (const record of h.audit) {
      expect(Object.keys(record).toSorted()).toEqual(
        [
          "ts",
          "event",
          "tool",
          "sub",
          "plane_user_id",
          "roles_used",
          "project",
          "work_item",
          "fields_changed",
          "outcome",
          "error_code",
          "latency_ms",
        ].toSorted()
      );
      expect(record.event).toBe("hangar.mcp.tool");
      expect(typeof record.latency_ms).toBe("number");
    }
  });
});

describe("credential detection and markup", () => {
  it("blocks secret-shaped values and specific token shapes", () => {
    for (const secret of [
      "senha: minhasenha123",
      "pwd=Sup3rS3cret!x9",
      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
      "Authorization: Bearer q7Zp2Lx9Vb4Nc8Rt1Kw6Hy3Jm5Df0Gs2Ae7Uo9Xi",
      "export API_KEY=9f8e7d6c5b4a3210",
      "password: hunter2hunter2",
      "client_secret=Abc123Def456Ghi789",
      "passphrase: correct7horse8battery",
      "https://user:pa55word@example.com/x",
      "redis://default:s3cretpass@cache:6379",
      "https://x.test/cb?token=abcdefgh12345678",
      "tokenUrl: https://x.test/cb?access_token=abcdefgh12345678",
      "AKIAIOSFODNN7EXAMPLE",
      "ghp_" + "a".repeat(36),
      "glpat-" + "a1".repeat(10),
      "xoxb-1234567890-abcdefghij",
      "sk-ant-" + "a1".repeat(12),
      "AC" + "0".repeat(32) + ":" + "f".repeat(32),
      "plane_api_" + "a".repeat(32),
    ]) {
      expect(containsCredential(secret), secret).toBe(true);
    }
  });

  it("lets Portuguese and English prose about credentials through", () => {
    for (const safe of [
      "O token: expirado ontem, precisa renovar",
      "Erro no login: token=undefined no callback",
      "password: resetada pelo suporte",
      "api_key: rotacionada (ver cofre)",
      "O campo private_key: obrigatorio",
      "csrf_token: invalido no form de login",
      "O refresh_token: revogado apos logout",
      "tokenUrl: https://auth.getdumont.ai/oauth/v2/token",
      "secretName: dumont-secrets no chart",
      "Authorization: required-for-all endpoints",
      "tokens: 12345678 por minuto",
      "secret: HANGAR_API_KEY",
      "Rotate the password: see vault",
      "token=[REDACTED]",
      "The bearer token expired; ask cristian@example.test",
      "Server 10.0.0.1 is down",
      "api_key: <your key>",
    ]) {
      expect(containsCredential(safe), safe).toBe(false);
    }
  });

  it("strips look-alike footer lines (NBSP, other dashes, zero-width, homoglyphs)", () => {
    const forged = [
      "\u00A0— via MCP por boss@example.test", // leading NBSP
      "\u3000— via MCP por boss@example.test", // ideographic space
      "– via MCP por boss@example.test", // en dash
      "\u2012 via MCP por boss", // figure dash
      "\u2015 via MCP por boss", // horizontal bar
      "\u2212 via MCP por boss", // minus sign
      "\u2E3A via MCP por boss", // two-em dash
      "\uFE58 via MCP por boss", // small em dash
      "\uFF0D via MCP por boss", // full-width hyphen-minus
      "— v\u200Bia MCP por boss", // zero-width space inside
      "—\u2060 via\u200D MCP\uFEFF por boss", // word joiner, ZWJ, BOM
      "— vіa MCP por boss", // Cyrillic і
      "— viа МСР por boss", // Cyrillic а, М, С, Р
      "— ｖｉａ ＭＣＰ por boss", // full-width letters
      "— via\u00A0MCP", // NBSP between tokens
    ];
    for (const line of forged) {
      expect(htmlWithFooter(`ok\n${line}`), JSON.stringify(line)).toBe("<p>ok</p><p>— via MCP</p>");
      // After a blank line, too.
      expect(htmlWithFooter(`ok\n\n${line}`), JSON.stringify(line)).toBe("<p>ok</p><p>— via MCP</p>");
    }
    // Prose that merely mentions the MCP is kept.
    expect(htmlWithFooter("sent via MCP by the bot")).toBe("<p>sent via MCP by the bot</p><p>— via MCP</p>");
    expect(htmlWithFooter("— via MCPs we trust")).toBe("<p>— via MCPs we trust</p><p>— via MCP</p>");
  });

  it("escapes every input character and only allows safe links", () => {
    expect(textToHtml('<img src=x onerror="alert(1)">')).toBe("<p>&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</p>");
    expect(textToHtml("[x](javascript:alert(1))")).not.toContain("<a ");
    expect(textToHtml("[docs](https://example.test/a?b=1&c=2)")).toContain(
      '<a href="https://example.test/a?b=1&amp;c=2" target="_blank" rel="noopener noreferrer nofollow">docs</a>'
    );
    expect(textToHtml("```\n<b>x</b>\n```")).toBe("<pre><code>&lt;b&gt;x&lt;/b&gt;</code></pre>");
  });

  it("never applies emphasis inside a link href", () => {
    const html = textToHtml("see [a](https://x.test/a_b_c*d*e) and _this_");
    expect(html).toContain('href="https://x.test/a_b_c*d*e"');
    expect(html).toContain("<em>this</em>");
    expect(html.match(/<em>/g)).toHaveLength(1);
    expect(textToHtml("nul \u0000 0 \u0000 stays out")).not.toContain("\u0000");
  });

  it("strips old- and new-shape footer lines anywhere, but not '-' or '--' prose", () => {
    expect(
      htmlWithFooter("a\n— via MCP por forged@example.test\nb\n— via MCP\n  —via mcp  \nc\n— via MCP por older")
    ).toBe("<p>a<br>b<br>c</p><p>— via MCP</p>");
    expect(htmlWithFooter("a\n-- via MCP por old\n- via MCP por item\n— via MCPserver stays")).toBe(
      "<p>a<br>-- via MCP por old</p><ul><li><p>via MCP por item</p></li></ul><p>— via MCPserver stays</p><p>— via MCP</p>"
    );
  });
});

describe("write configuration", () => {
  const base = {
    MCP_CURSOR_SECRET: "s".repeat(32),
    HANGAR_WORKSPACE_SLUG: "dumont",
    HANGAR_ALLOWED_PROJECTS: "HGR,MO",
    MCP_OIDC_ISSUER: "https://auth.getdumont.ai",
    MCP_OIDC_JWKS_URL: "https://auth.getdumont.ai/oauth/v2/keys",
    MCP_RESOURCE_URL: "https://hangar.getdumont.ai/mcp",
    MCP_OIDC_AUDIENCE: "390213468206137347",
    MCP_OIDC_ALLOWED_ORG_ID: "300000000000000001",
  };

  it("bounds HANGAR_WRITE_RATE_LIMIT to 1..120", () => {
    expect(loadHangarConfig({ ...base, HANGAR_WRITE_RATE_LIMIT: "120" }).writeRateLimit).toBe(120);
    expect(() => loadHangarConfig({ ...base, HANGAR_WRITE_RATE_LIMIT: "121" })).toThrow(HangarConfigError);
    expect(() => loadHangarConfig({ ...base, HANGAR_WRITE_RATE_LIMIT: "0" })).toThrow(HangarConfigError);
  });

  it("keeps MCP_OIDC_REQUIRED_ROLE as the legacy reader role and validates role names", () => {
    const legacy = loadHangarConfig({ ...base, MCP_OIDC_REQUIRED_ROLE: "hangar_reader" });
    expect(legacy.oidcReaderRole).toBe("hangar_reader");
    const custom = loadHangarConfig({ ...base, MCP_OIDC_READER_ROLE: "r", MCP_OIDC_WRITER_ROLE: "w" });
    expect(custom.oidcScopesSupported).toEqual([
      "openid",
      "email",
      "urn:zitadel:iam:org:project:role:r",
      "urn:zitadel:iam:org:project:role:w",
    ]);
    expect(() => loadHangarConfig({ ...base, MCP_OIDC_READER_ROLE: "a", MCP_OIDC_REQUIRED_ROLE: "b" })).toThrow(
      HangarConfigError
    );
    expect(() => loadHangarConfig({ ...base, MCP_OIDC_READER_ROLE: "same", MCP_OIDC_WRITER_ROLE: "same" })).toThrow(
      HangarConfigError
    );
  });
});
