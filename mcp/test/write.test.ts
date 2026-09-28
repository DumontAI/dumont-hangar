import { InMemoryTransport, type JSONRPCMessage } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";
import { WriteRateLimiter, type AuditRecord } from "../src/access.js";
import { HangarClient } from "../src/client.js";
import { HangarConfigError, loadHangarConfig } from "../src/config.js";
import { htmlWithFooter, textToHtml } from "../src/markup.js";
import { containsCredential } from "../src/redaction.js";
import { createHangarServer, IDEMPOTENCY_EXTERNAL_SOURCE } from "../src/tools.js";
import type { HangarConfig, Principal } from "../src/types.js";
import {
  HGR_WORK_ITEM,
  PROJECT_HGR,
  PROJECT_SEC,
  READER,
  WORK_ITEM_HGR_5,
  WRITER,
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

function writeFetch(writes: WriteCall[], options: { conflict?: boolean } = {}) {
  const reads = hangarFetch([]);
  return async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
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
      if (/\/projects\/[0-9a-f-]+\/$/.test(url.pathname) && url.pathname.includes(PROJECT_SEC)) {
        return jsonResponse({ id: PROJECT_SEC, identifier: "SEC", name: "Dumont Secrets" });
      }
      return reads(input, init);
    }
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    writes.push({ method, path: url.pathname, body });
    if (method === "POST" && url.pathname.endsWith("/comments/")) {
      return jsonResponse(
        { id: COMMENT_ID, comment_html: body.comment_html, created_by: "bot", created_at: "2026-09-28T00:00:00Z" },
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
  readonly writes: WriteCall[];
  readonly audit: AuditRecord[];
}

async function harness(
  principal: Principal | null,
  configOverrides: Partial<HangarConfig> = { writeProjects: ["HGR"] },
  options: { conflict?: boolean; rateLimiter?: WriteRateLimiter } = {}
): Promise<Harness> {
  const config = testConfig({ allowedProjects: ["HGR", "SEC"], ...configOverrides });
  const writes: WriteCall[] = [];
  const audit: AuditRecord[] = [];
  const client = new HangarClient(config, writeFetch(writes, options));
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

    const writerOnly = await harness({ sub: "w", email: null, roles: ["hangar_writer"] });
    const readByWriter = await writerOnly.call("hangar_list_projects", { limit: 5 });
    expect(readByWriter.isError).toBeUndefined();
    expect(writerOnly.audit.at(-1)).toMatchObject({ roles_used: ["hangar_writer"] });
  });

  it("denies every tool when there is no principal", async () => {
    const h = await harness(null);
    expect(errorCode(await h.call("hangar_list_projects", { limit: 5 }))).toBe("FORBIDDEN");
  });

  it("returns WRITES_DISABLED when HANGAR_WRITE_PROJECTS is empty", async () => {
    const h = await harness(WRITER, { writeProjects: [] });
    for (const [tool, args] of [
      ["hangar_create_work_item", { project: "HGR", name: "x" }],
      ["hangar_update_work_item", { work_item: "HGR-5", name: "x" }],
      ["hangar_add_comment", { work_item: "HGR-5", body: "hi" }],
    ] as const) {
      // The harness routes one response at a time, so calls stay sequential.
      // oxlint-disable-next-line no-await-in-loop
      expect(errorCode(await h.call(tool, args))).toBe("WRITES_DISABLED");
    }
    expect(h.writes).toHaveLength(0);
  });

  it("refuses a writer in a readable but non-writable project with PROJECT_NOT_WRITABLE", async () => {
    const h = await harness(WRITER, { writeProjects: ["HGR"] });
    const result = await h.call("hangar_create_work_item", { project: "SEC", name: "x" });
    expect(errorCode(result)).toBe("PROJECT_NOT_WRITABLE");
    expect(h.writes).toHaveLength(0);
    expect(h.audit.at(-1)).toMatchObject({ outcome: "denied", error_code: "PROJECT_NOT_WRITABLE" });
  });

  it("refuses a project outside the read allowlist with PROJECT_NOT_ALLOWED", async () => {
    const h = await harness(WRITER, { allowedProjects: ["HGR"], writeProjects: ["HGR"] });
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
    const h = await harness(WRITER, { writeProjects: ["HGR"] }, { rateLimiter: limiter });
    expect((await h.call("hangar_add_comment", { work_item: "HGR-5", body: "one" })).isError).toBeUndefined();
    expect((await h.call("hangar_add_comment", { work_item: "HGR-5", body: "two" })).isError).toBeUndefined();
    const third = await h.call("hangar_add_comment", { work_item: "HGR-5", body: "three" });
    expect(errorCode(third)).toBe("RATE_LIMITED");
    expect((third.structuredContent as { error: { retryable: boolean } }).error.retryable).toBe(true);
    expect(h.writes).toHaveLength(2);
    // Reads are not rate-limited, and another subject has its own window.
    expect((await h.call("hangar_list_projects", { limit: 1 })).isError).toBeUndefined();
    const other = await harness(
      { ...WRITER, sub: "someone-else" },
      { writeProjects: ["HGR"] },
      { rateLimiter: limiter }
    );
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
  it("creates a work item with resolved ids, safe HTML and one attribution footer", async () => {
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
      assignees: ["user-1", "user-2"],
      parent: WORK_ITEM_HGR_5,
      start_date: "2026-09-28",
      target_date: "2026-10-01",
    });
    const html = String(write.body.description_html);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("<ul><li><p>one</p></li><li><p><strong>two</strong></p></li></ul>");
    expect(html.endsWith("<p>— via MCP por cristian@example.test</p>")).toBe(true);
    expect(write.body.external_id).toBeUndefined();
    expect(h.audit.at(-1)).toMatchObject({
      tool: "hangar_create_work_item",
      sub: WRITER.sub,
      email: WRITER.email,
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

  it("adds the footer with the subject when the token has no email, and on an empty description", async () => {
    const h = await harness({ sub: "sub-123", email: null, roles: ["hangar_writer"] });
    await h.call("hangar_create_work_item", { project: "HGR", name: "No description" });
    expect(h.writes[0]!.body.description_html).toBe("<p>— via MCP por sub-123</p>");
  });

  it('refuses assignee "me" without an email claim', async () => {
    const h = await harness({ sub: "sub-123", email: null, roles: ["hangar_writer"] });
    const result = await h.call("hangar_create_work_item", { project: "HGR", name: "x", assignees: ["me"] });
    expect(errorCode(result)).toBe("FORBIDDEN");
    expect(h.writes).toHaveLength(0);
  });

  it("maps idempotency_key to a per-user external_id and returns the existing item on 409", async () => {
    const h = await harness(WRITER, { writeProjects: ["HGR"] }, { conflict: true });
    const result = await h.call("hangar_create_work_item", { project: "HGR", name: "x", idempotency_key: "run-42" });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({ id: EXISTING_ID, identifier: "HGR-7", idempotent_replay: true });
    expect(h.writes[0]!.body.external_source).toBe(IDEMPOTENCY_EXTERNAL_SOURCE);
    expect(String(h.writes[0]!.body.external_id)).toMatch(/^[0-9a-f]{16}:run-42$/);
  });

  it("updates only the given fields and never stacks the footer", async () => {
    const h = await harness(WRITER);
    const copied = "Updated text\n\n— via MCP por someone@example.test\n";
    const result = await h.call("hangar_update_work_item", {
      work_item: "HGR-5",
      description: copied,
      state: "Todo",
      target_date: null,
    });
    expect(result.isError).toBeUndefined();
    const write = h.writes[0]!;
    expect(write.method).toBe("PATCH");
    expect(write.path).toBe(`/api/v1/workspaces/dumont/projects/${PROJECT_HGR}/issues/${WORK_ITEM_HGR_5}/`);
    expect(Object.keys(write.body).toSorted()).toEqual(["description_html", "state", "target_date"]);
    const html = String(write.body.description_html);
    expect(html.match(/via MCP por/g)).toHaveLength(1);
    expect(html).toBe("<p>Updated text</p><p>— via MCP por cristian@example.test</p>");
    expect(h.audit.at(-1)).toMatchObject({
      work_item: "HGR-5",
      fields_changed: ["description", "state", "target_date"],
    });
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
      body: { comment_html: "<p>Looks good</p><p>— via MCP por cristian@example.test</p>" },
    });
    expect(result.structuredContent).toMatchObject({ id: COMMENT_ID, work_item: "HGR-5" });
  });

  it("never writes text bodies, tokens or the API key into the audit line", async () => {
    const h = await harness(WRITER);
    const config = testConfig();
    await h.call("hangar_create_work_item", { project: "HGR", name: SENTINEL, description: SENTINEL });
    await h.call("hangar_update_work_item", { work_item: "HGR-5", name: SENTINEL, description: SENTINEL });
    await h.call("hangar_add_comment", { work_item: "HGR-5", body: SENTINEL });
    await h.call("hangar_search_work_items", { query: SENTINEL });
    await h.call("hangar_get_project", { project: SENTINEL.slice(0, 20) });
    expect(h.audit).toHaveLength(5);
    const serialized = JSON.stringify(h.audit);
    expect(serialized).not.toContain(SENTINEL);
    expect(serialized).not.toContain(SENTINEL.slice(0, 20));
    expect(serialized).not.toContain(config.apiKey);
    for (const record of h.audit) {
      expect(Object.keys(record).toSorted()).toEqual(
        [
          "ts",
          "event",
          "tool",
          "sub",
          "email",
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
  it("flags credential shapes and ignores prose, key names and placeholders", () => {
    for (const secret of [
      "Authorization: Bearer abcdefghijklmnop1234",
      "export API_KEY=9f8e7d6c5b4a3210",
      "password: hunter2hunter2",
      "https://user:pa55word@example.com/x",
      "redis://default:s3cretpass@cache:6379",
      "https://x.test/cb?token=abcdefgh12345678",
      "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl",
      "-----BEGIN RSA PRIVATE KEY-----",
      "AKIAIOSFODNN7EXAMPLE",
      "ghp_" + "a".repeat(36),
      "plane_api_" + "a".repeat(32),
    ]) {
      expect(containsCredential(secret), secret).toBe(true);
    }
    for (const safe of [
      "Rotate the password: see vault",
      "Set the GitHub secret: HANGAR_MCP_API_KEY",
      "token=[REDACTED]",
      "The bearer token expired; ask cristian@example.test",
      "Server 10.0.0.1 is down",
      "api_key: <your key>",
    ]) {
      expect(containsCredential(safe), safe).toBe(false);
    }
  });

  it("escapes every input character and only allows safe links", () => {
    expect(textToHtml('<img src=x onerror="alert(1)">')).toBe("<p>&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</p>");
    expect(textToHtml("[x](javascript:alert(1))")).not.toContain("<a ");
    expect(textToHtml("[docs](https://example.test/a?b=1&c=2)")).toContain(
      '<a href="https://example.test/a?b=1&amp;c=2" target="_blank" rel="noopener noreferrer nofollow">docs</a>'
    );
    expect(textToHtml("```\n<b>x</b>\n```")).toBe("<pre><code>&lt;b&gt;x&lt;/b&gt;</code></pre>");
    expect(htmlWithFooter("a\n-- via MCP por old\n— via MCP por older", "me@x.test")).toBe(
      "<p>a</p><p>— via MCP por me@x.test</p>"
    );
  });
});

describe("write configuration", () => {
  const base = {
    HANGAR_API_KEY: "plane_api_" + "a".repeat(32),
    HANGAR_WORKSPACE_SLUG: "dumont",
    HANGAR_ALLOWED_PROJECTS: "HGR,MO",
    MCP_OIDC_ISSUER: "https://auth.getdumont.ai",
    MCP_OIDC_JWKS_URL: "https://auth.getdumont.ai/oauth/v2/keys",
    MCP_RESOURCE_URL: "https://hangar.getdumont.ai/mcp",
    MCP_OIDC_AUDIENCE: "390213468206137347",
  };

  it("requires HANGAR_WRITE_PROJECTS to be a subset of HANGAR_ALLOWED_PROJECTS", () => {
    expect(loadHangarConfig({ ...base, HANGAR_WRITE_PROJECTS: "hgr" }).writeProjects).toEqual(["HGR"]);
    expect(() => loadHangarConfig({ ...base, HANGAR_WRITE_PROJECTS: "HGR,SEC" })).toThrow(HangarConfigError);
    expect(() => loadHangarConfig({ ...base, HANGAR_WRITE_PROJECTS: PROJECT_HGR })).toThrow(/subset/);
    expect(() => loadHangarConfig({ ...base, HANGAR_WRITE_PROJECTS: "not a project" })).toThrow(HangarConfigError);
    expect(loadHangarConfig({ ...base, HANGAR_WRITE_PROJECTS: "" }).writeProjects).toEqual([]);
  });

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
