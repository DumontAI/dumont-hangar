import { describe, expect, it } from "vitest";
import { HangarClient } from "../src/client.js";
import {
  HGR_PROJECT,
  HGR_WORK_ITEM,
  PROJECT_HGR,
  PROJECT_SEC,
  SECRET_PROJECT,
  hangarFetch,
  jsonResponse,
  testConfig,
} from "./fixtures.js";

type Fetcher = (input: string | URL, init?: RequestInit) => Promise<Response>;
type ConfigOverrides = Parameters<typeof testConfig>[0];

function client(overrides: ConfigOverrides = {}, fetcher?: Fetcher) {
  const calls: URL[] = [];
  const config = testConfig(overrides);
  return { client: new HangarClient(config, fetcher ?? hangarFetch(calls)), calls, config };
}

function projectsPage(...records: unknown[]): Response {
  return jsonResponse({ results: records, next_page_results: false, next_cursor: null });
}

const oversizedResponse: Fetcher = async () =>
  new Response(JSON.stringify({ results: [], padding: "x".repeat(5000) }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

const stalledCall: Fetcher = (_input, init) =>
  new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
  });

describe("Hangar client allowlist and resolution", () => {
  it("lists only allowlisted projects", async () => {
    const { client: hangar } = client();
    const page = await hangar.listProjects(50);
    expect(page.results.map((record) => record.identifier)).toEqual(["HGR"]);
    expect(page.nextCursor).toBeNull();
  });

  it("resolves identifiers case-insensitively and refuses projects outside the allowlist", async () => {
    const { client: hangar } = client();
    await expect(hangar.resolveProject("hgr")).resolves.toMatchObject({ id: PROJECT_HGR });
    await expect(hangar.resolveProject(PROJECT_HGR)).resolves.toMatchObject({ identifier: "HGR" });
    await expect(hangar.resolveProject("SEC")).rejects.toMatchObject({ code: "PROJECT_NOT_ALLOWED" });
    await expect(hangar.resolveProject("NOPE")).rejects.toMatchObject({ code: "PROJECT_NOT_FOUND" });
  });

  it("drops work items that do not belong to the requested project", async () => {
    const fetcher: Fetcher = async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/projects/")) return projectsPage(HGR_PROJECT);
      return jsonResponse({
        results: [{ ...HGR_WORK_ITEM, project: PROJECT_SEC }],
        next_page_results: false,
        next_cursor: null,
      });
    };
    const { client: hangar } = client({}, fetcher);
    const page = await hangar.listWorkItems("HGR", 10, undefined);
    expect(page.results).toEqual([]);
  });

  it("refuses an identifier that resolves outside the allowlist", async () => {
    const fetcher: Fetcher = async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/projects/")) return projectsPage(HGR_PROJECT, SECRET_PROJECT);
      return jsonResponse({ ...HGR_WORK_ITEM, project: PROJECT_SEC });
    };
    const { client: hangar } = client({}, fetcher);
    await expect(hangar.getWorkItemByIdentifier("SEC-1")).rejects.toMatchObject({ code: "PROJECT_NOT_ALLOWED" });
  });
});

describe("Hangar client filters", () => {
  it("resolves state and label names to ids and assigns members by display name", async () => {
    const { client: hangar, calls } = client();
    const page = await hangar.listWorkItems("HGR", 10, undefined, {
      state: "Todo",
      label: "bug",
      assignee: "Cristian",
      priority: "high",
    });
    expect(page.results).toHaveLength(1);
    const issuesCall = calls.find((url) => url.pathname.endsWith("/issues/"));
    expect(issuesCall).toBeDefined();
    expect(issuesCall!.searchParams.get("state")).toBe("state-1");
    expect(issuesCall!.searchParams.get("labels")).toBe("label-1");
    expect(issuesCall!.searchParams.get("assignees")).toBe("user-1");
    expect(issuesCall!.searchParams.get("priority")).toBe("high");
  });

  it("rejects an unknown or ambiguous name instead of guessing", async () => {
    const { client: hangar } = client();
    await expect(hangar.listWorkItems("HGR", 10, undefined, { state: "Missing" })).rejects.toMatchObject({
      code: "INVALID_ARGUMENT",
    });
    const ambiguous: Fetcher = async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/projects/")) return projectsPage(HGR_PROJECT);
      return jsonResponse({
        results: [
          { id: "state-1", name: "Todo" },
          { id: "state-2", name: "todo" },
        ],
        next_page_results: false,
        next_cursor: null,
      });
    };
    const { client: other } = client({}, ambiguous);
    await expect(other.listWorkItems("HGR", 10, undefined, { state: "Todo" })).rejects.toMatchObject({
      code: "INVALID_ARGUMENT",
    });
  });

  it("rejects its own unknown cursors and invalid arguments", async () => {
    const { client: hangar } = client();
    await expect(hangar.listWorkItems("HGR", 10, "not-a-cursor")).rejects.toMatchObject({ code: "INVALID_CURSOR" });
    await expect(hangar.listWorkItems("HGR", 10, undefined, { priority: "blocker" })).rejects.toMatchObject({
      code: "INVALID_ARGUMENT",
    });
  });
});

describe("Hangar client upstream boundary", () => {
  it("maps upstream failures without echoing upstream bodies and keeps retryability", async () => {
    const unauthorized: Fetcher = async () => jsonResponse({ error: "secret upstream detail" }, 401);
    const { client: hangar } = client({}, unauthorized);
    const failure = await hangar.listProjects(10).catch((error) => error as Error & { retryable: boolean });
    expect(failure).toMatchObject({ code: "UPSTREAM_UNAUTHORIZED", retryable: false });
    expect(String(failure.message)).not.toContain("secret upstream detail");

    const unavailable: Fetcher = async () => jsonResponse({ error: "down" }, 503);
    const { client: other } = client({}, unavailable);
    await expect(other.listProjects(10)).rejects.toMatchObject({ code: "UPSTREAM_UNAVAILABLE", retryable: true });
  });

  it("refuses an oversized upstream response before parsing it", async () => {
    const { client: hangar } = client({ maxResponseBytes: 1024 }, oversizedResponse);
    await expect(hangar.listProjects(10)).rejects.toMatchObject({ code: "UPSTREAM_RESPONSE_TOO_LARGE" });
  });

  it("aborts an upstream call that exceeds the timeout", async () => {
    const { client: hangar } = client({ timeoutMs: 50 }, stalledCall);
    await expect(hangar.listProjects(10)).rejects.toMatchObject({ code: "UPSTREAM_TIMEOUT", retryable: true });
  });

  it("sends the API key as x-api-key and never as a bearer token", async () => {
    const seen: RequestInit[] = [];
    const fetcher: Fetcher = async (_input, init) => {
      seen.push(init ?? {});
      return projectsPage(HGR_PROJECT);
    };
    const { client: hangar } = client({}, fetcher);
    await hangar.listProjects(10);
    const headers = seen[0]?.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe(hangar.config.apiKey);
    expect(headers.authorization).toBeUndefined();
  });
});
