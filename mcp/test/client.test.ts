import { describe, expect, it } from "vitest";
import { SubjectCache } from "../src/cache.js";
import { HangarClient } from "../src/client.js";
import type { UpstreamCaller } from "../src/types.js";
import {
  HGR_PROJECT,
  HGR_WORK_ITEM,
  ME_USER_ID,
  PROJECT_HGR,
  PROJECT_SEC,
  SECRET_PROJECT,
  TEST_ACCESS_TOKEN,
  callerFor,
  hangarFetch,
  jsonResponse,
  testConfig,
} from "./fixtures.js";

type Fetcher = (input: string | URL, init?: RequestInit) => Promise<Response>;
type ConfigOverrides = Parameters<typeof testConfig>[0];

const ALICE = { sub: "alice-sub" };
const BOB = { sub: "bob-sub" };

function client(
  overrides: ConfigOverrides = {},
  fetcher?: Fetcher,
  options: { caller?: UpstreamCaller; cache?: SubjectCache; now?: () => number } = {}
) {
  const calls: URL[] = [];
  const config = testConfig(overrides);
  const hangar = new HangarClient(config, options.caller ?? callerFor(ALICE), {
    fetch: fetcher ?? hangarFetch(calls),
    ...(options.cache ? { cache: options.cache } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
  return { client: hangar, calls, config };
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

describe("Hangar client project ceiling and resolution", () => {
  it("lists only projects inside the ceiling", async () => {
    const { client: hangar } = client();
    const page = await hangar.listProjects(50);
    expect(page.results.map((record) => record.identifier)).toEqual(["HGR"]);
    expect(page.nextCursor).toBeNull();
  });

  it("has no ceiling when HANGAR_ALLOWED_PROJECTS is empty: whatever Hangar shows the user", async () => {
    const { client: hangar } = client({ allowedProjects: [] });
    const page = await hangar.listProjects(50);
    expect(page.results.map((record) => record.identifier)).toEqual(["HGR", "SEC"]);
    await expect(hangar.resolveProject("SEC")).resolves.toMatchObject({ id: PROJECT_SEC });
  });

  it("resolves identifiers case-insensitively and refuses projects outside the ceiling", async () => {
    const { client: hangar } = client();
    await expect(hangar.resolveProject("hgr")).resolves.toMatchObject({ id: PROJECT_HGR });
    await expect(hangar.resolveProject(PROJECT_HGR)).resolves.toMatchObject({ identifier: "HGR" });
    await expect(hangar.resolveProject("SEC")).rejects.toMatchObject({ code: "PROJECT_NOT_ALLOWED" });
    await expect(hangar.resolveProject("NOPE")).rejects.toMatchObject({
      code: "PROJECT_NOT_FOUND",
      message: expect.stringContaining("hangar.project.nope.member"),
    });
  });

  it("treats an empty project list as legitimate (a user with no projects yet)", async () => {
    const { client: hangar } = client({ allowedProjects: [] }, async () => projectsPage());
    await expect(hangar.listProjects(10)).resolves.toEqual({ results: [], nextCursor: null });
    await expect(hangar.searchWorkItems("x", 10, undefined)).rejects.toMatchObject({ code: "PROJECT_NOT_FOUND" });
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

  it("refuses an identifier that resolves outside the ceiling", async () => {
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

describe("Hangar client acts as the caller", () => {
  it("forwards the caller's own token as Authorization: Bearer and never an x-api-key", async () => {
    const seen: RequestInit[] = [];
    const fetcher: Fetcher = async (_input, init) => {
      seen.push(init ?? {});
      return projectsPage(HGR_PROJECT);
    };
    const { client: hangar } = client({}, fetcher);
    await hangar.listProjects(10);
    const headers = seen[0]?.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${TEST_ACCESS_TOKEN}`);
    expect(Object.keys(headers).map((name) => name.toLowerCase())).not.toContain("x-api-key");
    expect(seen[0]?.redirect).toBe("error");
  });

  it("refuses to forward an opaque (introspected) token, before any network call", async () => {
    let calls = 0;
    const { client: hangar } = client(
      {},
      async () => {
        calls += 1;
        return projectsPage(HGR_PROJECT);
      },
      { caller: callerFor(ALICE, null) }
    );
    await expect(hangar.listProjects(10)).rejects.toMatchObject({
      code: "TOKEN_NOT_FORWARDABLE",
      message: expect.stringContaining("pinned"),
    });
    await expect(hangar.currentUserId()).rejects.toMatchObject({ code: "TOKEN_NOT_FORWARDABLE" });
    expect(calls).toBe(0);
  });

  it("resolves the current user through GET /api/v1/users/me/ and caches it per subject", async () => {
    const { client: hangar, calls } = client();
    expect(hangar.cachedUserId()).toBeNull();
    expect(await hangar.currentUserId()).toBe(ME_USER_ID);
    expect(await hangar.currentUserId()).toBe(ME_USER_ID);
    expect(calls.filter((url) => url.pathname === "/api/v1/users/me/")).toHaveLength(1);
    expect(hangar.cachedUserId()).toBe(ME_USER_ID);
  });

  it("never serves user A's cached project list or members to user B", async () => {
    const cache = new SubjectCache(60_000);
    const aliceCalls: string[] = [];
    const bobCalls: string[] = [];
    const recorder =
      (log: string[], projects: unknown[], members: unknown[]): Fetcher =>
      async (input, init) => {
        const url = new URL(String(input));
        const headers = (init?.headers ?? {}) as Record<string, string>;
        log.push(`${url.pathname}|${headers.Authorization}`);
        if (url.pathname.endsWith("/projects/")) return projectsPage(...projects);
        if (url.pathname.endsWith("/workspaces/dumont/members/")) return jsonResponse(members);
        return jsonResponse({}, 404);
      };
    const alice = client(
      { allowedProjects: [] },
      recorder(aliceCalls, [HGR_PROJECT, SECRET_PROJECT], [{ id: "user-1", display_name: "Secret Sam" }]),
      { cache, caller: callerFor(ALICE, "alice-token") }
    ).client;
    const bob = client({ allowedProjects: [] }, recorder(bobCalls, [HGR_PROJECT], []), {
      cache,
      caller: callerFor(BOB, "bob-token"),
    }).client;

    expect((await alice.listProjects(50)).results.map((record) => record.identifier)).toEqual(["HGR", "SEC"]);
    await expect(alice.resolveProject("SEC")).resolves.toMatchObject({ id: PROJECT_SEC });
    expect((await alice.listMembers(undefined, 10)).results).toHaveLength(1);
    const aliceFetches = aliceCalls.length;

    // Bob shares the process cache but gets his own Hangar answer, with his token.
    await expect(bob.resolveProject("SEC")).rejects.toMatchObject({ code: "PROJECT_NOT_FOUND" });
    expect((await bob.listMembers(undefined, 10)).results).toEqual([]);
    expect(bobCalls.length).toBeGreaterThan(0);
    expect(bobCalls.every((line) => line.endsWith("|Bearer bob-token"))).toBe(true);

    // Alice's entries are still served to Alice from the cache (no refetch).
    await expect(alice.resolveProject("SEC")).resolves.toMatchObject({ id: PROJECT_SEC });
    expect(aliceCalls.length).toBe(aliceFetches);
    expect(aliceCalls.every((line) => line.endsWith("|Bearer alice-token"))).toBe(true);
  });

  it("binds pagination cursors to the caller subject", async () => {
    const cache = new SubjectCache(60_000);
    const twoProjects: Fetcher = async () => projectsPage(HGR_PROJECT, SECRET_PROJECT);
    const alice = client({ allowedProjects: [] }, twoProjects, { cache, caller: callerFor(ALICE) }).client;
    const bob = client({ allowedProjects: [] }, twoProjects, { cache, caller: callerFor(BOB) }).client;
    const first = await alice.listProjects(1);
    expect(first.nextCursor).toMatch(/^hmc1\./);
    await expect(alice.listProjects(1, first.nextCursor!)).resolves.toMatchObject({
      results: [{ identifier: "SEC" }],
    });
    await expect(bob.listProjects(1, first.nextCursor!)).rejects.toMatchObject({ code: "INVALID_CURSOR" });
    // Same subject, different MCP_CURSOR_SECRET: refused as well.
    const rotated = client(
      { allowedProjects: [], cursorSecret: "another-cursor-secret-".padEnd(40, "y") },
      twoProjects,
      {
        caller: callerFor(ALICE),
      }
    ).client;
    await expect(rotated.listProjects(1, first.nextCursor!)).rejects.toMatchObject({ code: "INVALID_CURSOR" });
  });
});

describe("Hangar client maps Hangar errors for the user", () => {
  it("tells an unlinked user to sign in once to Hangar web", async () => {
    const { client: hangar } = client({}, async () =>
      jsonResponse({ error_code: "DUMONT_ACCOUNT_NOT_LINKED", error: "Sign in once at https://x" }, 401)
    );
    await expect(hangar.listProjects(10)).rejects.toMatchObject({
      code: "ACCOUNT_NOT_LINKED",
      retryable: false,
      message: expect.stringContaining("sign in once at https://hangar.example.test with Dumont login"),
    });
  });

  it("reports a Plane 401 on a live token as UPSTREAM_UNAUTHORIZED, and near expiry as retryable TOKEN_EXPIRED", async () => {
    const unauthorized: Fetcher = async () => jsonResponse({ detail: "secret upstream detail" }, 401);
    const nowMs = 1_800_000_000_000;
    const live = client({}, unauthorized, {
      caller: callerFor(ALICE, TEST_ACCESS_TOKEN, nowMs / 1000 + 600),
      now: () => nowMs,
    }).client;
    const failure = await live.listProjects(10).catch((error) => error as Error & { code: string });
    expect(failure).toMatchObject({ code: "UPSTREAM_UNAUTHORIZED", retryable: false });
    expect(String(failure.message)).not.toContain("secret upstream detail");

    const expiring = client({}, unauthorized, {
      caller: callerFor(ALICE, TEST_ACCESS_TOKEN, nowMs / 1000 + 5),
      now: () => nowMs,
    }).client;
    await expect(expiring.listProjects(10)).rejects.toMatchObject({ code: "TOKEN_EXPIRED", retryable: true });
  });

  it("maps writer-role, project and managed 403s", async () => {
    const forbidden =
      (body: Record<string, unknown>): Fetcher =>
      async (input, init) => {
        const url = new URL(String(input));
        if (init?.method === "GET" && url.pathname.endsWith("/projects/")) return projectsPage(HGR_PROJECT);
        return jsonResponse(body, 403);
      };
    const writerRole = client({}, forbidden({ error_code: "DUMONT_WRITER_ROLE_REQUIRED" })).client;
    const project = await writerRole.resolveProject("HGR");
    await expect(writerRole.addComment(project, HGR_WORK_ITEM.id, "<p>x</p>")).rejects.toMatchObject({
      code: "WRITER_ROLE_REQUIRED",
      message: expect.stringContaining("hangar_writer"),
    });

    const noMember = client({}, forbidden({ detail: "You do not have permission" })).client;
    await expect(noMember.listStates("HGR", 10)).rejects.toMatchObject({
      code: "PROJECT_ACCESS_DENIED",
      message: "No read access to project HGR in Hangar; ask for the role hangar.project.hgr.member in Dumont Auth",
    });
    await expect(noMember.getWorkItemByIdentifier("HGR-5")).rejects.toMatchObject({ code: "PROJECT_ACCESS_DENIED" });

    const managed = client({}, forbidden({ error_code: "DUMONT_MANAGED_BY_ZITADEL", error: "x" })).client;
    await expect(managed.listStates("HGR", 10)).rejects.toMatchObject({
      code: "UPSTREAM_FORBIDDEN",
      message: expect.stringContaining("Dumont Auth"),
    });
  });

  it("keeps 5xx retryable for reads", async () => {
    const { client: hangar } = client({}, async () => jsonResponse({ error: "down" }, 503));
    await expect(hangar.listProjects(10)).rejects.toMatchObject({ code: "UPSTREAM_UNAVAILABLE", retryable: true });
  });

  it("refuses an oversized upstream response before parsing it", async () => {
    const { client: hangar } = client({ maxResponseBytes: 1024 }, oversizedResponse);
    await expect(hangar.listProjects(10)).rejects.toMatchObject({ code: "UPSTREAM_RESPONSE_TOO_LARGE" });
  });

  it("aborts an upstream call that exceeds the timeout", async () => {
    const { client: hangar } = client({ timeoutMs: 50 }, stalledCall);
    await expect(hangar.listProjects(10)).rejects.toMatchObject({ code: "UPSTREAM_TIMEOUT", retryable: true });
  });
});

describe("per-subject cache", () => {
  it("expires entries, bounds subjects and is disabled with a zero TTL", () => {
    let now = 0;
    const cache = new SubjectCache(1000, 2, () => now);
    cache.set("a", "projects", ["A"]);
    expect(cache.get("a", "projects")).toEqual(["A"]);
    expect(cache.get("b", "projects")).toBeUndefined();
    now = 1000;
    expect(cache.get("a", "projects")).toBeUndefined();
    cache.set("a", "me", "1");
    cache.set("b", "me", "2");
    cache.set("c", "me", "3");
    expect(cache.size).toBe(2);
    expect(cache.get("a", "me")).toBeUndefined();
    expect(cache.get("c", "me")).toBe("3");
    const off = new SubjectCache(0);
    off.set("a", "me", "1");
    expect(off.get("a", "me")).toBeUndefined();
  });
});
