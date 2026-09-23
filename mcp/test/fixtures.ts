import type { HangarConfig } from "../src/types.js";

export const PROJECT_HGR = "1f4b7c4b-fe28-441d-a6ce-b3dfe87384b2";
export const PROJECT_SEC = "ac913f1a-fa7f-4c98-848b-b0ae826f7117";
export const WORK_ITEM_HGR_5 = "1b9b5489-3af2-4b16-881b-d4f00bf0f15d";

export const HGR_PROJECT = { id: PROJECT_HGR, identifier: "HGR", name: "Hangar" };
export const SECRET_PROJECT = { id: PROJECT_SEC, identifier: "SEC", name: "Dumont Secrets" };
export const HGR_WORK_ITEM = {
  id: WORK_ITEM_HGR_5,
  project: PROJECT_HGR,
  sequence_id: 5,
  name: "Hangar MCP",
  description_html: "<p>Remote MCP for Hangar</p>",
  priority: "high",
  state: "state-1",
  created_at: "2026-09-23T23:44:47.990877Z",
  updated_at: "2026-09-23T23:44:48.020362Z",
};

export function testConfig(overrides: Partial<HangarConfig> = {}): HangarConfig {
  return {
    baseUrl: new URL("https://hangar.example.test"),
    apiKey: "plane_api_" + "a".repeat(32),
    workspaceSlug: "dumont",
    allowedProjects: ["HGR"],
    timeoutMs: 200,
    maxResponseBytes: 100_000,
    maxSearchPages: 2,
    projectCacheSeconds: 60,
    httpPort: 0,
    httpHost: "127.0.0.1",
    authMode: "static",
    mcpAuthToken: "mcp-test-token",
    allowedOrigins: [],
    allowedHosts: [],
    oidcIssuer: null,
    oidcJwksUrl: null,
    oidcAudience: "",
    oidcRequiredScope: "urn:zitadel:iam:org:project:role:hangar_reader",
    oidcRequiredRole: "hangar_reader",
    oidcAllowedOrgId: "",
    oidcAllowedSubjects: [],
    resourceUrl: null,
    oidcIntrospectionUrl: null,
    oidcIntrospectionAuth: null,
    oidcIntrospectionTimeoutMs: 3000,
    oidcIntrospectionCacheSeconds: 30,
    oidcIntrospectionMaxInFlight: 8,
    oidcIntrospectionRatePerSecond: 20,
    ...overrides,
  };
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function page(results: unknown[]): Response {
  return jsonResponse({ results, next_page_results: false, next_cursor: null });
}

export function hangarFetch(calls: URL[]): (input: string | URL, init?: RequestInit) => Promise<Response> {
  return async (input, init) => {
    const url = new URL(String(input));
    calls.push(url);
    if (init?.method !== "GET") return jsonResponse({ error: "method" }, 405);
    const path = url.pathname;
    if (path.endsWith("/projects/")) return page([HGR_PROJECT, SECRET_PROJECT]);
    if (/\/projects\/[0-9a-f-]+\/$/.test(path)) return jsonResponse(HGR_PROJECT);
    if (path.endsWith("/issues/")) {
      const search = url.searchParams.get("search");
      if (search && search.toLowerCase() !== "mcp" && search.toLowerCase() !== "hangar") return page([]);
      return page([HGR_WORK_ITEM]);
    }
    if (path.endsWith("/states/")) {
      return page([
        { id: "state-1", name: "Todo", group: "unstarted", default: true, sequence: 1 },
        { id: "state-2", name: "Done", group: "completed", default: false, sequence: 2 },
      ]);
    }
    if (path.endsWith("/labels/")) return page([{ id: "label-1", name: "bug", color: "#f00" }]);
    if (path.endsWith("/comments/")) {
      return page([
        {
          id: "comment-1",
          comment_html: "<p>Ping user@example.com about token=super-secret</p>",
          created_by: "user-1",
          created_at: "2026-09-24T00:00:00Z",
        },
      ]);
    }
    if (path.endsWith("/members/") && path.includes("/projects/")) {
      return page([{ id: "user-1", display_name: "Cristian", role: 20 }]);
    }
    if (path.endsWith("/workspaces/dumont/members/")) {
      return jsonResponse([
        { id: "user-1", display_name: "Cristian", first_name: "Cristian", last_name: "", role: 20 },
        { id: "user-2", display_name: "Camila", first_name: "Camila", last_name: "", role: 15 },
      ]);
    }
    if (/\/work-items\/[A-Z0-9]+-[0-9]+\/$/.test(path)) return jsonResponse(HGR_WORK_ITEM);
    if (/\/issues\/[0-9a-f-]+\/$/.test(path)) return jsonResponse(HGR_WORK_ITEM);
    return jsonResponse({ error: "Page not found." }, 404);
  };
}
