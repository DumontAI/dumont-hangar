// Post-deploy READ-ONLY smoke with a short-lived OIDC access token: initialize,
// list the tool catalog, and read the project list. It never calls a write
// tool. Prints only outcome codes and counts, never the token.
//
// The MCP forwards this token to Hangar and acts as its user. It can be a JWT
// from the pinned public client or an opaque token from a DCR client (Codex,
// OpenCode; run the smoke with both after a deploy), and that user must have
// signed in once to Hangar web with Dumont login. project_count is how many projects THAT
// user sees, capped at 50 (the tool's page limit; 0 is a valid answer for a
// user without projects). A tool error prints its
// code, e.g. HANGAR_PROJECTS_READ_FAILED:ACCOUNT_NOT_LINKED.
const endpoint = process.env.MCP_URL?.trim() || `http://127.0.0.1:${process.env.MCP_HTTP_PORT || "3014"}/mcp`;
const token = process.env.MCP_AUTH_TOKEN?.trim() || "";
// 9 read tools plus 3 write tools (always listed; the writer role gates them per call).
const EXPECTED_TOOL_COUNTS = new Set([12]);
const TOOL_ERROR_CODE = /^[A-Z][A-Z_]{1,63}$/;
const REQUEST_TIMEOUT_MS = 10000;

function fail(code) {
  console.error(JSON.stringify({ ok: false, code }));
  process.exit(1);
}

if (!token || /[\r\n]/.test(token)) fail("MCP_AUTH_TOKEN_REQUIRED");

let parsedEndpoint;
try {
  parsedEndpoint = new URL(endpoint);
  if (
    !["http:", "https:"].includes(parsedEndpoint.protocol) ||
    parsedEndpoint.username ||
    parsedEndpoint.password ||
    parsedEndpoint.search ||
    parsedEndpoint.hash ||
    parsedEndpoint.pathname !== "/mcp"
  ) {
    throw new Error("invalid endpoint");
  }
} catch {
  fail("MCP_URL_INVALID");
}

async function rpc(message, expectJson = true) {
  let response;
  try {
    response = await fetch(parsedEndpoint, {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    fail("MCP_UNREACHABLE");
    return null;
  }
  const text = await response.text();
  if (!response.ok) {
    fail(`MCP_HTTP_${response.status}`);
    return null;
  }
  if (!expectJson || !text) return { status: response.status, body: null };
  try {
    return { status: response.status, body: JSON.parse(text) };
  } catch {
    fail("MCP_INVALID_JSON");
    return null;
  }
}

const initialize = await rpc({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "hangar-mcp-live-smoke", version: "1" },
  },
});
if (!initialize || initialize.body?.result?.serverInfo?.name !== "hangar-mcp-server") {
  fail("MCP_INITIALIZE_FAILED");
}

await rpc({ jsonrpc: "2.0", method: "notifications/initialized" }, false);
const listed = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
const tools = listed?.body?.result?.tools;
if (
  !Array.isArray(tools) ||
  !EXPECTED_TOOL_COUNTS.has(tools.length) ||
  tools.some((tool) => typeof tool?.name !== "string" || !tool.name.startsWith("hangar_"))
) {
  fail("MCP_TOOLS_LIST_FAILED");
}

const call = await rpc({
  jsonrpc: "2.0",
  id: 3,
  method: "tools/call",
  params: { name: "hangar_list_projects", arguments: { limit: 50, response_format: "json" } },
});
const structured = call?.body?.result?.structuredContent;
if (call?.body?.result?.isError === true) {
  // Only a code-shaped value is printed; tool messages are never echoed.
  const code = structured?.error?.code;
  fail(`HANGAR_PROJECTS_READ_FAILED${typeof code === "string" && TOOL_ERROR_CODE.test(code) ? `:${code}` : ""}`);
}
if (!structured || !Array.isArray(structured.results)) {
  fail("HANGAR_PROJECTS_READ_FAILED");
}

console.log(
  JSON.stringify({
    ok: true,
    endpoint: `${parsedEndpoint.origin}${parsedEndpoint.pathname}`,
    initialize_status: initialize.status,
    tools_status: listed.status,
    tool_count: tools.length,
    project_count: structured.results.length,
  })
);
