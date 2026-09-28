// Post-deploy READ-ONLY smoke with a short-lived OIDC access token: initialize,
// list the tool catalog, and read the project list. It never calls a write
// tool. Prints only outcome codes and counts, never the token.
const endpoint = process.env.MCP_URL?.trim() || `http://127.0.0.1:${process.env.MCP_HTTP_PORT || "3014"}/mcp`;
const token = process.env.MCP_AUTH_TOKEN?.trim() || "";
const EXPECTED_TOOLS = 12;
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
  tools.length !== EXPECTED_TOOLS ||
  tools.some((tool) => typeof tool?.name !== "string" || !tool.name.startsWith("hangar_"))
) {
  fail("MCP_TOOLS_LIST_FAILED");
}

const call = await rpc({
  jsonrpc: "2.0",
  id: 3,
  method: "tools/call",
  params: { name: "hangar_list_projects", arguments: { limit: 1, response_format: "json" } },
});
const structured = call?.body?.result?.structuredContent;
if (!structured || call.body?.result?.isError === true || !Array.isArray(structured.results)) {
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
