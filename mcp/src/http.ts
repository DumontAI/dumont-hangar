import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { assertHttpAuthConfigured, loadHangarConfig } from "./config.js";
import {
  authorizationChallenge,
  createAuthorizer,
  type AuthorizerDependencies,
  protectedResourceMetadata,
  protectedResourceMetadataPaths,
} from "./auth.js";
import { WriteRateLimiter } from "./access.js";
import { HangarClient } from "./client.js";
import { isMainModule } from "./runtime.js";
import { createHangarServer } from "./tools.js";
import { HangarError, type HangarConfig, type Principal } from "./types.js";

const MAX_REQUEST_BYTES = 1024 * 1024;

function responseError(
  res: ServerResponse,
  status: number,
  message: string,
  headers: Record<string, string> = {}
): void {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", ...headers });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message }, id: null }));
}

function requestPath(req: IncomingMessage): string {
  return (req.url ?? "").split("?", 1)[0] ?? "";
}

function responseMetadata(res: ServerResponse, metadata: Record<string, unknown>): void {
  res.writeHead(200, {
    "cache-control": "public, max-age=300",
    "content-type": "application/json; charset=utf-8",
  });
  res.end(JSON.stringify(metadata));
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const declaredLength = Number(req.headers["content-length"]);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) {
    throw new HangarError("REQUEST_TOO_LARGE", "The MCP request exceeded the configured safety limit");
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_REQUEST_BYTES)
      throw new HangarError("REQUEST_TOO_LARGE", "The MCP request exceeded the configured safety limit");
    chunks.push(bytes);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new HangarError("INVALID_REQUEST", "The MCP request body must be valid JSON");
  }
}

export type HangarServerFactory = (principal: Principal) => ReturnType<typeof createHangarServer>;

export function createHangarHttpServer(
  config: HangarConfig = loadHangarConfig(),
  serverFactory?: HangarServerFactory,
  authorizerDependencies: AuthorizerDependencies = {}
): Server {
  assertHttpAuthConfigured(config);
  // One limiter per process so the per-user write window spans requests (each
  // request gets its own stateless McpServer).
  const rateLimiter = new WriteRateLimiter(config.writeRateLimit);
  const factory: HangarServerFactory =
    serverFactory ?? ((principal) => createHangarServer(config, new HangarClient(config), { principal, rateLimiter }));
  const authorize = createAuthorizer(config, authorizerDependencies);
  const metadata = protectedResourceMetadata(config);
  const metadataPaths = protectedResourceMetadataPaths(config);
  return createServer(async (req, res) => {
    const path = requestPath(req);
    if (metadata && metadataPaths.includes(path)) {
      if (req.method !== "GET") {
        responseError(res, 405, "Protected resource metadata only accepts GET");
        return;
      }
      responseMetadata(res, metadata);
      return;
    }
    if (path !== "/mcp") {
      responseError(res, 404, "Not found");
      return;
    }
    const authorization = await authorize(req);
    if (authorization.failure === "temporarily_unavailable") {
      responseError(res, 503, "MCP authorization is temporarily unavailable", { "retry-after": "1" });
      return;
    }
    if (authorization.failure || !authorization.principal) {
      const failure = authorization.failure ?? "invalid_credentials";
      const status = failure === "insufficient_scope" ? 403 : 401;
      const challenge = authorizationChallenge(config, failure);
      responseError(
        res,
        status,
        status === 403
          ? "MCP credentials do not have the required access"
          : "Missing or invalid MCP credentials or request origin/host",
        challenge ? { "www-authenticate": challenge } : {}
      );
      return;
    }
    const origin = req.headers.origin;
    if (origin && config.allowedOrigins.includes(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    }
    if (req.method !== "POST" && req.method !== "GET" && req.method !== "DELETE") {
      responseError(res, 405, "MCP endpoint accepts POST, GET, or DELETE");
      return;
    }

    try {
      const body = req.method === "POST" ? await readJsonBody(req) : undefined;
      const server = factory(authorization.principal);
      const transport = new NodeStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      if (error instanceof HangarError && error.code === "REQUEST_TOO_LARGE") {
        responseError(res, 413, error.message);
      } else if (error instanceof HangarError && error.code === "INVALID_REQUEST") {
        responseError(res, 400, error.message);
      } else {
        responseError(res, 500, "MCP request could not be completed");
      }
    }
  });
}

export async function startHttp(): Promise<Server> {
  const config = loadHangarConfig();
  const server = createHangarHttpServer(config);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.httpPort, config.httpHost, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return server;
}

if (isMainModule(import.meta.url)) {
  startHttp().catch((error) => {
    const message = error instanceof Error ? error.message : "Hangar MCP HTTP server failed to start";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
