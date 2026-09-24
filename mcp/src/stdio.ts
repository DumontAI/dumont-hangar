import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import type { Readable, Writable } from "node:stream";
import { createHangarServer } from "./tools.js";
import { loadHangarConfig } from "./config.js";
import { isMainModule } from "./runtime.js";

export async function connectStdio(
  server: ReturnType<typeof createHangarServer>,
  input: Readable = process.stdin,
  output: Writable = process.stdout
): Promise<void> {
  const transport = new StdioServerTransport(input, output);
  await server.connect(transport);
}

export async function startStdio(): Promise<void> {
  const config = loadHangarConfig();
  await connectStdio(createHangarServer(config));
}

if (isMainModule(import.meta.url)) {
  startStdio().catch((error) => {
    const message = error instanceof Error ? error.message : "Hangar MCP server failed to start";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
