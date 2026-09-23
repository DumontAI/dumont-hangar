import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { HangarClient, type WorkItemFilters } from "./client.js";
import { loadHangarConfig } from "./config.js";
import {
  sanitizeComment,
  sanitizeLabel,
  sanitizeMember,
  sanitizeProject,
  sanitizeState,
  sanitizeWorkItem,
} from "./redaction.js";
import { HangarError, type HangarConfig, type JsonRecord, type ResourceName } from "./types.js";

const annotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const outputSchema = z.record(z.string(), z.unknown());
const projectReference = z.string().trim().min(1).max(64);
const workItemReference = z.string().trim().min(1).max(64);
const common = {
  limit: z.number().int().min(1).max(50).default(20),
  cursor: z.string().max(2048).optional(),
  response_format: z.enum(["json", "markdown"]).default("markdown"),
};

export const HANGAR_TOOL_NAMES = [
  "hangar_list_projects",
  "hangar_get_project",
  "hangar_list_work_items",
  "hangar_get_work_item",
  "hangar_search_work_items",
  "hangar_list_work_item_comments",
  "hangar_list_states",
  "hangar_list_labels",
  "hangar_list_members",
] as const;

type ResponseFormat = "json" | "markdown";

function textFor(title: string, value: JsonRecord, format: ResponseFormat): string {
  const json = JSON.stringify(value);
  if (format === "json") return json;
  return `## ${title}\n\n\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\``;
}

function success(value: JsonRecord, title: string, format: ResponseFormat) {
  return {
    structuredContent: value,
    content: [{ type: "text" as const, text: textFor(title, value, format) }],
  };
}

function failure(error: unknown) {
  const safe =
    error instanceof HangarError
      ? { code: error.code, message: error.message, retryable: error.retryable }
      : { code: "INTERNAL_ERROR", message: "Hangar read operation could not be completed", retryable: false };
  const value = { error: safe };
  return {
    isError: true,
    structuredContent: value,
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
  };
}

async function run<T extends JsonRecord>(title: string, format: ResponseFormat, operation: () => Promise<T>) {
  try {
    return success(await operation(), title, format);
  } catch (error) {
    return failure(error);
  }
}

export function createHangarServer(
  config: HangarConfig = loadHangarConfig(),
  client = new HangarClient(config)
): McpServer {
  const server = new McpServer(
    { name: "hangar-mcp-server", version: "0.1.0" },
    {
      instructions:
        "Read-only Hangar (Plane) triage: projects, work items, comments, states, labels and members. Project access is limited by the server allowlist; writes are not available.",
    }
  );

  async function identifierFor(projectId: string | null): Promise<string | null> {
    if (!projectId) return null;
    const project = await client.projectById(projectId);
    return project?.identifier ?? null;
  }

  server.registerTool(
    "hangar_list_projects",
    {
      title: "List Hangar projects",
      description: "List only the Hangar projects in the server-side allowlist.",
      inputSchema: z.object(common),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar projects", args.response_format, async () => {
        const page = await client.listProjects(args.limit, args.cursor);
        return {
          results: page.results.map(sanitizeProject),
          next_cursor: page.nextCursor,
        };
      })
  );

  server.registerTool(
    "hangar_get_project",
    {
      title: "Get a Hangar project",
      description: "Get one allowlisted Hangar project by identifier (like HGR) or UUID.",
      inputSchema: z.object({ project: projectReference, response_format: common.response_format }),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar project", args.response_format, async () => {
        return sanitizeProject(await client.getProject(args.project));
      })
  );

  server.registerTool(
    "hangar_list_work_items",
    {
      title: "List Hangar work items",
      description:
        "List work items of one allowlisted project, newest first unless order_by says otherwise. state/label accept a UUID or an exact name; assignee accepts a member UUID or exact display name.",
      inputSchema: z.object({
        ...common,
        project: projectReference,
        state: z.string().trim().min(1).max(200).optional(),
        assignee: z.string().trim().min(1).max(200).optional(),
        label: z.string().trim().min(1).max(200).optional(),
        priority: z.enum(["urgent", "high", "medium", "low", "none"]).optional(),
        order_by: z
          .enum(["created_at", "-created_at", "updated_at", "-updated_at", "priority", "-priority"])
          .optional(),
        search: z.string().trim().min(1).max(256).optional(),
      }),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar work items", args.response_format, async () => {
        const filters: WorkItemFilters = {
          ...(args.state ? { state: args.state } : {}),
          ...(args.assignee ? { assignee: args.assignee } : {}),
          ...(args.label ? { label: args.label } : {}),
          ...(args.priority ? { priority: args.priority } : {}),
          ...(args.order_by ? { orderBy: args.order_by } : {}),
          ...(args.search ? { search: args.search } : {}),
        };
        const page = await client.listWorkItems(args.project, args.limit, args.cursor, filters);
        const identifier = (await client.resolveProject(args.project)).identifier;
        return {
          results: page.results.map((raw) => sanitizeWorkItem(raw, identifier)),
          next_cursor: page.nextCursor,
        };
      })
  );

  server.registerTool(
    "hangar_get_work_item",
    {
      title: "Get a Hangar work item",
      description: "Get one work item by identifier (like HGR-5) or by UUID. Pass project together with a UUID.",
      inputSchema: z.object({
        work_item: workItemReference,
        project: projectReference.optional(),
        response_format: common.response_format,
      }),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar work item", args.response_format, async () => {
        const raw = args.project
          ? await client.getWorkItemById(args.project, args.work_item)
          : await client.getWorkItemByIdentifier(args.work_item);
        const projectId = typeof raw.project === "string" ? raw.project : null;
        return sanitizeWorkItem(raw, await identifierFor(projectId));
      })
  );

  server.registerTool(
    "hangar_search_work_items",
    {
      title: "Search Hangar work items",
      description:
        "Search work items by text. Omit project to search every allowlisted project, paging project by project.",
      inputSchema: z.object({
        ...common,
        query: z.string().trim().min(1).max(256),
        project: projectReference.optional(),
        priority: z.enum(["urgent", "high", "medium", "low", "none"]).optional(),
        order_by: z
          .enum(["created_at", "-created_at", "updated_at", "-updated_at", "priority", "-priority"])
          .optional(),
      }),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar work item search", args.response_format, async () => {
        const filters: WorkItemFilters = {
          ...(args.priority ? { priority: args.priority } : {}),
          ...(args.order_by ? { orderBy: args.order_by } : {}),
        };
        const page = await client.searchWorkItems(args.query, args.limit, args.cursor, {
          ...(args.project ? { project: args.project } : {}),
          filters,
        });
        const projectIds = [
          ...new Set(
            page.results.flatMap((raw) => {
              const projectId = typeof raw.project === "string" ? raw.project : null;
              return projectId ? [projectId] : [];
            })
          ),
        ];
        const identifiers = new Map(
          await Promise.all(projectIds.map(async (projectId) => [projectId, await identifierFor(projectId)] as const))
        );
        const results = page.results.map((raw) => {
          const projectId = typeof raw.project === "string" ? raw.project : null;
          return sanitizeWorkItem(raw, projectId ? (identifiers.get(projectId) ?? null) : null);
        });
        return { results, next_cursor: page.nextCursor };
      })
  );

  server.registerTool(
    "hangar_list_work_item_comments",
    {
      title: "List Hangar work item comments",
      description: "List comments of one work item (UUID or IDENTIFIER-N). Comment text is credential-scrubbed.",
      inputSchema: z.object({
        ...common,
        project: projectReference,
        work_item: workItemReference,
      }),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar work item comments", args.response_format, async () => {
        const page = await client.listComments(args.project, args.work_item, args.limit, args.cursor);
        return {
          results: page.results.map(sanitizeComment),
          next_cursor: page.nextCursor,
        };
      })
  );

  server.registerTool(
    "hangar_list_states",
    {
      title: "List Hangar states",
      description: "List the workflow states of one allowlisted project.",
      inputSchema: z.object({ ...common, project: projectReference }),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar states", args.response_format, async () => {
        const page = await client.listStates(args.project, args.limit, args.cursor);
        return { results: page.results.map(sanitizeState), next_cursor: page.nextCursor };
      })
  );

  server.registerTool(
    "hangar_list_labels",
    {
      title: "List Hangar labels",
      description: "List the labels of one allowlisted project.",
      inputSchema: z.object({ ...common, project: projectReference }),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar labels", args.response_format, async () => {
        const page = await client.listLabels(args.project, args.limit, args.cursor);
        return { results: page.results.map(sanitizeLabel), next_cursor: page.nextCursor };
      })
  );

  server.registerTool(
    "hangar_list_members",
    {
      title: "List Hangar members",
      description:
        "List workspace members, or the members of one allowlisted project when project is given. Emails are never returned.",
      inputSchema: z.object({ ...common, project: projectReference.optional() }),
      outputSchema,
      annotations,
    },
    async (args) =>
      run("Hangar members", args.response_format, async () => {
        const page = await client.listMembers(args.project, args.limit, args.cursor);
        return { results: page.results.map(sanitizeMember), next_cursor: page.nextCursor };
      })
  );

  return server;
}

export type { ResourceName };
