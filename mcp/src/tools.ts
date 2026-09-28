import { createHash } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import {
  auditProject,
  auditWorkItem,
  authorizeTool,
  stderrAuditSink,
  WriteRateLimiter,
  type AuditOutcome,
  type AuditSink,
  type ToolKind,
} from "./access.js";
import { HangarClient, type ProjectRecord, type WorkItemFilters } from "./client.js";
import { appendWithFooter, htmlWithFooter } from "./markup.js";
import {
  containsCredential,
  sanitizeComment,
  sanitizeLabel,
  sanitizeMember,
  sanitizeProject,
  sanitizeState,
  sanitizeWorkItem,
  workItemIdentifier,
} from "./redaction.js";
import { HangarError, type HangarConfig, type JsonRecord, type Principal, type ResourceName } from "./types.js";

const readAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

function writeAnnotations(idempotentHint: boolean) {
  return { readOnlyHint: false, destructiveHint: false, idempotentHint, openWorldHint: true } as const;
}

const outputSchema = z.record(z.string(), z.unknown());
const projectReference = z.string().trim().min(1).max(64);
const workItemReference = z.string().trim().min(1).max(64);
const common = {
  limit: z.number().int().min(1).max(50).default(20),
  cursor: z.string().max(2048).optional(),
  response_format: z.enum(["json", "markdown"]).default("markdown"),
};
const priority = z.enum(["urgent", "high", "medium", "low", "none"]);
const isoDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "must be a date like 2026-09-30")
  .refine((value) => Number.isFinite(Date.parse(`${value}T00:00:00Z`)), "must be a valid calendar date");
const nameReference = z.string().trim().min(1).max(200);
const referenceList = z.array(nameReference).max(20);

export const IDEMPOTENCY_EXTERNAL_SOURCE = "dumont-hangar-mcp";

export const HANGAR_READ_TOOL_NAMES = [
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

export const HANGAR_WRITE_TOOL_NAMES = [
  "hangar_create_work_item",
  "hangar_update_work_item",
  "hangar_add_comment",
] as const;

export const HANGAR_TOOL_NAMES = [...HANGAR_READ_TOOL_NAMES, ...HANGAR_WRITE_TOOL_NAMES] as const;

// Denials are policy outcomes (this server's or Hangar's), not failures of
// Hangar or of this server.
const DENIAL_CODES = new Set([
  "FORBIDDEN",
  "PROJECT_NOT_ALLOWED",
  "RATE_LIMITED",
  "SECRET_DETECTED",
  "ACCOUNT_NOT_LINKED",
  "TOKEN_NOT_FORWARDABLE",
  "WRITER_ROLE_REQUIRED",
  "PROJECT_ACCESS_DENIED",
  "UPSTREAM_FORBIDDEN",
  "USER_NOT_ALLOWED",
]);

// Failures of the caller's credential itself: when looking up the Hangar user
// id hits one of these, the tool call stops there (every other call would fail
// the same way; Hangar's token check being unavailable is included for that
// reason). Any other lookup failure only leaves the audit id empty.
const CREDENTIAL_FAILURES = new Set([
  "ACCOUNT_NOT_LINKED",
  "TOKEN_NOT_FORWARDABLE",
  "TOKEN_EXPIRED",
  "UPSTREAM_UNAUTHORIZED",
  "USER_NOT_ALLOWED",
  "UPSTREAM_AUTH_UNAVAILABLE",
]);

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
      : { code: "INTERNAL_ERROR", message: "Hangar operation could not be completed", retryable: false };
  const value = { error: safe };
  return {
    isError: true,
    structuredContent: value,
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
  };
}

function stringsOf(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) stringsOf(item, out);
  else if (value && typeof value === "object") for (const item of Object.values(value)) stringsOf(item, out);
  return out;
}

export interface HangarServerContext {
  /** Verified caller of this request; null denies every tool. */
  readonly principal: Principal | null;
  /** Shared across requests by the HTTP server; a private one is created otherwise. */
  readonly rateLimiter?: WriteRateLimiter;
  readonly audit?: AuditSink;
}

interface CallAudit {
  project: string | null;
  work_item: string | null;
  fields_changed: string[];
}

/**
 * Builds the MCP server for ONE request. `client` must be bound to the same
 * caller as `context.principal` (it carries that caller's token to Hangar).
 */
export function createHangarServer(
  config: HangarConfig,
  client: HangarClient,
  context: HangarServerContext = { principal: null }
): McpServer {
  const principal = context.principal;
  const rateLimiter = context.rateLimiter ?? new WriteRateLimiter(config.writeRateLimit);
  const audit = context.audit ?? stderrAuditSink;

  const server = new McpServer(
    { name: "hangar-mcp-server", version: "0.3.0" },
    {
      instructions:
        "Hangar (Plane) triage as the logged-in user: read projects, work items, comments, states, labels and members; create and update work items and add comments (needs the hangar_writer role, and Member access to the project in Hangar). Your own Hangar permissions apply. Deletes are not available. Descriptions are never replaced, only appended to. Read text is redacted and truncated: never write it back. Hangar records you as the author and a '— via MCP' footer marks the text; text that looks like a credential is refused.",
    }
  );

  /**
   * Every tool call goes through here: per-tool role check, write gates
   * (enabled, credential-free input, per-user rate limit), then one audit
   * line in `finally` with identifiers and field names only.
   */
  async function invoke<T extends JsonRecord>(
    tool: string,
    kind: ToolKind,
    title: string,
    format: ResponseFormat,
    args: Record<string, unknown>,
    operation: (call: CallAudit) => Promise<T>
  ) {
    const started = performance.now();
    const call: CallAudit = {
      project: auditProject(args.project),
      work_item: auditWorkItem(args.work_item),
      fields_changed: [],
    };
    let rolesUsed: string[] = [];
    let outcome: AuditOutcome = "error";
    let errorCode: string | null = null;
    let planeUserId: string | null = null;
    try {
      rolesUsed = [authorizeTool(config, principal, kind)];
      if (kind === "write") {
        if (stringsOf(args).some(containsCredential)) {
          throw new HangarError(
            "SECRET_DETECTED",
            "The input looks like it contains a credential (token, password, key or connection string); nothing was written. Remove it and reference the secret by name instead."
          );
        }
        rateLimiter.consume(principal!.sub);
      }
      // The Hangar user behind the token, for the audit line (cached per sub).
      planeUserId = await client.currentUserId().catch((error: unknown) => {
        if (error instanceof HangarError && CREDENTIAL_FAILURES.has(error.code)) throw error;
        return null;
      });
      const value = await operation(call);
      outcome = "success";
      return success(value, title, format);
    } catch (error) {
      errorCode = error instanceof HangarError ? error.code : "INTERNAL_ERROR";
      outcome = DENIAL_CODES.has(errorCode) ? "denied" : "error";
      return failure(error);
    } finally {
      audit({
        ts: new Date().toISOString(),
        event: "hangar.mcp.tool",
        tool,
        sub: principal?.sub ?? null,
        plane_user_id: planeUserId ?? (principal ? client.cachedUserId() : null),
        roles_used: rolesUsed,
        project: call.project,
        work_item: call.work_item,
        fields_changed: call.fields_changed,
        outcome,
        error_code: errorCode,
        latency_ms: Math.round(performance.now() - started),
      });
    }
  }

  async function identifierFor(projectId: string | null): Promise<string | null> {
    if (!projectId) return null;
    const project = await client.projectById(projectId);
    return project?.identifier ?? null;
  }

  server.registerTool(
    "hangar_list_projects",
    {
      title: "List Hangar projects",
      description: "List the Hangar projects your account can see (within this server's optional project ceiling).",
      inputSchema: z.object(common),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke("hangar_list_projects", "read", "Hangar projects", args.response_format, args, async () => {
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
      description: "Get one Hangar project you can see, by identifier (like HGR) or UUID.",
      inputSchema: z.object({ project: projectReference, response_format: common.response_format }),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke("hangar_get_project", "read", "Hangar project", args.response_format, args, async () => {
        return sanitizeProject(await client.getProject(args.project));
      })
  );

  server.registerTool(
    "hangar_list_work_items",
    {
      title: "List Hangar work items",
      description:
        "List work items of one project you can see, newest first unless order_by says otherwise. state/label accept a UUID or an exact name; assignee accepts a member UUID or exact display name. Text fields are redacted (credentials, emails, IPs) and truncated; never write them back to Hangar.",
      inputSchema: z.object({
        ...common,
        project: projectReference,
        state: z.string().trim().min(1).max(200).optional(),
        assignee: z.string().trim().min(1).max(200).optional(),
        label: z.string().trim().min(1).max(200).optional(),
        priority: priority.optional(),
        order_by: z
          .enum(["created_at", "-created_at", "updated_at", "-updated_at", "priority", "-priority"])
          .optional(),
        search: z.string().trim().min(1).max(256).optional(),
      }),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke("hangar_list_work_items", "read", "Hangar work items", args.response_format, args, async () => {
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
      description:
        "Get one work item by identifier (like HGR-5) or by UUID. Pass project together with a UUID. Text fields are redacted (credentials, emails, IPs) and truncated; never write them back to Hangar.",
      inputSchema: z.object({
        work_item: workItemReference,
        project: projectReference.optional(),
        response_format: common.response_format,
      }),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke("hangar_get_work_item", "read", "Hangar work item", args.response_format, args, async () => {
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
        "Search work items by text. Omit project to search every project you can see, paging project by project. Text fields are redacted (credentials, emails, IPs) and truncated; never write them back to Hangar.",
      inputSchema: z.object({
        ...common,
        query: z.string().trim().min(1).max(256),
        project: projectReference.optional(),
        priority: priority.optional(),
        order_by: z
          .enum(["created_at", "-created_at", "updated_at", "-updated_at", "priority", "-priority"])
          .optional(),
      }),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke("hangar_search_work_items", "read", "Hangar work item search", args.response_format, args, async () => {
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
      description:
        "List comments of one work item (UUID or IDENTIFIER-N). Text fields are redacted (credentials, emails, IPs) and truncated; never write them back to Hangar.",
      inputSchema: z.object({
        ...common,
        project: projectReference,
        work_item: workItemReference,
      }),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke(
        "hangar_list_work_item_comments",
        "read",
        "Hangar work item comments",
        args.response_format,
        args,
        async () => {
          const page = await client.listComments(args.project, args.work_item, args.limit, args.cursor);
          return {
            results: page.results.map(sanitizeComment),
            next_cursor: page.nextCursor,
          };
        }
      )
  );

  server.registerTool(
    "hangar_list_states",
    {
      title: "List Hangar states",
      description: "List the workflow states of one project you can see.",
      inputSchema: z.object({ ...common, project: projectReference }),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke("hangar_list_states", "read", "Hangar states", args.response_format, args, async () => {
        const page = await client.listStates(args.project, args.limit, args.cursor);
        return { results: page.results.map(sanitizeState), next_cursor: page.nextCursor };
      })
  );

  server.registerTool(
    "hangar_list_labels",
    {
      title: "List Hangar labels",
      description: "List the labels of one project you can see.",
      inputSchema: z.object({ ...common, project: projectReference }),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke("hangar_list_labels", "read", "Hangar labels", args.response_format, args, async () => {
        const page = await client.listLabels(args.project, args.limit, args.cursor);
        return { results: page.results.map(sanitizeLabel), next_cursor: page.nextCursor };
      })
  );

  server.registerTool(
    "hangar_list_members",
    {
      title: "List Hangar members",
      description:
        "List workspace members, or the members of one project you can see when project is given. Emails are never returned.",
      inputSchema: z.object({ ...common, project: projectReference.optional() }),
      outputSchema,
      annotations: readAnnotations,
    },
    async (args) =>
      invoke("hangar_list_members", "read", "Hangar members", args.response_format, args, async () => {
        const page = await client.listMembers(args.project, args.limit, args.cursor);
        return { results: page.results.map(sanitizeMember), next_cursor: page.nextCursor };
      })
  );

  // ------------------------------------------------------------------ writes
  // Always registered: the hangar_writer role gates them here, and Hangar
  // decides per project whether this user may write there.

  interface WriteFieldInput {
    readonly name?: string | undefined;
    readonly description?: string | undefined;
    readonly append_description?: string | undefined;
    readonly state?: string | undefined;
    readonly priority?: string | undefined;
    readonly labels?: readonly string[] | undefined;
    readonly assignees?: readonly string[] | undefined;
    readonly parent?: string | null | undefined;
    readonly start_date?: string | null | undefined;
    readonly target_date?: string | null | undefined;
  }

  /** Resolves names to ids and builds the Plane body; returns the changed field names. */
  async function writeBody(
    project: ProjectRecord,
    input: WriteFieldInput,
    withFooterOnEmptyDescription: boolean,
    existingDescriptionHtml?: string
  ): Promise<{ body: JsonRecord; fields: string[] }> {
    const body: JsonRecord = {};
    const fields: string[] = [];
    if (input.name !== undefined) {
      body.name = input.name;
      fields.push("name");
    }
    if (input.description !== undefined) {
      body.description_html = htmlWithFooter(input.description);
      fields.push("description");
    } else if (withFooterOnEmptyDescription) {
      body.description_html = htmlWithFooter("");
    }
    if (input.append_description !== undefined) {
      if (existingDescriptionHtml === undefined) {
        throw new HangarError("INTERNAL_ERROR", "append_description needs the stored description");
      }
      // Raw stored HTML (server-side only, never returned) + the new text + footer.
      body.description_html = appendWithFooter(existingDescriptionHtml, input.append_description);
      fields.push("append_description");
    }
    if (input.state !== undefined) {
      body.state = await client.resolveStateId(project, input.state);
      fields.push("state");
    }
    if (input.priority !== undefined) {
      body.priority = input.priority;
      fields.push("priority");
    }
    if (input.labels !== undefined) {
      body.labels = await client.resolveLabelIds(project, input.labels);
      fields.push("labels");
    }
    if (input.assignees !== undefined) {
      body.assignees = await client.resolveAssigneeIds(project, input.assignees);
      fields.push("assignees");
    }
    if (input.parent !== undefined) {
      body.parent = input.parent === null ? null : await client.resolveParentId(project, input.parent);
      fields.push("parent");
    }
    if (input.start_date !== undefined) {
      body.start_date = input.start_date;
      fields.push("start_date");
    }
    if (input.target_date !== undefined) {
      body.target_date = input.target_date;
      fields.push("target_date");
    }
    if (
      typeof body.start_date === "string" &&
      typeof body.target_date === "string" &&
      body.start_date > body.target_date
    ) {
      throw new HangarError("INVALID_ARGUMENT", "start_date cannot be after target_date");
    }
    return { body, fields };
  }

  const writeFields = {
    state: nameReference.optional().describe("State name (exact, case-insensitive) or UUID"),
    priority: priority.optional(),
    labels: referenceList.optional().describe("Label names or UUIDs; on update this REPLACES the label set"),
    assignees: referenceList
      .optional()
      .describe('Member display names, UUIDs, or "me"; on update this REPLACES the assignee set'),
  };

  server.registerTool(
    "hangar_create_work_item",
    {
      title: "Create a Hangar work item",
      description:
        "Create a work item as yourself in a project where you are a Hangar Member. Requires the hangar_writer role. The description ends with a '— via MCP' footer. Pass idempotency_key to make retries safe: a repeat with the same key returns the item created first.",
      inputSchema: z.object({
        project: projectReference,
        name: z.string().trim().min(1).max(255),
        description: z
          .string()
          .max(20_000)
          .optional()
          .describe("Markdown or plain text; converted to safe HTML. A '— via MCP' footer is appended."),
        ...writeFields,
        parent: workItemReference.optional().describe("Parent work item, like HGR-5, in the same project"),
        start_date: isoDate.optional(),
        target_date: isoDate.optional(),
        idempotency_key: z
          .string()
          .regex(/^[A-Za-z0-9._:-]{1,64}$/, "use 1-64 letters, digits, dot, underscore, colon or dash")
          .optional(),
        response_format: common.response_format,
      }),
      outputSchema,
      annotations: writeAnnotations(false),
    },
    async (args) =>
      invoke(
        "hangar_create_work_item",
        "write",
        "Hangar work item created",
        args.response_format,
        args,
        async (call) => {
          const project = await client.resolveProject(args.project);
          call.project = project.identifier;
          const { body, fields } = await writeBody(project, args, true);
          call.fields_changed = fields;
          if (args.idempotency_key) {
            // Scoped per caller so two users' keys can never collide.
            const subject = createHash("sha256").update(principal!.sub).digest("hex").slice(0, 16);
            body.external_source = IDEMPOTENCY_EXTERNAL_SOURCE;
            body.external_id = `${subject}:${args.idempotency_key}`;
          }
          const { record, replayed } = await client.createWorkItem(project, body);
          const identifier = workItemIdentifier(record, project.identifier);
          call.work_item = identifier ?? auditWorkItem(record.id);
          if (replayed) call.fields_changed = [];
          return { ...sanitizeWorkItem(record, project.identifier), idempotent_replay: replayed };
        }
      )
  );

  server.registerTool(
    "hangar_update_work_item",
    {
      title: "Update a Hangar work item",
      description:
        "Update fields of one work item (like HGR-5, or UUID plus project) as yourself, in a project where you are a Hangar Member. Requires the hangar_writer role. Only the fields you pass change; labels/assignees replace the whole set. Moving to a cancelled state is allowed; deleting is not available. The description cannot be replaced: use append_description, which adds your text plus a '— via MCP' footer after the stored description. Text returned by the read tools is redacted and truncated; never write it back.",
      // Strict: an unknown key such as `description` is an error, not silently ignored.
      inputSchema: z.strictObject({
        work_item: workItemReference,
        project: projectReference.optional().describe("Required when work_item is a UUID"),
        name: z.string().trim().min(1).max(255).optional(),
        append_description: z
          .string()
          .trim()
          .min(1)
          .max(20_000)
          .optional()
          .describe(
            "Markdown or plain text APPENDED to the stored description, followed by a '— via MCP' footer. The existing description is kept as stored; do not paste read-tool output here."
          ),
        ...writeFields,
        parent: workItemReference.nullable().optional().describe("Parent like HGR-5 in the same project; null clears"),
        start_date: isoDate.nullable().optional().describe("null clears"),
        target_date: isoDate.nullable().optional().describe("null clears"),
        response_format: common.response_format,
      }),
      outputSchema,
      // Not idempotent: append_description adds text on every call.
      annotations: writeAnnotations(false),
    },
    async (args) =>
      invoke(
        "hangar_update_work_item",
        "write",
        "Hangar work item updated",
        args.response_format,
        args,
        async (call) => {
          const target = await client.workItemForWrite(args.work_item, args.project);
          call.project = target.project.identifier;
          call.work_item = workItemIdentifier(target.record, target.project.identifier) ?? target.id;
          let existing: string | undefined;
          if (args.append_description !== undefined) {
            const stored = target.record.description_html;
            if (stored !== null && stored !== undefined && typeof stored !== "string") {
              throw new HangarError(
                "UPSTREAM_INVALID_RESPONSE",
                "Hangar returned an invalid description; nothing changed"
              );
            }
            if (stored === undefined) {
              throw new HangarError(
                "UPSTREAM_INVALID_RESPONSE",
                "Hangar did not return the stored description; nothing changed"
              );
            }
            existing = stored ?? "";
          }
          const { body, fields } = await writeBody(target.project, args, false, existing);
          if (fields.length === 0) {
            throw new HangarError("INVALID_ARGUMENT", "Pass at least one field to update");
          }
          call.fields_changed = fields;
          const record = await client.updateWorkItem(target.project, target.id, body);
          return sanitizeWorkItem(record, target.project.identifier);
        }
      )
  );

  server.registerTool(
    "hangar_add_comment",
    {
      title: "Comment on a Hangar work item",
      description:
        "Add a comment as yourself to one work item (like HGR-5, or UUID plus project) in a project where you are a Hangar Member. Requires the hangar_writer role. Markdown or plain text; a '— via MCP' footer is appended.",
      inputSchema: z.object({
        work_item: workItemReference,
        project: projectReference.optional().describe("Required when work_item is a UUID"),
        body: z.string().trim().min(1).max(20_000),
        response_format: common.response_format,
      }),
      outputSchema,
      annotations: writeAnnotations(false),
    },
    async (args) =>
      invoke("hangar_add_comment", "write", "Hangar comment added", args.response_format, args, async (call) => {
        const target = await client.workItemForWrite(args.work_item, args.project);
        call.project = target.project.identifier;
        call.work_item = workItemIdentifier(target.record, target.project.identifier) ?? target.id;
        call.fields_changed = ["comment"];
        const comment = await client.addComment(target.project, target.id, htmlWithFooter(args.body));
        return { ...sanitizeComment(comment), work_item: call.work_item };
      })
  );

  return server;
}

export type { ResourceName };
