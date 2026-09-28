import { createHmac } from "node:crypto";
import { SubjectCache } from "./cache.js";
import { decodeCursor, encodeCursor, type CursorState } from "./cursor.js";
import type { HangarConfig, UpstreamCaller } from "./types.js";
import { HangarError, type HangarPage, type JsonRecord, type RawPage, type ResourceName } from "./types.js";

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

/**
 * Plane answers these `error_code`s for the Dumont bearer (fork module
 * apps/api/plane/dumont/). Only matched against constants, never echoed.
 */
const PLANE_ACCOUNT_NOT_LINKED = "DUMONT_ACCOUNT_NOT_LINKED";
const PLANE_WRITER_ROLE_REQUIRED = "DUMONT_WRITER_ROLE_REQUIRED";
const PLANE_MANAGED_BY_ZITADEL = "DUMONT_MANAGED_BY_ZITADEL";
// A Plane 401 this close to (or past) the token `exp` is treated as expiry:
// Plane and this host may disagree by a few seconds.
const EXPIRY_MARGIN_SECONDS = 60;
const PROJECT_IDENTIFIER = /^[A-Z][A-Z0-9]{1,9}$/;

type Operation = "read" | "write";

const MAX_LIST_PAGES_PER_CALL = 10;
const MAX_PROJECT_PAGES = 5;
const PER_PAGE_MAX = 100;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const PROJECT_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const WORK_ITEM_IDENTIFIER = /^([A-Z][A-Z0-9]{1,9})-([0-9]{1,10})$/;
const UPSTREAM_CURSOR = /^[A-Za-z0-9:._-]{1,256}$/;
const PRIORITIES = new Set(["urgent", "high", "medium", "low", "none"]);
const ORDER_BY = new Set(["created_at", "-created_at", "updated_at", "-updated_at", "priority", "-priority"]);

const PROJECT_UUID_KEY = "__hangar_project_uuid";

function asRecord(value: unknown): JsonRecord | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : null;
}

function stringField(record: JsonRecord, key: string): string | null {
  const value = record[key];
  return typeof value === "string" && value ? value : null;
}

function validId(value: string, field: string): string {
  if (!SAFE_ID.test(value)) throw new HangarError("INVALID_ARGUMENT", `${field} has an invalid format`);
  return value;
}

function validCursor(value: string): string {
  if (!UPSTREAM_CURSOR.test(value)) {
    throw new HangarError("INVALID_ARGUMENT", "cursor has an invalid format");
  }
  return value;
}

export interface WorkItemFilters {
  readonly search?: string;
  readonly state?: string;
  readonly assignee?: string;
  readonly label?: string;
  readonly priority?: string;
  readonly orderBy?: string;
}

export interface ProjectRecord {
  readonly id: string;
  readonly identifier: string;
  readonly name: string | null;
}

export interface HangarClientOptions {
  readonly fetch?: FetchLike;
  /**
   * Shared across requests by the HTTP server (one per process). Everything
   * in it is keyed by the caller's `sub`; a private one is created otherwise.
   */
  readonly cache?: SubjectCache;
  readonly now?: () => number;
}

/**
 * Hangar API v1 client acting as ONE caller: every upstream call carries the
 * caller's own access token (`Authorization: Bearer`), so Hangar applies that
 * user's workspace and project permissions. Create one per MCP request.
 */
export class HangarClient {
  private readonly fetcher: FetchLike;
  private readonly cursorSecret: string;
  private readonly cache: SubjectCache;
  private readonly now: () => number;

  constructor(
    readonly config: HangarConfig,
    private readonly caller: UpstreamCaller,
    options: HangarClientOptions = {}
  ) {
    this.fetcher = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.cache = options.cache ?? new SubjectCache(config.projectCacheSeconds * 1000);
    this.now = options.now ?? Date.now;
    // Per-subject key: a cursor issued to one user never decodes for another.
    this.cursorSecret = createHmac("sha256", config.cursorSecret)
      .update(`hangar-mcp-cursor\u0000${caller.sub}`)
      .digest("hex");
  }

  /** True when the project is inside the optional HANGAR_ALLOWED_PROJECTS ceiling. */
  isAllowedProject(project: ProjectRecord): boolean {
    if (this.config.allowedProjects.length === 0) return true;
    return (
      this.config.allowedProjects.includes(project.identifier) ||
      this.config.allowedProjects.includes(project.id.toLowerCase())
    );
  }

  /**
   * Resolves a caller-supplied project reference (identifier like HGR, or UUID)
   * to the canonical project and refuses anything outside the server allowlist.
   */
  async resolveProject(reference: string): Promise<ProjectRecord> {
    const value = reference.trim();
    if (!value || value.length > 64) {
      throw new HangarError("INVALID_ARGUMENT", "project has an invalid format");
    }
    const projects = await this.loadProjects();
    let project: ProjectRecord | undefined;
    if (PROJECT_UUID.test(value)) {
      project = projects.find((item) => item.id.toLowerCase() === value.toLowerCase());
    } else {
      const identifier = value.toUpperCase();
      project = projects.find((item) => item.identifier === identifier);
    }
    if (!project) {
      const identifier = value.toUpperCase();
      throw new HangarError(
        "PROJECT_NOT_FOUND",
        PROJECT_IDENTIFIER.test(identifier)
          ? `Project ${identifier} was not found among the Hangar projects you can access; if it exists, ask for the role ${projectRole(identifier)} in Dumont Auth`
          : "The requested project was not found among the Hangar projects you can access"
      );
    }
    if (!this.isAllowedProject(project)) {
      throw new HangarError(
        "PROJECT_NOT_ALLOWED",
        "The requested project is outside this MCP server's project ceiling (HANGAR_ALLOWED_PROJECTS)"
      );
    }
    return project;
  }

  async projectById(projectId: string): Promise<ProjectRecord | null> {
    if (!PROJECT_UUID.test(projectId)) return null;
    const projects = await this.loadProjects();
    return projects.find((project) => project.id.toLowerCase() === projectId.toLowerCase()) ?? null;
  }

  async listProjects(limit: number, cursor?: string): Promise<HangarPage<JsonRecord>> {
    const scope = `projects|${this.config.allowedProjects.join(",")}`;
    let state = this.initialState("projects", scope, cursor);
    const results: JsonRecord[] = [];
    let scanned = 0;
    while (results.length < limit && scanned < MAX_LIST_PAGES_PER_CALL && state.projectIndex < 1) {
      // Sequential pagination: each page needs the previous cursor.
      // oxlint-disable-next-line no-await-in-loop
      const page = await this.requestPage("/projects/", limit, state.upstreamCursor);
      scanned += 1;
      const visible = page.results.filter((record) => {
        const project = this.projectRecord(record);
        return project !== null && this.isAllowedProject(project);
      });
      const selected = visible.slice(state.offset, state.offset + (limit - results.length));
      results.push(...selected.map((record) => this.markProject(record)));
      const offsetAfter = state.offset + selected.length;
      if (results.length >= limit) {
        const continuation =
          offsetAfter < visible.length
            ? this.nextState(state, offsetAfter, state.upstreamCursor, 0)
            : this.afterPage(state, page.nextCursor, 1);
        return { results, nextCursor: this.encodeIfMore(continuation, 1) };
      }
      state = this.afterPage(state, page.nextCursor, 1);
    }
    return { results, nextCursor: this.encodeIfMore(state, 1) };
  }

  async getProject(reference: string): Promise<JsonRecord> {
    const project = await this.resolveProject(reference);
    const record = await this.request<JsonRecord>(
      `/projects/${encodeURIComponent(project.id)}/`,
      {},
      project.identifier
    );
    const resolved = this.projectRecord(record);
    if (!resolved || resolved.id.toLowerCase() !== project.id.toLowerCase()) {
      throw new HangarError("PROJECT_SCOPE_MISMATCH", "The returned project is outside the requested scope");
    }
    return this.markProject(record);
  }

  async listWorkItems(
    reference: string,
    limit: number,
    cursor: string | undefined,
    filters: WorkItemFilters = {}
  ): Promise<HangarPage<JsonRecord>> {
    const project = await this.resolveProject(reference);
    const params = await this.workItemParams(project, filters);
    return this.listProjectScoped("work_items", `/projects/${project.id}/issues/`, limit, cursor, project, params);
  }

  async searchWorkItems(
    query: string,
    limit: number,
    cursor: string | undefined,
    options: { project?: string; filters?: WorkItemFilters } = {}
  ): Promise<HangarPage<JsonRecord>> {
    const projects = options.project ? [await this.resolveProject(options.project)] : await this.allowlistedProjects();
    if (projects.length === 0) {
      throw new HangarError(
        "PROJECT_NOT_FOUND",
        "No Hangar project is visible to you through this MCP; ask for a hangar.project.<identifier>.member role in Dumont Auth"
      );
    }
    const filters = { ...options.filters, search: query };
    const scope = `search_work_items|${projects.map((project) => project.id).join(",")}|${JSON.stringify(filters)}`;
    let state = this.initialState("search_work_items", scope, cursor);
    const results: JsonRecord[] = [];
    let scanned = 0;
    while (results.length < limit && state.projectIndex < projects.length && scanned < this.config.maxSearchPages) {
      const project = projects[state.projectIndex]!;
      const params: Record<string, string> = { search: query };
      if (filters.priority) params.priority = filters.priority;
      if (filters.orderBy) params.order_by = filters.orderBy;
      // Sequential pagination: each page needs the previous cursor.
      // oxlint-disable-next-line no-await-in-loop
      const page = await this.requestPage(
        `/projects/${project.id}/issues/`,
        limit,
        state.upstreamCursor,
        params,
        project.identifier
      );
      scanned += 1;
      const visible = page.results
        .filter((record) => this.matchesProject(record, project))
        .map((record) => this.markProject(record));
      const selected = visible.slice(state.offset, state.offset + (limit - results.length));
      results.push(...selected);
      const offsetAfter = state.offset + selected.length;
      if (results.length >= limit) {
        const hasSamePage = offsetAfter < visible.length;
        const continuation = hasSamePage
          ? this.nextState(state, offsetAfter, state.upstreamCursor, state.projectIndex)
          : this.afterPage(state, page.nextCursor, projects.length);
        return { results, nextCursor: this.encodeIfMore(continuation, projects.length) };
      }
      state = this.afterPage(state, page.nextCursor, projects.length);
    }
    return { results, nextCursor: this.encodeIfMore(state, projects.length) };
  }

  async getWorkItemById(reference: string, workItemId: string): Promise<JsonRecord> {
    const project = await this.resolveProject(reference);
    const id = validId(workItemId, "work_item_id");
    if (!PROJECT_UUID.test(id)) {
      throw new HangarError("INVALID_ARGUMENT", "work_item_id must be the work item UUID when a project is given");
    }
    const record = await this.request<JsonRecord>(
      `/projects/${encodeURIComponent(project.id)}/issues/${encodeURIComponent(id)}/`,
      {},
      project.identifier
    );
    this.assertRecordProject(record, project);
    return record;
  }

  async getWorkItemByIdentifier(identifier: string): Promise<JsonRecord> {
    const value = identifier.trim().toUpperCase();
    const match = WORK_ITEM_IDENTIFIER.exec(value);
    if (!match) {
      throw new HangarError("INVALID_ARGUMENT", "work_item must look like HGR-5 or be the work item UUID");
    }
    const record = await this.request<JsonRecord>(`/work-items/${encodeURIComponent(value)}/`, {}, match[1]);
    const project = this.projectRecord(record) ?? (await this.projectOfRecord(record));
    if (!project) {
      throw new HangarError(
        "PROJECT_SCOPE_MISMATCH",
        "The work item could not be verified against a Hangar project you can access"
      );
    }
    if (!this.isAllowedProject(project)) {
      throw new HangarError(
        "PROJECT_NOT_ALLOWED",
        "The work item is outside this MCP server's project ceiling (HANGAR_ALLOWED_PROJECTS)"
      );
    }
    return record;
  }

  async listComments(
    reference: string,
    workItem: string,
    limit: number,
    cursor?: string
  ): Promise<HangarPage<JsonRecord>> {
    const project = await this.resolveProject(reference);
    const id = await this.resolveWorkItemId(project, workItem);
    return this.listProjectScoped("comments", `/projects/${project.id}/issues/${id}/comments/`, limit, cursor, project);
  }

  async listStates(reference: string, limit: number, cursor?: string): Promise<HangarPage<JsonRecord>> {
    const project = await this.resolveProject(reference);
    return this.listProjectScoped("states", `/projects/${project.id}/states/`, limit, cursor, project);
  }

  async listLabels(reference: string, limit: number, cursor?: string): Promise<HangarPage<JsonRecord>> {
    const project = await this.resolveProject(reference);
    return this.listProjectScoped("labels", `/projects/${project.id}/labels/`, limit, cursor, project);
  }

  async listMembers(reference: string | undefined, limit: number, cursor?: string): Promise<HangarPage<JsonRecord>> {
    if (!reference) {
      const records = await this.loadWorkspaceMembers();
      const visible = records.slice(0, limit);
      return { results: visible, nextCursor: null };
    }
    const project = await this.resolveProject(reference);
    return this.listProjectScoped("members", `/projects/${project.id}/members/`, limit, cursor, project);
  }

  private async workItemParams(project: ProjectRecord, filters: WorkItemFilters): Promise<Record<string, string>> {
    const params: Record<string, string> = {};
    if (filters.search) {
      if (filters.search.length > 256)
        throw new HangarError("INVALID_ARGUMENT", "search must be at most 256 characters");
      params.search = filters.search;
    }
    if (filters.priority) {
      const priority = filters.priority.toLowerCase();
      if (!PRIORITIES.has(priority)) {
        throw new HangarError("INVALID_ARGUMENT", "priority must be one of urgent, high, medium, low, none");
      }
      params.priority = priority;
    }
    if (filters.orderBy) {
      if (!ORDER_BY.has(filters.orderBy)) {
        throw new HangarError(
          "INVALID_ARGUMENT",
          "order_by must be one of created_at, -created_at, updated_at, -updated_at, priority, -priority"
        );
      }
      params.order_by = filters.orderBy;
    }
    if (filters.state) {
      params.state = (await this.resolveNamedId(project, "state", filters.state, () => this.rawStates(project))).join(
        ","
      );
    }
    if (filters.label) {
      params.labels = (await this.resolveNamedId(project, "label", filters.label, () => this.rawLabels(project))).join(
        ","
      );
    }
    if (filters.assignee) {
      const members = await this.loadWorkspaceMembers();
      params.assignees = this.resolveMember(project, filters.assignee, members);
    }
    return params;
  }

  private resolveMember(project: ProjectRecord, reference: string, members: JsonRecord[]): string {
    const value = reference.trim();
    if (PROJECT_UUID.test(value)) return value;
    const needle = value.toLowerCase();
    const matches = members.filter((member) => {
      const name = stringField(member, "display_name")?.toLowerCase();
      const first = stringField(member, "first_name")?.toLowerCase() ?? "";
      const last = stringField(member, "last_name")?.toLowerCase() ?? "";
      return name === needle || `${first} ${last}`.trim() === needle;
    });
    if (matches.length === 0) {
      throw new HangarError("INVALID_ARGUMENT", "assignee did not match any workspace member by id or display name");
    }
    if (matches.length > 1) {
      throw new HangarError("INVALID_ARGUMENT", "assignee is ambiguous; pass the member UUID");
    }
    const id = stringField(matches[0]!, "id");
    if (!id)
      throw new HangarError("INVALID_ARGUMENT", "assignee did not match any workspace member by id or display name");
    void project;
    return id;
  }

  private async resolveNamedId(
    project: ProjectRecord,
    label: "state" | "label",
    reference: string,
    load: () => Promise<JsonRecord[]>
  ): Promise<string[]> {
    const value = reference.trim();
    const parts = value
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
    if (parts.length === 0 || parts.length > 10) {
      throw new HangarError("INVALID_ARGUMENT", `${label} has an invalid format`);
    }
    return this.resolveNamedIds(label, parts, load);
  }

  /** Exact (case-insensitive) name or UUID match, loading the records once. */
  private async resolveNamedIds(
    label: "state" | "label",
    parts: readonly string[],
    load: () => Promise<JsonRecord[]>
  ): Promise<string[]> {
    const records = parts.every((part) => PROJECT_UUID.test(part)) ? [] : await load();
    return parts.map((part) => {
      if (PROJECT_UUID.test(part)) return part;
      const needle = part.toLowerCase();
      const matches = records.filter((record) => stringField(record, "name")?.toLowerCase() === needle);
      if (matches.length === 0) {
        throw new HangarError(
          "INVALID_ARGUMENT",
          `${label} "${part}" did not match any name in this project; pass the UUID for an exact match`
        );
      }
      if (matches.length > 1) {
        throw new HangarError("INVALID_ARGUMENT", `${label} "${part}" is ambiguous; pass the UUID`);
      }
      const id = stringField(matches[0]!, "id");
      if (!id) throw new HangarError("INVALID_ARGUMENT", `${label} "${part}" did not match any name in this project`);
      return id;
    });
  }

  // ---------------------------------------------------------------- caller

  /**
   * The Hangar user behind the caller's token (`GET /api/v1/users/me/`),
   * cached per subject. Used for assignee "me" and the audit line.
   */
  async currentUserId(): Promise<string> {
    const cached = this.cache.get<string>(this.caller.sub, "me");
    if (cached) return cached;
    const record = await this.requestUrl<JsonRecord>(new URL("/api/v1/users/me/", this.config.baseUrl));
    const id = asRecord(record) ? stringField(record, "id") : null;
    if (!id || !PROJECT_UUID.test(id)) {
      throw new HangarError("UPSTREAM_INVALID_RESPONSE", "Hangar returned an invalid current user");
    }
    const normalized = id.toLowerCase();
    this.cache.set(this.caller.sub, "me", normalized);
    return normalized;
  }

  /** The Hangar user id if it is already known for this subject; never calls Hangar. */
  cachedUserId(): string | null {
    return this.cache.get<string>(this.caller.sub, "me") ?? null;
  }

  // ---------------------------------------------------------------- writes

  /**
   * Loads the work item a write targets (IDENTIFIER-N, or UUID together with
   * project) and returns it with its project (inside the optional ceiling).
   * Whether the caller may write there is Hangar's decision.
   */
  async workItemForWrite(
    workItem: string,
    projectReference?: string
  ): Promise<{ project: ProjectRecord; record: JsonRecord; id: string }> {
    const value = workItem.trim();
    let record: JsonRecord;
    let project: ProjectRecord | null;
    if (PROJECT_UUID.test(value)) {
      if (!projectReference) {
        throw new HangarError("INVALID_ARGUMENT", "Pass project together with a work item UUID, or use IDENTIFIER-N");
      }
      project = await this.resolveProject(projectReference);
      record = await this.getWorkItemById(project.id, value);
    } else {
      record = await this.getWorkItemByIdentifier(value);
      project = this.projectRecord(record) ?? (await this.projectOfRecord(record));
      if (!project) {
        throw new HangarError("PROJECT_SCOPE_MISMATCH", "The work item could not be verified against its project");
      }
      if (projectReference) {
        const expected = await this.resolveProject(projectReference);
        if (expected.id !== project.id) {
          throw new HangarError("INVALID_ARGUMENT", "work_item does not belong to the given project");
        }
      }
    }
    const id = stringField(record, "id");
    if (!id || !PROJECT_UUID.test(id)) {
      throw new HangarError("UPSTREAM_INVALID_RESPONSE", "Hangar returned an invalid work item");
    }
    return { project, record, id: id.toLowerCase() };
  }

  async resolveStateId(project: ProjectRecord, reference: string): Promise<string> {
    const [id] = await this.resolveNamedIds("state", [reference.trim()], () => this.rawStates(project));
    return id!;
  }

  async resolveLabelIds(project: ProjectRecord, references: readonly string[]): Promise<string[]> {
    const parts = references.map((reference) => reference.trim()).filter(Boolean);
    if (parts.length === 0) return [];
    return [...new Set(await this.resolveNamedIds("label", parts, () => this.rawLabels(project)))];
  }

  /**
   * Member UUID, exact display name / full name, or "me" (the Hangar user
   * behind the caller's token, from `GET /api/v1/users/me/`).
   */
  async resolveAssigneeIds(project: ProjectRecord, references: readonly string[]): Promise<string[]> {
    const parts = references.map((reference) => reference.trim()).filter(Boolean);
    if (parts.length === 0) return [];
    const me = parts.some((part) => part.toLowerCase() === "me") ? await this.currentUserId() : null;
    const others = parts.filter((part) => part.toLowerCase() !== "me");
    const members = others.every((part) => PROJECT_UUID.test(part)) ? [] : await this.loadWorkspaceMembers();
    const ids = parts.map((part) => (part.toLowerCase() === "me" ? me! : this.resolveMember(project, part, members)));
    return [...new Set(ids)];
  }

  /** Parent by IDENTIFIER-N or UUID; Plane only accepts a parent in the same project. */
  async resolveParentId(project: ProjectRecord, reference: string): Promise<string> {
    const value = reference.trim();
    const record = PROJECT_UUID.test(value)
      ? await this.getWorkItemById(project.id, value)
      : await this.getWorkItemByIdentifier(value);
    const parentProject = stringField(record, "project");
    if (!parentProject || parentProject.toLowerCase() !== project.id.toLowerCase()) {
      throw new HangarError("INVALID_ARGUMENT", "parent must be a work item of the same project");
    }
    const id = stringField(record, "id");
    if (!id || !PROJECT_UUID.test(id)) {
      throw new HangarError("UPSTREAM_INVALID_RESPONSE", "Hangar returned an invalid work item");
    }
    return id.toLowerCase();
  }

  /**
   * POST a work item. With an external_id/external_source pair Plane answers
   * 409 {"id": <existing>} for a repeat (apps/api/plane/api/views/issue.py,
   * IssueListCreateAPIEndpoint.post); that existing item is returned instead.
   */
  async createWorkItem(project: ProjectRecord, body: JsonRecord): Promise<{ record: JsonRecord; replayed: boolean }> {
    const response = await this.write("POST", `/projects/${project.id}/issues/`, body, project, [409]);
    if (response.status === 409) {
      const existing = stringField(response.json, "id");
      if (!existing || !PROJECT_UUID.test(existing)) {
        throw new HangarError("UPSTREAM_CONFLICT", "Hangar reported a conflicting work item without its id");
      }
      return { record: await this.getWorkItemById(project.id, existing), replayed: true };
    }
    this.assertRecordProject(response.json, project);
    return { record: response.json, replayed: false };
  }

  async updateWorkItem(project: ProjectRecord, workItemId: string, body: JsonRecord): Promise<JsonRecord> {
    const id = validId(workItemId, "work_item_id");
    const response = await this.write(
      "PATCH",
      `/projects/${project.id}/issues/${encodeURIComponent(id)}/`,
      body,
      project
    );
    this.assertRecordProject(response.json, project);
    return response.json;
  }

  async addComment(project: ProjectRecord, workItemId: string, commentHtml: string): Promise<JsonRecord> {
    const id = validId(workItemId, "work_item_id");
    const response = await this.write(
      "POST",
      `/projects/${project.id}/issues/${encodeURIComponent(id)}/comments/`,
      { comment_html: commentHtml },
      project
    );
    this.assertRecordProject(response.json, project);
    return response.json;
  }

  /**
   * The caller's bearer for Hangar. Only a locally verified JWS is ever
   * forwarded; an opaque token (accepted through introspection) is refused
   * before any network call.
   */
  private authorization(): string {
    const token = this.caller.accessToken;
    if (!token) {
      throw new HangarError(
        "TOKEN_NOT_FORWARDABLE",
        "Your MCP login uses an opaque access token, which Hangar does not accept. Connect with the pinned Dumont public client (it issues JWT access tokens) and log in again; see the Hangar MCP README, 'Team access'."
      );
    }
    return `Bearer ${token}`;
  }

  private workspaceUrl(path: string): URL {
    return new URL(`/api/v1/workspaces/${encodeURIComponent(this.config.workspaceSlug)}${path}`, this.config.baseUrl);
  }

  private async write(
    method: "POST" | "PATCH",
    path: string,
    body: JsonRecord,
    project: ProjectRecord,
    passStatuses: readonly number[] = []
  ): Promise<{ status: number; json: JsonRecord }> {
    const url = this.workspaceUrl(path);
    const authorization = this.authorization();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const response = await this.fetcher(url, {
        method,
        redirect: "error",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          Authorization: authorization,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await this.readBody(response, controller);
      let json: JsonRecord = {};
      try {
        json = asRecord(text ? JSON.parse(text) : {}) ?? {};
      } catch {
        if (response.ok) throw new HangarError("UPSTREAM_INVALID_RESPONSE", "Hangar returned invalid JSON");
      }
      if (!response.ok && !passStatuses.includes(response.status)) {
        throw this.upstreamError(response.status, json, "write", project.identifier);
      }
      return { status: response.status, json };
    } catch (error) {
      if (error instanceof HangarError) throw error;
      // A write that timed out may or may not have been applied: never retryable blindly.
      if (controller.signal.aborted) {
        throw new HangarError(
          "UPSTREAM_TIMEOUT",
          "Hangar did not answer before the timeout; the write may or may not have been applied, check before retrying (or pass idempotency_key)"
        );
      }
      throw new HangarError("UPSTREAM_UNAVAILABLE", "Hangar write operation could not be completed");
    } finally {
      clearTimeout(timer);
    }
  }

  private tokenExpiring(): boolean {
    const expiresAt = this.caller.expiresAt;
    return expiresAt !== null && expiresAt - Math.floor(this.now() / 1000) <= EXPIRY_MARGIN_SECONDS;
  }

  /**
   * Maps a Hangar error to a tool error. None of these becomes an HTTP 401 of
   * this MCP (that would restart the client's login loop for a problem a new
   * login cannot fix); an expired token is reported as retryable TOKEN_EXPIRED
   * and the next MCP request with it gets the regular 401 challenge.
   * `projectIdentifier` names the project the call was scoped to, if any.
   */
  private upstreamError(
    status: number,
    json: JsonRecord,
    operation: Operation,
    projectIdentifier?: string
  ): HangarError {
    const code = typeof json.error_code === "string" ? json.error_code : null;
    if (status === 401) {
      if (code === PLANE_ACCOUNT_NOT_LINKED) {
        return new HangarError(
          "ACCOUNT_NOT_LINKED",
          `Your Dumont login is not linked to a Hangar account yet: sign in once at ${this.config.baseUrl.origin} with Dumont login, then retry`
        );
      }
      if (this.tokenExpiring()) {
        return new HangarError(
          "TOKEN_EXPIRED",
          "Your Dumont access token expired; retry and your MCP client will be asked to refresh the login",
          true
        );
      }
      return new HangarError(
        "UPSTREAM_UNAUTHORIZED",
        "Hangar did not accept your Dumont token for its API (logging in again will not help unless it expired); Hangar's Dumont bearer login may be disabled or misconfigured"
      );
    }
    if (status === 403) {
      if (code === PLANE_WRITER_ROLE_REQUIRED) {
        return new HangarError(
          "WRITER_ROLE_REQUIRED",
          `Hangar requires the ${this.config.oidcWriterRole} role for this change; ask for it in Dumont Auth and log in again`
        );
      }
      if (code === PLANE_MANAGED_BY_ZITADEL) {
        return new HangarError("UPSTREAM_FORBIDDEN", "Hangar refused: this access is managed in Dumont Auth (ZITADEL)");
      }
      if (projectIdentifier) {
        return new HangarError(
          "PROJECT_ACCESS_DENIED",
          `No ${operation} access to project ${projectIdentifier} in Hangar; ask for the role ${projectRole(projectIdentifier)} in Dumont Auth`
        );
      }
      return new HangarError("UPSTREAM_FORBIDDEN", `Hangar denied the ${operation} operation for your account`);
    }
    if (status === 404) {
      return new HangarError(
        "UPSTREAM_NOT_FOUND",
        projectIdentifier
          ? `Hangar did not find the requested resource in project ${projectIdentifier}, or your account cannot see it`
          : "Hangar did not find the requested resource"
      );
    }
    if (status === 429) {
      return new HangarError("UPSTREAM_RATE_LIMITED", `Hangar rate-limited the ${operation} operation`, true);
    }
    return operation === "write" ? this.writeError(status, json) : this.readError(status);
  }

  private readError(status: number): HangarError {
    if (status >= 500) return new HangarError("UPSTREAM_UNAVAILABLE", "Hangar is temporarily unavailable", true);
    return new HangarError("UPSTREAM_REQUEST_FAILED", "Hangar rejected the read operation");
  }

  private writeError(status: number, json: JsonRecord): HangarError {
    if (status === 400) {
      // Only the field names Plane complained about; messages may echo input.
      const fields = Object.keys(json)
        .filter((key) => /^[a-z_]{1,40}$/.test(key))
        .slice(0, 10);
      return new HangarError(
        "UPSTREAM_VALIDATION_FAILED",
        fields.length > 0
          ? `Hangar rejected the write; check these fields: ${fields.join(", ")}`
          : "Hangar rejected the write as invalid"
      );
    }
    if (status === 409) return new HangarError("UPSTREAM_CONFLICT", "Hangar reported a conflicting resource");
    if (status >= 500) {
      return new HangarError(
        "UPSTREAM_UNAVAILABLE",
        "Hangar failed while writing; the write may or may not have been applied, check before retrying"
      );
    }
    return new HangarError("UPSTREAM_REQUEST_FAILED", "Hangar rejected the write operation");
  }

  private async rawStates(project: ProjectRecord): Promise<JsonRecord[]> {
    const page = await this.listProjectScoped(
      "states",
      `/projects/${project.id}/states/`,
      PER_PAGE_MAX,
      undefined,
      project
    );
    return page.results;
  }

  private async rawLabels(project: ProjectRecord): Promise<JsonRecord[]> {
    const page = await this.listProjectScoped(
      "labels",
      `/projects/${project.id}/labels/`,
      PER_PAGE_MAX,
      undefined,
      project
    );
    return page.results;
  }

  private async resolveWorkItemId(project: ProjectRecord, workItem: string): Promise<string> {
    const value = workItem.trim();
    if (PROJECT_UUID.test(value)) return value;
    const identifier = value.toUpperCase();
    const normalized = /^[0-9]{1,10}$/.test(identifier) ? `${project.identifier}-${identifier}` : identifier;
    const match = WORK_ITEM_IDENTIFIER.exec(normalized);
    if (!match || match[1] !== project.identifier) {
      throw new HangarError(
        "INVALID_ARGUMENT",
        "work_item must be the work item UUID or IDENTIFIER-N of the given project"
      );
    }
    const record = await this.request<JsonRecord>(
      `/work-items/${encodeURIComponent(normalized)}/`,
      {},
      project.identifier
    );
    const id = stringField(record, "id");
    if (!id || !SAFE_ID.test(id)) {
      throw new HangarError("UPSTREAM_INVALID_RESPONSE", "Hangar returned an invalid work item");
    }
    return id;
  }

  private async listProjectScoped(
    resource: Exclude<ResourceName, "projects" | "search_work_items">,
    path: string,
    limit: number,
    cursor: string | undefined,
    project: ProjectRecord,
    params: Record<string, string> = {}
  ): Promise<HangarPage<JsonRecord>> {
    const scope = `${resource}|${project.id}|${JSON.stringify(Object.entries(params).toSorted())}`;
    let state = this.initialState(resource, scope, cursor);
    const results: JsonRecord[] = [];
    let scanned = 0;
    while (results.length < limit && scanned < MAX_LIST_PAGES_PER_CALL && state.projectIndex < 1) {
      // Sequential pagination: each page needs the previous cursor.
      // oxlint-disable-next-line no-await-in-loop
      const page = await this.requestPage(path, limit, state.upstreamCursor, params, project.identifier);
      scanned += 1;
      const visible = page.results.filter((record) => this.matchesProject(record, project));
      const selected = visible.slice(state.offset, state.offset + (limit - results.length));
      results.push(...selected.map((record) => this.markProject(record)));
      const offsetAfter = state.offset + selected.length;
      if (results.length >= limit) {
        const hasSamePage = offsetAfter < visible.length;
        const continuation = hasSamePage
          ? this.nextState(state, offsetAfter, state.upstreamCursor, 0)
          : this.afterPage(state, page.nextCursor, 1);
        return { results, nextCursor: this.encodeIfMore(continuation, 1) };
      }
      state = this.afterPage(state, page.nextCursor, 1);
    }
    return { results, nextCursor: this.encodeIfMore(state, 1) };
  }

  private initialState(resource: ResourceName, scope: string, cursor?: string): CursorState {
    return cursor
      ? decodeCursor(cursor, this.cursorSecret, resource, scope)
      : { version: 1, resource, scope, projectIndex: 0, upstreamCursor: null, offset: 0 };
  }

  private nextState(
    state: CursorState,
    offset: number,
    upstreamCursor: string | null,
    projectIndex: number
  ): CursorState {
    return { ...state, projectIndex, upstreamCursor, offset };
  }

  private afterPage(state: CursorState, next: string | null, projectCount: number): CursorState {
    if (next !== null) return this.nextState(state, 0, next, state.projectIndex);
    const nextProject = state.projectIndex + 1;
    return this.nextState(state, 0, null, Math.min(nextProject, projectCount));
  }

  private encodeIfMore(state: CursorState, projectCount: number): string | null {
    return state.projectIndex < projectCount || state.upstreamCursor !== null
      ? encodeCursor(state, this.cursorSecret)
      : null;
  }

  private projectRecord(record: JsonRecord): ProjectRecord | null {
    const id = stringField(record, "id");
    const identifier = stringField(record, "identifier");
    if (!id || !PROJECT_UUID.test(id) || !identifier) return null;
    return { id: id.toLowerCase(), identifier: identifier.toUpperCase(), name: stringField(record, "name") };
  }

  private async projectOfRecord(record: JsonRecord): Promise<ProjectRecord | null> {
    const projectId = stringField(record, "project");
    if (!projectId || !PROJECT_UUID.test(projectId)) return null;
    const projects = await this.loadProjects();
    return projects.find((project) => project.id.toLowerCase() === projectId.toLowerCase()) ?? null;
  }

  private markProject(record: JsonRecord): JsonRecord {
    const project = this.projectRecord(record) ?? stringField(record, "project");
    if (!project) return record;
    return { ...record, [PROJECT_UUID_KEY]: typeof project === "string" ? project.toLowerCase() : project.id };
  }

  private matchesProject(record: JsonRecord, project: ProjectRecord): boolean {
    const value = stringField(record, "project") ?? stringField(record, PROJECT_UUID_KEY);
    if (value === null) return true;
    return value.toLowerCase() === project.id.toLowerCase();
  }

  private assertRecordProject(record: JsonRecord, project: ProjectRecord): void {
    const value = stringField(record, "project");
    if (value !== null && value.toLowerCase() !== project.id.toLowerCase()) {
      throw new HangarError("PROJECT_SCOPE_MISMATCH", "The result is outside the requested project scope");
    }
  }

  /** The projects Hangar shows THIS caller, cached per subject. */
  private async loadProjects(): Promise<ProjectRecord[]> {
    const cached = this.cache.get<ProjectRecord[]>(this.caller.sub, "projects");
    if (cached) return cached;
    const records: ProjectRecord[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < MAX_PROJECT_PAGES; page += 1) {
      // Sequential pagination: each page needs the previous cursor.
      // oxlint-disable-next-line no-await-in-loop
      const payload = await this.requestPage("/projects/", PER_PAGE_MAX, cursor);
      for (const record of payload.results) {
        const project = this.projectRecord(record);
        if (project) records.push(project);
      }
      if (!payload.nextCursor) break;
      cursor = payload.nextCursor;
    }
    // An empty list is legitimate now: the user may not be in any project yet.
    this.cache.set(this.caller.sub, "projects", records);
    return records;
  }

  private async allowlistedProjects(): Promise<ProjectRecord[]> {
    const projects = await this.loadProjects();
    const visible = projects.filter((project) => this.isAllowedProject(project));
    return visible;
  }

  /** Workspace members as Hangar shows them to THIS caller, cached per subject. */
  private async loadWorkspaceMembers(): Promise<JsonRecord[]> {
    const cached = this.cache.get<JsonRecord[]>(this.caller.sub, "workspace_members");
    if (cached) return cached;
    const payload = await this.request<unknown>("/members/");
    const records = Array.isArray(payload)
      ? payload.flatMap((value) => {
          const record = asRecord(value);
          return record ? [record] : [];
        })
      : [];
    this.cache.set(this.caller.sub, "workspace_members", records);
    return records;
  }

  private async requestPage(
    path: string,
    limit: number,
    upstreamCursor: string | null,
    params: Record<string, string> = {},
    projectIdentifier?: string
  ): Promise<RawPage> {
    const query: Record<string, string> = { ...params, per_page: String(Math.min(Math.max(limit, 1), PER_PAGE_MAX)) };
    if (upstreamCursor) query.cursor = validCursor(upstreamCursor);
    const payload = await this.request<JsonRecord>(path, query, projectIdentifier);
    const rawResults = payload.results;
    const results = Array.isArray(rawResults)
      ? rawResults.flatMap((value) => {
          const record = asRecord(value);
          return record ? [record] : [];
        })
      : [];
    return { results, nextCursor: this.extractNextCursor(payload) };
  }

  private extractNextCursor(payload: JsonRecord): string | null {
    const hasMore = payload.next_page_results === true;
    const next = payload.next_cursor;
    if (!hasMore || typeof next !== "string" || !next) return null;
    return validCursor(next);
  }

  private async request<T>(path: string, params: Record<string, string> = {}, projectIdentifier?: string): Promise<T> {
    const url = this.workspaceUrl(path);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    return this.requestUrl<T>(url, projectIdentifier);
  }

  private async requestUrl<T>(url: URL, projectIdentifier?: string): Promise<T> {
    const authorization = this.authorization();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const response = await this.fetcher(url, {
        method: "GET",
        redirect: "error",
        headers: { Accept: "application/json", Authorization: authorization },
        signal: controller.signal,
      });
      const body = await this.readBody(response, controller);
      if (!response.ok) {
        throw this.upstreamError(response.status, parseErrorBody(body), "read", projectIdentifier);
      }
      try {
        return JSON.parse(body) as T;
      } catch {
        throw new HangarError("UPSTREAM_INVALID_RESPONSE", "Hangar returned invalid JSON");
      }
    } catch (error) {
      if (error instanceof HangarError) throw error;
      if (controller.signal.aborted)
        throw new HangarError("UPSTREAM_TIMEOUT", "Hangar did not respond before the timeout", true);
      throw new HangarError("UPSTREAM_UNAVAILABLE", "Hangar read operation could not be completed", true);
    } finally {
      clearTimeout(timer);
    }
  }

  private async readBody(response: Response, controller: AbortController): Promise<string> {
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > this.config.maxResponseBytes) {
      throw new HangarError("UPSTREAM_RESPONSE_TOO_LARGE", "Hangar response exceeded the configured safety limit");
    }
    if (!response.body) {
      const body = await response.text();
      this.assertBodySize(body);
      return body;
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        // Sequential stream read by design.
        // oxlint-disable-next-line no-await-in-loop
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > this.config.maxResponseBytes) {
          // oxlint-disable-next-line no-await-in-loop
          await reader.cancel();
          throw new HangarError("UPSTREAM_RESPONSE_TOO_LARGE", "Hangar response exceeded the configured safety limit");
        }
        chunks.push(value);
      }
    } finally {
      if (controller.signal.aborted) await reader.cancel();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(bytes);
  }

  private assertBodySize(body: string): void {
    if (new TextEncoder().encode(body).byteLength > this.config.maxResponseBytes) {
      throw new HangarError("UPSTREAM_RESPONSE_TOO_LARGE", "Hangar response exceeded the configured safety limit");
    }
  }
}

/** Error bodies are parsed only to read `error_code`; they are never echoed. */
function parseErrorBody(text: string): JsonRecord {
  try {
    return asRecord(text ? JSON.parse(text) : {}) ?? {};
  } catch {
    return {};
  }
}

/** The ZITADEL role that grants Member access to a managed Hangar project. */
function projectRole(identifier: string): string {
  return `hangar.project.${identifier.toLowerCase()}.member`;
}
