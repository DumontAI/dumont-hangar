import { createHash } from "node:crypto";
import { decodeCursor, encodeCursor, type CursorState } from "./cursor.js";
import type { HangarConfig } from "./types.js";
import { HangarError, type HangarPage, type JsonRecord, type RawPage, type ResourceName } from "./types.js";

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

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

export class HangarClient {
  private readonly fetcher: FetchLike;
  private readonly cursorSecret: string;
  private projects: { readonly at: number; readonly records: ProjectRecord[] } | null = null;

  constructor(
    readonly config: HangarConfig,
    fetcher: FetchLike = (input, init) => globalThis.fetch(input, init)
  ) {
    this.fetcher = fetcher;
    this.cursorSecret = createHash("sha256").update(config.apiKey).digest("hex");
  }

  isAllowedProject(project: ProjectRecord): boolean {
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
      throw new HangarError("PROJECT_NOT_FOUND", "The requested project was not found in this workspace");
    }
    if (!this.isAllowedProject(project)) {
      throw new HangarError("PROJECT_NOT_ALLOWED", "The requested project is not in the configured allowlist");
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
    const record = await this.request<JsonRecord>(`/projects/${encodeURIComponent(project.id)}/`);
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
      throw new HangarError("PROJECT_NOT_ALLOWED", "No allowlisted project is visible to this token");
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
      const page = await this.requestPage(`/projects/${project.id}/issues/`, limit, state.upstreamCursor, params);
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
      `/projects/${encodeURIComponent(project.id)}/issues/${encodeURIComponent(id)}/`
    );
    this.assertRecordProject(record, project);
    return record;
  }

  async getWorkItemByIdentifier(identifier: string): Promise<JsonRecord> {
    const value = identifier.trim().toUpperCase();
    if (!WORK_ITEM_IDENTIFIER.test(value)) {
      throw new HangarError("INVALID_ARGUMENT", "work_item must look like HGR-5 or be the work item UUID");
    }
    const record = await this.request<JsonRecord>(`/work-items/${encodeURIComponent(value)}/`);
    const project = this.projectRecord(record) ?? (await this.projectOfRecord(record));
    if (!project) {
      throw new HangarError(
        "PROJECT_SCOPE_MISMATCH",
        "The work item could not be verified against the configured project allowlist"
      );
    }
    if (!this.isAllowedProject(project)) {
      throw new HangarError("PROJECT_NOT_ALLOWED", "The work item is outside the configured project allowlist");
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
    const record = await this.request<JsonRecord>(`/work-items/${encodeURIComponent(normalized)}/`);
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
      const page = await this.requestPage(path, limit, state.upstreamCursor, params);
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

  private async loadProjects(): Promise<ProjectRecord[]> {
    const now = Date.now();
    if (this.projects && now - this.projects.at < this.config.projectCacheSeconds * 1000) {
      return this.projects.records;
    }
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
    if (records.length === 0) {
      throw new HangarError("UPSTREAM_INVALID_RESPONSE", "Hangar returned no readable projects for this token");
    }
    this.projects = { at: now, records };
    return records;
  }

  private async allowlistedProjects(): Promise<ProjectRecord[]> {
    const projects = await this.loadProjects();
    const visible = projects.filter((project) => this.isAllowedProject(project));
    return visible;
  }

  private memberCache: { readonly at: number; readonly records: JsonRecord[] } | null = null;

  private async loadWorkspaceMembers(): Promise<JsonRecord[]> {
    const now = Date.now();
    if (this.memberCache && now - this.memberCache.at < this.config.projectCacheSeconds * 1000) {
      return this.memberCache.records;
    }
    const payload = await this.request<unknown>("/members/");
    const records = Array.isArray(payload)
      ? payload.flatMap((value) => {
          const record = asRecord(value);
          return record ? [record] : [];
        })
      : [];
    this.memberCache = { at: now, records };
    return records;
  }

  private async requestPage(
    path: string,
    limit: number,
    upstreamCursor: string | null,
    params: Record<string, string> = {}
  ): Promise<RawPage> {
    const query: Record<string, string> = { ...params, per_page: String(Math.min(Math.max(limit, 1), PER_PAGE_MAX)) };
    if (upstreamCursor) query.cursor = validCursor(upstreamCursor);
    const payload = await this.request<JsonRecord>(path, query);
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

  private async request<T>(path: string, params: Record<string, string> = {}): Promise<T> {
    const url = new URL(
      `/api/v1/workspaces/${encodeURIComponent(this.config.workspaceSlug)}${path}`,
      this.config.baseUrl
    );
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const response = await this.fetcher(url, {
        method: "GET",
        redirect: "error",
        headers: { Accept: "application/json", "x-api-key": this.config.apiKey },
        signal: controller.signal,
      });
      const body = await this.readBody(response, controller);
      if (!response.ok) throw this.responseError(response.status);
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

  private responseError(status: number): HangarError {
    if (status === 401) return new HangarError("UPSTREAM_UNAUTHORIZED", "Hangar rejected the read credential");
    if (status === 403) return new HangarError("UPSTREAM_FORBIDDEN", "Hangar denied the read operation");
    if (status === 404) return new HangarError("UPSTREAM_NOT_FOUND", "Hangar did not find the requested resource");
    if (status === 429) return new HangarError("UPSTREAM_RATE_LIMITED", "Hangar rate-limited the read operation", true);
    if (status >= 500) return new HangarError("UPSTREAM_UNAVAILABLE", "Hangar is temporarily unavailable", true);
    return new HangarError("UPSTREAM_REQUEST_FAILED", "Hangar rejected the read operation");
  }
}
