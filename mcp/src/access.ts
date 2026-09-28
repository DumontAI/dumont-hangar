import { HangarError, type HangarConfig, type Principal } from "./types.js";

export type ToolKind = "read" | "write";

/**
 * Per-tool role check. Read tools accept the reader or the writer role (writer
 * implies reader); write tools need the writer role. Returns the role that
 * authorized the call, for the audit line.
 */
export function authorizeTool(config: HangarConfig, principal: Principal | null, kind: ToolKind): string {
  const roles = principal?.roles ?? [];
  if (kind === "write") {
    if (roles.includes(config.oidcWriterRole)) return config.oidcWriterRole;
    throw new HangarError(
      "FORBIDDEN",
      `This Hangar write tool requires the ${config.oidcWriterRole} role; ask for the grant and log in again`
    );
  }
  if (roles.includes(config.oidcReaderRole)) return config.oidcReaderRole;
  if (roles.includes(config.oidcWriterRole)) return config.oidcWriterRole;
  throw new HangarError("FORBIDDEN", `This Hangar tool requires the ${config.oidcReaderRole} role`);
}

export const WRITE_RATE_WINDOW_MS = 60_000;
const MAX_TRACKED_SUBJECTS = 10_000;

/**
 * Fixed-window (60 s) counter of write tool calls per token subject. One
 * instance is shared by every request of the HTTP server process.
 */
export class WriteRateLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly limit: number,
    private readonly now: () => number = Date.now
  ) {}

  consume(subject: string): void {
    const now = this.now();
    let window = this.windows.get(subject);
    if (!window || now - window.start >= WRITE_RATE_WINDOW_MS) {
      if (!window && this.windows.size >= MAX_TRACKED_SUBJECTS) this.prune(now);
      window = { start: now, count: 0 };
      this.windows.set(subject, window);
    }
    if (window.count >= this.limit) {
      const retryAfter = Math.max(1, Math.ceil((window.start + WRITE_RATE_WINDOW_MS - now) / 1000));
      throw new HangarError(
        "RATE_LIMITED",
        `Too many Hangar write calls for this user (limit ${this.limit} per minute); retry in ${retryAfter}s`,
        true
      );
    }
    window.count += 1;
  }

  private prune(now: number): void {
    for (const [subject, window] of this.windows) {
      if (now - window.start >= WRITE_RATE_WINDOW_MS) this.windows.delete(subject);
    }
  }
}

export type AuditOutcome = "success" | "denied" | "error";

/**
 * One line per tool call. Only identifiers and field NAMES: never text bodies,
 * tokens, the Hangar API key, or free-form arguments.
 */
export interface AuditRecord {
  readonly ts: string;
  readonly event: "hangar.mcp.tool";
  readonly tool: string;
  readonly sub: string | null;
  readonly email: string | null;
  readonly roles_used: readonly string[];
  readonly project: string | null;
  readonly work_item: string | null;
  readonly fields_changed: readonly string[];
  readonly outcome: AuditOutcome;
  readonly error_code: string | null;
  readonly latency_ms: number;
}

export type AuditSink = (record: AuditRecord) => void;

export const stderrAuditSink: AuditSink = (record) => {
  try {
    process.stderr.write(`${JSON.stringify(record)}\n`);
  } catch {
    // Auditing must never turn a completed tool call into a failure.
  }
};

const AUDIT_PROJECT = /^(?:[A-Z][A-Z0-9]{1,9}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const AUDIT_WORK_ITEM =
  /^(?:[A-Z][A-Z0-9]{1,9}-[0-9]{1,10}|[0-9]{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

/** Caller-supplied references are logged only when they have a reference shape. */
export function auditProject(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return AUDIT_PROJECT.test(trimmed) ? trimmed : "[invalid]";
}

export function auditWorkItem(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!AUDIT_WORK_ITEM.test(trimmed)) return "[invalid]";
  return trimmed.includes("-") && trimmed.length === 36 ? trimmed.toLowerCase() : trimmed.toUpperCase();
}
