import type { JsonRecord } from "./types.js";

const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const SENSITIVE_KEY =
  /(?:authorization|cookie|token|password|secret|dsn|api[-_]?key|connection|string|payload|body|query|email|username|phone|ip(?:_address)?)/i;
const PROJECT_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function valueEnd(value: string, start: number): number {
  const first = value[start];
  if (first === '"' || first === "'") {
    let escaped = false;
    for (let index = start + 1; index < value.length; index += 1) {
      const current = value[index];
      if (escaped) escaped = false;
      else if (current === "\\") escaped = true;
      else if (current === first) return index + 1;
    }
    return value.length;
  }
  if (first === "{" || first === "[") {
    const closing = first === "{" ? "}" : "]";
    let depth = 0;
    let quote: string | null = null;
    let escaped = false;
    for (let index = start; index < value.length; index += 1) {
      const current = value[index];
      if (quote) {
        if (escaped) escaped = false;
        else if (current === "\\") escaped = true;
        else if (current === quote) quote = null;
        continue;
      }
      if (current === '"' || current === "'") quote = current;
      else if (current === first) depth += 1;
      else if (current === closing && --depth === 0) return index + 1;
    }
    return value.length;
  }
  let index = start;
  while (index < value.length && !/[,;\s}\]\r\n]/.test(value[index] ?? "")) index += 1;
  return index;
}

function redactAssignments(value: string): string {
  const key = /["']?[A-Za-z0-9_.-]+["']?\s*[:=]\s*/g;
  let result = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = key.exec(value))) {
    const keyText = match[0];
    const keyName = keyText.match(/[A-Za-z0-9_.-]+/)?.[0] ?? "";
    if (!SENSITIVE_KEY.test(keyName)) continue;
    const start = match.index + keyText.length;
    result += value.slice(last, start);
    const end = valueEnd(value, start);
    result += "[REDACTED]";
    last = end;
    key.lastIndex = end;
  }
  return result + value.slice(last);
}

/**
 * Scrubs credentials out of free text (work item descriptions, comments)
 * before it leaves the server. Internal notes stay readable; secrets do not.
 */
export function redactText(value: string, maxLength = 4000): string {
  const redacted = redactAssignments(
    value
      .replace(/((?:authorization)\s*[:=]\s*)(?:[A-Za-z][A-Za-z0-9_-]*\s+)?[^\s,;}\]]+/gi, "$1[REDACTED]")
      .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
      .replace(/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s)]+/gi, "[REDACTED_CONNECTION_STRING]")
      .replace(/(https?:\/\/)(?:[^/\s:@]+(?::[^/\s@]*)?@)([^/\s]+)/gi, "$1[REDACTED]@$2")
      .replace(/([?&](?:token|secret|password|api[_-]?key|dsn)=)[^&#\s]+/gi, "$1[REDACTED]")
      .replace(/((?:cookie|set-cookie)\s*[:=]\s*)[^\r\n]*/gi, "$1[REDACTED]")
      .replace(EMAIL, "[REDACTED_EMAIL]")
      .replace(IPV4, "[REDACTED_IP]")
  );
  return redacted.slice(0, maxLength);
}

// Credential detectors for text that is about to be WRITTEN to Hangar. They
// mirror the credential rules of redactText (authorization header, bearer,
// connection strings with a password, URL userinfo, secret query parameters,
// cookies, secret-looking assignments) plus well-known token shapes. Emails
// and IP addresses are redacted on read but are not credentials, so they do
// not block a write. Assignment values shorter than 8 characters or that look
// like placeholders ([REDACTED], <token>, ***, ${VAR}) are ignored so prose
// such as "password: see vault" still goes through.
const CREDENTIAL_KEY = String.raw`[A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[-_]?key|private[-_]?key|access[-_]?key|dsn)[A-Za-z0-9_.-]*`;
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
  /\bauthorization\s*[:=]\s*(?:[A-Za-z][A-Za-z0-9_-]*\s+)?[A-Za-z0-9._~+/=-]{8,}/i,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^\s:@/]+:[^\s@/]+@/i,
  /\bhttps?:\/\/[^/\s:@]+:[^/\s@]+@/i,
  /[?&](?:token|secret|password|api[_-]?key|dsn)=[^&#\s]{8,}/i,
  /\b(?:set-)?cookie\s*[:=]\s*[^\s=;]+=[^\s;]{8,}/i,
  /\bplane_api_[0-9a-f]{32}\b/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b/,
  /\bAC[0-9a-f]{32}:[0-9a-f]{32}\b/i,
];
const CREDENTIAL_ASSIGNMENT = new RegExp(String.raw`["']?(${CREDENTIAL_KEY})["']?\s*[:=]\s*["']?([^\s"',;}\]]+)`, "gi");
// The value capture stops at "]", so "[REDACTED]" arrives as "[REDACTED".
const PLACEHOLDER = /^(?:\[.*|<.*|\*+|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|x+|\.\.\.+)$/i;
// Naming a secret is fine ("secret: HANGAR_API_KEY"); only values are refused.
const ENV_VARIABLE_NAME = /^[A-Z][A-Z0-9_]{2,}$/;

/**
 * True when the text looks like it carries a credential. Used to refuse a
 * write outright; the matched value is never returned or logged.
 */
export function containsCredential(value: string): boolean {
  if (CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value))) return true;
  CREDENTIAL_ASSIGNMENT.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = CREDENTIAL_ASSIGNMENT.exec(value))) {
    const candidate = match[2] ?? "";
    if (candidate.length >= 8 && !PLACEHOLDER.test(candidate) && !ENV_VARIABLE_NAME.test(candidate)) return true;
  }
  return false;
}

function record(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : {};
}

function scalar(value: unknown, maxLength = 240): string | number | boolean | null {
  if (typeof value === "string") return redactText(value, maxLength);
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "boolean") return value;
  return null;
}

function stringValue(source: JsonRecord, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = scalar(source[key]);
    if (typeof value === "string" && value) return value;
  }
  return null;
}

function timestampValue(source: JsonRecord, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && Number.isFinite(Date.parse(value))) return value;
  }
  return null;
}

function safeId(value: unknown): string | number | null {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value)) return value;
  return null;
}

export function resourceId(raw: JsonRecord, ...keys: string[]): string | null {
  for (const key of ["id", ...keys]) {
    const value = safeId(raw[key]);
    if (value !== null) return String(value);
  }
  return null;
}

export function recordProjectId(raw: JsonRecord): string | null {
  const value = raw.project ?? raw.project_id;
  if (typeof value === "string" && PROJECT_UUID.test(value)) return value.toLowerCase();
  const nested = record(value);
  const nestedId = nested.id;
  return typeof nestedId === "string" && PROJECT_UUID.test(nestedId) ? nestedId.toLowerCase() : null;
}

function stringArray(value: unknown, max = 50): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string").slice(0, max);
}

function htmlToText(value: string): string {
  return value
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<[^>]*>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function textBody(raw: JsonRecord, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = raw[key];
    if (typeof value === "string" && value.trim()) {
      const text = key.endsWith("_stripped") ? value : htmlToText(value);
      const redacted = redactText(text, 8000);
      if (redacted) return redacted;
    }
  }
  return null;
}

export function workItemIdentifier(raw: JsonRecord, projectIdentifier: string | null): string | null {
  const sequence = raw.sequence_id;
  if (!projectIdentifier) return null;
  if (typeof sequence === "number" && Number.isSafeInteger(sequence) && sequence > 0) {
    return `${projectIdentifier}-${sequence}`;
  }
  return null;
}

export function sanitizeProject(raw: JsonRecord): JsonRecord {
  return {
    id: stringValue(raw, "id"),
    identifier: stringValue(raw, "identifier"),
    name: stringValue(raw, "name"),
    description: textBody(raw, "description_stripped", "description_html", "description"),
    lead: stringValue(raw, "lead") ?? record(raw.lead).id ?? null,
    created_at: timestampValue(raw, "created_at"),
    updated_at: timestampValue(raw, "updated_at"),
    archived_at: timestampValue(raw, "archived_at"),
    total_members: typeof raw.total_members === "number" ? raw.total_members : null,
    total_cycles: typeof raw.total_cycles === "number" ? raw.total_cycles : null,
    total_modules: typeof raw.total_modules === "number" ? raw.total_modules : null,
  };
}

export function sanitizeWorkItem(raw: JsonRecord, projectIdentifier: string | null): JsonRecord {
  return {
    id: stringValue(raw, "id"),
    identifier: workItemIdentifier(raw, projectIdentifier),
    project: recordProjectId(raw),
    name: stringValue(raw, "name"),
    description: textBody(raw, "description_stripped", "description_html"),
    priority: stringValue(raw, "priority"),
    state: stringValue(raw, "state"),
    assignees: stringArray(raw.assignee_ids ?? raw.assignees),
    labels: stringArray(raw.label_ids ?? raw.labels),
    parent: stringValue(raw, "parent"),
    created_at: timestampValue(raw, "created_at"),
    updated_at: timestampValue(raw, "updated_at"),
    completed_at: timestampValue(raw, "completed_at"),
    target_date: timestampValue(raw, "target_date"),
    start_date: timestampValue(raw, "start_date"),
  };
}

export function sanitizeComment(raw: JsonRecord): JsonRecord {
  return {
    id: stringValue(raw, "id"),
    comment: textBody(raw, "comment_stripped", "comment_html", "comment"),
    actor: stringValue(raw, "created_by") ?? record(raw.actor).id ?? null,
    created_at: timestampValue(raw, "created_at"),
    updated_at: timestampValue(raw, "updated_at"),
  };
}

export function sanitizeState(raw: JsonRecord): JsonRecord {
  return {
    id: stringValue(raw, "id"),
    name: stringValue(raw, "name"),
    group: stringValue(raw, "group"),
    color: stringValue(raw, "color"),
    default: typeof raw.default === "boolean" ? raw.default : null,
    sequence: typeof raw.sequence === "number" ? raw.sequence : null,
  };
}

export function sanitizeLabel(raw: JsonRecord): JsonRecord {
  return {
    id: stringValue(raw, "id"),
    name: stringValue(raw, "name"),
    description: textBody(raw, "description_stripped", "description"),
    color: stringValue(raw, "color"),
  };
}

const MEMBER_ROLES: Record<number, string> = { 20: "admin", 15: "member", 5: "guest" };

export function sanitizeMember(raw: JsonRecord): JsonRecord {
  const role = typeof raw.role === "number" ? (MEMBER_ROLES[raw.role] ?? String(raw.role)) : stringValue(raw, "role");
  return {
    id: stringValue(raw, "id"),
    display_name: stringValue(raw, "display_name"),
    role,
  };
}
