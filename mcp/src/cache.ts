/**
 * Process-wide cache of what Hangar showed ONE caller, keyed by the caller's
 * token `sub`. The MCP acts as the logged-in user, so two users can see
 * different projects and members: nothing cached for one subject is ever
 * served to another. Entries expire after `ttlMs`; at most `maxSubjects`
 * subjects are kept (least recently used dropped first). A TTL of 0 disables
 * caching.
 */
export type SubjectCacheKey = "projects" | "workspace_members" | "me";

const DEFAULT_MAX_SUBJECTS = 1000;

interface Entry {
  readonly at: number;
  readonly value: unknown;
}

export class SubjectCache {
  private readonly subjects = new Map<string, Map<SubjectCacheKey, Entry>>();

  constructor(
    private readonly ttlMs: number,
    private readonly maxSubjects = DEFAULT_MAX_SUBJECTS,
    private readonly now: () => number = Date.now
  ) {}

  get<T>(subject: string, key: SubjectCacheKey): T | undefined {
    if (this.ttlMs <= 0 || !subject) return undefined;
    const entries = this.subjects.get(subject);
    const entry = entries?.get(key);
    if (!entries || !entry) return undefined;
    if (this.now() - entry.at >= this.ttlMs) {
      entries.delete(key);
      if (entries.size === 0) this.subjects.delete(subject);
      return undefined;
    }
    // Refresh recency.
    this.subjects.delete(subject);
    this.subjects.set(subject, entries);
    return entry.value as T;
  }

  set(subject: string, key: SubjectCacheKey, value: unknown): void {
    if (this.ttlMs <= 0 || !subject) return;
    let entries = this.subjects.get(subject);
    if (entries) {
      this.subjects.delete(subject);
    } else {
      entries = new Map();
      if (this.subjects.size >= this.maxSubjects) this.evict();
    }
    entries.set(key, { at: this.now(), value });
    this.subjects.set(subject, entries);
  }

  /** Drops everything cached for one subject (for example after Hangar refused it). */
  forget(subject: string): void {
    this.subjects.delete(subject);
  }

  get size(): number {
    return this.subjects.size;
  }

  private evict(): void {
    const now = this.now();
    for (const [subject, entries] of this.subjects) {
      for (const [key, entry] of entries) {
        if (now - entry.at >= this.ttlMs) entries.delete(key);
      }
      if (entries.size === 0) this.subjects.delete(subject);
    }
    while (this.subjects.size >= this.maxSubjects) {
      const oldest = this.subjects.keys().next().value;
      if (oldest === undefined) break;
      this.subjects.delete(oldest);
    }
  }
}
