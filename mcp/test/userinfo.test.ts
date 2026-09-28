import { describe, expect, it } from "vitest";
import { HangarConfigError, loadHangarConfig } from "../src/config.js";
import { UserinfoEmailResolver } from "../src/userinfo.js";
import { jsonResponse, testConfig } from "./fixtures.js";

const USERINFO = new URL("https://issuer.example.test/oidc/v1/userinfo");
const TOKEN = "caller-access-token-value";

interface Seen {
  url: string;
  init: RequestInit | undefined;
}

function resolverWith(respond: (call: number) => Response | Promise<Response>, options: { now?: () => number } = {}) {
  const seen: Seen[] = [];
  const logs: string[] = [];
  const resolver = new UserinfoEmailResolver(testConfig({ oidcUserinfoUrl: USERINFO }), {
    fetch: async (input, init) => {
      seen.push({ url: String(input), init });
      return respond(seen.length);
    },
    log: (line) => logs.push(line),
    ...(options.now ? { now: options.now } : {}),
  });
  return { resolver, seen, logs };
}

describe("userinfo email resolution", () => {
  it("sends the caller bearer to the userinfo URL without following redirects and caches by sub", async () => {
    let now = 1_000_000;
    const { resolver, seen } = resolverWith(() => jsonResponse({ sub: "u1", email: "Camila@Example.test" }), {
      now: () => now,
    });
    expect(await resolver.emailFor("u1", TOKEN)).toBe("camila@example.test");
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(USERINFO.href);
    expect(seen[0]!.init?.redirect).toBe("error");
    expect(((seen[0]!.init?.headers ?? {}) as Record<string, string>).Authorization).toBe(`Bearer ${TOKEN}`);

    now += 9 * 60_000;
    expect(await resolver.emailFor("u1", TOKEN)).toBe("camila@example.test");
    expect(seen).toHaveLength(1);
    now += 2 * 60_000; // past the 10 minute positive TTL
    await resolver.emailFor("u1", TOKEN);
    expect(seen).toHaveLength(2);
  });

  it("skips an unverified email and falls back to an email-shaped preferred_username", async () => {
    const { resolver } = resolverWith(() =>
      jsonResponse({ sub: "u1", email: "x@example.test", email_verified: false, preferred_username: "c@dumont.au" })
    );
    expect(await resolver.emailFor("u1", TOKEN)).toBe("c@dumont.au");
  });

  it("caches a miss for 60 s and logs one line per failure class per minute, never the token", async () => {
    let now = 5_000_000;
    let subject = "u1";
    const { resolver, seen, logs } = resolverWith(
      () => jsonResponse({ sub: subject, preferred_username: "cristian" }),
      {
        now: () => now,
      }
    );
    expect(await resolver.emailFor("u1", TOKEN)).toBeNull();
    expect(await resolver.emailFor("u1", TOKEN)).toBeNull();
    expect(seen).toHaveLength(1);
    now += 61_000;
    expect(await resolver.emailFor("u1", TOKEN)).toBeNull();
    expect(seen).toHaveLength(2);
    subject = "u2";
    expect(await resolver.emailFor("u2", TOKEN)).toBeNull(); // same class, same minute: no new line
    expect(seen).toHaveLength(3);
    expect(logs).toEqual([
      "hangar-mcp userinfo-email outcome=no_email fallback=sub",
      "hangar-mcp userinfo-email outcome=no_email fallback=sub",
    ]);
    expect(logs.join("\n")).not.toContain(TOKEN);
  });

  it("returns null on HTTP errors, subject mismatch, invalid JSON and oversized bodies", async () => {
    const cases: Array<[() => Response, string]> = [
      [() => jsonResponse({ error: "invalid_token" }, 401), "http_status"],
      [() => jsonResponse({ sub: "someone-else", email: "x@example.test" }), "subject_mismatch"],
      [() => new Response("not json", { status: 200 }), "invalid_json"],
      [() => new Response(JSON.stringify({ sub: "u1", pad: "x".repeat(70 * 1024) }), { status: 200 }), "too_large"],
    ];
    for (const [respond, outcome] of cases) {
      const { resolver, logs } = resolverWith(respond);
      // oxlint-disable-next-line no-await-in-loop
      expect(await resolver.emailFor("u1", TOKEN)).toBeNull();
      expect(logs).toEqual([`hangar-mcp userinfo-email outcome=${outcome} fallback=sub`]);
    }
  });

  it("returns null on network errors and never throws", async () => {
    const { resolver, logs } = resolverWith(() => {
      throw new TypeError("fetch failed");
    });
    expect(await resolver.emailFor("u1", TOKEN)).toBeNull();
    expect(logs).toEqual(["hangar-mcp userinfo-email outcome=network fallback=sub"]);
  });

  it("gives up after the 2 s timeout", async () => {
    const resolver = new UserinfoEmailResolver(testConfig({ oidcUserinfoUrl: USERINFO }), {
      fetch: (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
      log: () => {},
    });
    const started = Date.now();
    expect(await resolver.emailFor("u1", TOKEN)).toBeNull();
    expect(Date.now() - started).toBeGreaterThanOrEqual(1900);
  });

  it("shares one in-flight lookup per subject and bounds the cache to 1000 entries", async () => {
    const { resolver, seen } = resolverWith((call) =>
      jsonResponse({ sub: `s${call}`, email: `u${call}@example.test` })
    );
    // Subjects are named after the call number so each lookup matches its own sub.
    await Promise.all([resolver.emailFor("s1", TOKEN), resolver.emailFor("s1", TOKEN)]);
    expect(seen).toHaveLength(1);
    for (let index = 2; index <= 1001; index += 1) {
      // oxlint-disable-next-line no-await-in-loop
      await resolver.emailFor(`s${index}`, TOKEN);
    }
    expect(seen).toHaveLength(1001);
    await resolver.emailFor("s1", TOKEN); // evicted as the oldest entry
    expect(seen).toHaveLength(1002);
  });

  it("is disabled without a userinfo URL", async () => {
    let calls = 0;
    const resolver = new UserinfoEmailResolver(testConfig({ oidcUserinfoUrl: null }), {
      fetch: async () => {
        calls += 1;
        return jsonResponse({});
      },
    });
    expect(await resolver.emailFor("u1", TOKEN)).toBeNull();
    expect(calls).toBe(0);
  });

  it("accepts only a same-origin MCP_OIDC_USERINFO_URL", () => {
    const base = {
      HANGAR_API_KEY: "plane_api_" + "a".repeat(32),
      HANGAR_WORKSPACE_SLUG: "dumont",
      HANGAR_ALLOWED_PROJECTS: "HGR",
      MCP_OIDC_ISSUER: "https://auth.getdumont.ai",
      MCP_OIDC_JWKS_URL: "https://auth.getdumont.ai/oauth/v2/keys",
      MCP_RESOURCE_URL: "https://hangar.getdumont.ai/mcp",
      MCP_OIDC_AUDIENCE: "390213468206137347",
    };
    expect(
      loadHangarConfig({ ...base, MCP_OIDC_USERINFO_URL: "https://auth.getdumont.ai/custom/userinfo" }).oidcUserinfoUrl
        ?.href
    ).toBe("https://auth.getdumont.ai/custom/userinfo");
    expect(() => loadHangarConfig({ ...base, MCP_OIDC_USERINFO_URL: "https://evil.example/userinfo" })).toThrow(
      HangarConfigError
    );
    expect(() => loadHangarConfig({ ...base, MCP_OIDC_USERINFO_URL: "http://auth.getdumont.ai/userinfo" })).toThrow(
      HangarConfigError
    );
  });
});
