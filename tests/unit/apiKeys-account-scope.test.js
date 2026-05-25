// Verify API key account scope: allowedConnectionIds with UUID + noauth:<provider> tokens.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";

const originalDataDir = process.env.DATA_DIR;
let tempDir;
let db;

beforeAll(async () => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "9router-scope-"));
  process.env.DATA_DIR = tempDir;
  vi.resetModules();
  db = await import("@/lib/db/index.js");
  await db.initDb();
});

afterAll(() => {
  if (tempDir) {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    } catch {
      /* ignore */
    }
  }
  if (originalDataDir === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = originalDataDir;
});

beforeEach(async () => {
  const all = await db.getApiKeys();
  for (const k of all) await db.deleteApiKey(k.id);
});

const UUID_A = "11111111-2222-4333-8444-555555555555";
const UUID_B = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const NOT_A_UUID = "not-a-real-id";

describe("apiKeysRepo — allowedConnectionIds storage & dedup", () => {
  it("createApiKey persists a mixed UUID + noauth allowlist", async () => {
    const k = await db.createApiKey("scoped", "m1", {
      allowedConnectionIds: [UUID_A, "noauth:kiro"],
    });
    expect(k.allowedConnectionIds).toEqual([UUID_A, "noauth:kiro"]);

    const fetched = await db.getApiKeyById(k.id);
    expect(fetched.allowedConnectionIds).toEqual([UUID_A, "noauth:kiro"]);
  });

  it("dedups duplicate tokens", async () => {
    const k = await db.createApiKey("dup", "m1", {
      allowedConnectionIds: [UUID_A, UUID_A, "noauth:kiro", "noauth:kiro"],
    });
    expect(k.allowedConnectionIds).toEqual([UUID_A, "noauth:kiro"]);
  });

  it("drops invalid tokens silently at the storage layer", async () => {
    const k = await db.createApiKey("invalid", "m1", {
      allowedConnectionIds: [UUID_A, NOT_A_UUID, "", null, "noauth:opencode"],
    });
    expect(k.allowedConnectionIds).toEqual([UUID_A, "noauth:opencode"]);
  });

  it("null/empty array == no scope (legacy keys)", async () => {
    const k1 = await db.createApiKey("none1", "m1");
    expect(k1.allowedConnectionIds).toBeNull();

    const k2 = await db.createApiKey("none2", "m1", { allowedConnectionIds: [] });
    expect(k2.allowedConnectionIds).toBeNull();
  });

  it("updateApiKey can clear the allowlist", async () => {
    const k = await db.createApiKey("update", "m1", {
      allowedConnectionIds: [UUID_A],
    });
    expect(k.allowedConnectionIds).toEqual([UUID_A]);

    const updated = await db.updateApiKey(k.id, { allowedConnectionIds: null });
    expect(updated.allowedConnectionIds).toBeNull();
  });

  it("updateApiKey replaces the list (not merge)", async () => {
    const k = await db.createApiKey("replace", "m1", {
      allowedConnectionIds: [UUID_A, "noauth:kiro"],
    });
    const updated = await db.updateApiKey(k.id, {
      allowedConnectionIds: [UUID_B],
    });
    expect(updated.allowedConnectionIds).toEqual([UUID_B]);
  });
});

describe("isConnectionAllowedForKey — runtime check", () => {
  it("unlimited tier always returns true", () => {
    const key = {
      tier: "unlimited",
      allowedConnectionIds: [UUID_A], // ignored for unlimited
    };
    expect(db.isConnectionAllowedForKey(key, { id: UUID_B, provider: "openai" })).toBe(true);
  });

  it("restricted tier with null allowlist returns true (no scope)", () => {
    const key = { tier: "restricted", allowedConnectionIds: null };
    expect(db.isConnectionAllowedForKey(key, { id: UUID_A, provider: "openai" })).toBe(true);
  });

  it("restricted tier with empty allowlist returns true (legacy semantics)", () => {
    const key = { tier: "restricted", allowedConnectionIds: [] };
    expect(db.isConnectionAllowedForKey(key, { id: UUID_A, provider: "openai" })).toBe(true);
  });

  it("matches connection by exact UUID", () => {
    const key = { tier: "restricted", allowedConnectionIds: [UUID_A] };
    expect(db.isConnectionAllowedForKey(key, { id: UUID_A, provider: "openai" })).toBe(true);
    expect(db.isConnectionAllowedForKey(key, { id: UUID_B, provider: "openai" })).toBe(false);
  });

  it("matches noauth:<provider> for connections without UUIDs", () => {
    const key = { tier: "restricted", allowedConnectionIds: ["noauth:kiro"] };
    expect(db.isConnectionAllowedForKey(key, { provider: "kiro" })).toBe(true);
    expect(db.isConnectionAllowedForKey(key, { provider: "opencode" })).toBe(false);
  });

  it("UUID match takes precedence even when noauth also listed", () => {
    const key = {
      tier: "restricted",
      allowedConnectionIds: [UUID_A, "noauth:kiro"],
    };
    expect(db.isConnectionAllowedForKey(key, { id: UUID_A, provider: "openai" })).toBe(true);
    expect(db.isConnectionAllowedForKey(key, { provider: "kiro" })).toBe(true);
  });

  it("accepts a string id directly", () => {
    const key = { tier: "restricted", allowedConnectionIds: [UUID_A] };
    expect(db.isConnectionAllowedForKey(key, UUID_A)).toBe(true);
    expect(db.isConnectionAllowedForKey(key, UUID_B)).toBe(false);
  });

  it("returns false for missing/invalid conn", () => {
    const key = { tier: "restricted", allowedConnectionIds: [UUID_A] };
    expect(db.isConnectionAllowedForKey(key, null)).toBe(false);
    expect(db.isConnectionAllowedForKey(key, {})).toBe(false);
  });
});

describe("API route validation parity", () => {
  // Mirror the validation behaviour the keys API enforces. We re-implement the
  // validator inline so this test stays decoupled from Next.js route handlers,
  // but exercises the same regex contract that the route uses.
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const NOAUTH_RE = /^noauth:([a-z0-9_-]+)$/i;
  const KNOWN_NOAUTH = new Set(["kiro", "opencode", "searxng"]);

  function validate(value, validUuids) {
    if (value == null) return { ok: true, list: null };
    if (!Array.isArray(value)) return { ok: false, error: "not array" };
    if (value.length === 0) return { ok: true, list: [] };
    const seen = new Set();
    const out = [];
    for (const raw of value) {
      if (typeof raw !== "string") return { ok: false, error: "non-string" };
      const v = raw.trim();
      if (UUID_RE.test(v)) {
        const lc = v.toLowerCase();
        if (seen.has(lc)) continue;
        seen.add(lc);
        if (!validUuids.has(v) && !validUuids.has(lc)) return { ok: false, error: `unknown ${v}` };
        out.push(v);
        continue;
      }
      const m = v.match(NOAUTH_RE);
      if (m) {
        const pid = m[1].toLowerCase();
        const token = `noauth:${pid}`;
        if (seen.has(token)) continue;
        seen.add(token);
        if (!KNOWN_NOAUTH.has(pid)) return { ok: false, error: `unknown noauth ${pid}` };
        out.push(token);
        continue;
      }
      return { ok: false, error: `bad token ${v}` };
    }
    return { ok: true, list: out };
  }

  it("accepts null (no scope)", () => {
    const r = validate(null, new Set());
    expect(r.ok).toBe(true);
    expect(r.list).toBeNull();
  });

  it("accepts empty array (scoped, but nothing chosen)", () => {
    const r = validate([], new Set());
    expect(r.ok).toBe(true);
    expect(r.list).toEqual([]);
  });

  it("rejects non-array input", () => {
    expect(validate("nope", new Set()).ok).toBe(false);
  });

  it("rejects unknown UUIDs strictly", () => {
    const r = validate([UUID_A], new Set([UUID_B]));
    expect(r.ok).toBe(false);
  });

  it("rejects unknown noauth providers strictly", () => {
    const r = validate(["noauth:fakeprovider"], new Set());
    expect(r.ok).toBe(false);
  });

  it("rejects malformed tokens (not UUID, not noauth)", () => {
    const r = validate(["banana"], new Set());
    expect(r.ok).toBe(false);
  });

  it("dedups + normalises noauth case", () => {
    const r = validate(["noauth:KIRO", "noauth:kiro", UUID_A], new Set([UUID_A]));
    expect(r.ok).toBe(true);
    expect(r.list).toEqual(["noauth:kiro", UUID_A]);
  });
});

describe("auth picker filter contract", () => {
  // Verifies the filter shape used by getProviderCredentials in src/sse/services/auth.js:
  //   allowedConnectionIds.has(c.id) || allowedConnectionIds.has(`noauth:${providerId}`)
  function pickerFilter(connections, providerId, allowedSet) {
    if (!allowedSet) return connections;
    const noauthToken = `noauth:${providerId}`;
    return connections.filter(
      (c) => allowedSet.has(c.id) || allowedSet.has(noauthToken),
    );
  }

  const conns = [
    { id: UUID_A, provider: "openai", name: "primary" },
    { id: UUID_B, provider: "openai", name: "backup" },
  ];

  it("null allowlist returns all", () => {
    expect(pickerFilter(conns, "openai", null)).toHaveLength(2);
  });

  it("UUID-A only", () => {
    const out = pickerFilter(conns, "openai", new Set([UUID_A]));
    expect(out).toEqual([conns[0]]);
  });

  it("noauth-token only — no real conns shown for credentialed provider", () => {
    const out = pickerFilter(conns, "openai", new Set(["noauth:kiro"]));
    expect(out).toEqual([]);
  });

  it("noauth-token matching the provider returns all connections (kiro convention)", () => {
    const kiroConns = [{ id: "kiro-fake-1", provider: "kiro", name: "device" }];
    const out = pickerFilter(kiroConns, "kiro", new Set(["noauth:kiro"]));
    expect(out).toEqual(kiroConns);
  });
});
