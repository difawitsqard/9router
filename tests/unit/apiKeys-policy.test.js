// Verify API key policy: tier (unlimited/restricted), expiry, quota, allowlist.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";

const originalDataDir = process.env.DATA_DIR;
let tempDir;
let db;

beforeAll(async () => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "9router-keys-"));
  process.env.DATA_DIR = tempDir;
  vi.resetModules();
  db = await import("@/lib/db/index.js");
  await db.initDb();
});

afterAll(() => {
  if (tempDir) {
    // On Windows the SQLite file may still be held by the driver — best-effort cleanup.
    try {
      fs.rmSync(tempDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    } catch {
      /* ignore — temp dir will be reaped by OS */
    }
  }
  if (originalDataDir === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = originalDataDir;
});

beforeEach(async () => {
  // Clean slate per test
  const all = await db.getApiKeys();
  for (const k of all) await db.deleteApiKey(k.id);
});

describe("apiKeysRepo — tier defaults", () => {
  it("createApiKey defaults to 'restricted' tier", async () => {
    const k = await db.createApiKey("test", "machine-1");
    expect(k.tier).toBe("restricted");
    expect(k.tokenUsed).toBe(0);
    expect(k.tokenLimit).toBeNull();
    expect(k.expiresAt).toBeNull();
    // null = no allowlist set (allow all). Empty array would also mean allow all.
    expect(k.allowedModels === null || (Array.isArray(k.allowedModels) && k.allowedModels.length === 0)).toBe(true);
    expect(k.status).toBe("active");
  });

  it("createApiKey respects explicit options", async () => {
    const future = new Date(Date.now() + 7 * 86400000).toISOString();
    const k = await db.createApiKey("prod", "m-1", {
      tier: "unlimited",
      expiresAt: future,
      tokenLimit: 1000,
      allowedModels: ["openai/gpt-4"],
    });
    expect(k.tier).toBe("unlimited");
    expect(k.expiresAt).toBe(future);
    expect(k.tokenLimit).toBe(1000);
    expect(k.allowedModels).toEqual(["openai/gpt-4"]);
    expect(k.status).toBe("unlimited");
  });
});

describe("apiKeysRepo — validateApiKey", () => {
  it("returns NOT_FOUND for missing key", async () => {
    const r = await db.validateApiKey("sk-fake-nope");
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("not_found");
  });

  it("returns INACTIVE for paused key", async () => {
    const k = await db.createApiKey("paused", "m-1");
    await db.updateApiKey(k.id, { isActive: false });
    const r = await db.validateApiKey(k.key);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("key_inactive");
  });

  it("returns EXPIRED for past expiresAt (restricted)", async () => {
    const past = new Date(Date.now() - 1000).toISOString();
    const k = await db.createApiKey("expired", "m-1", { expiresAt: past });
    const r = await db.validateApiKey(k.key);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("key_expired");
  });

  it("returns OK when expiresAt is in the future", async () => {
    const future = new Date(Date.now() + 86400000).toISOString();
    const k = await db.createApiKey("ok", "m-1", { expiresAt: future });
    const r = await db.validateApiKey(k.key);
    expect(r.valid).toBe(true);
    expect(r.reason).toBe("ok");
  });

  it("returns QUOTA_EXCEEDED when tokenUsed >= tokenLimit", async () => {
    const k = await db.createApiKey("limited", "m-1", { tokenLimit: 100 });
    await db.incrementTokenUsed(k.key, 100);
    const r = await db.validateApiKey(k.key);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("quota_exceeded");
  });

  it("unlimited tier bypasses expiry", async () => {
    const past = new Date(Date.now() - 1000).toISOString();
    const k = await db.createApiKey("god", "m-1", {
      tier: "unlimited",
      expiresAt: past,
    });
    const r = await db.validateApiKey(k.key);
    expect(r.valid).toBe(true);
  });

  it("unlimited tier bypasses quota", async () => {
    const k = await db.createApiKey("god", "m-1", {
      tier: "unlimited",
      tokenLimit: 10,
    });
    await db.incrementTokenUsed(k.key, 999);
    const r = await db.validateApiKey(k.key);
    expect(r.valid).toBe(true);
  });

  it("unlimited tier still respects isActive=false", async () => {
    const k = await db.createApiKey("god", "m-1", { tier: "unlimited" });
    await db.updateApiKey(k.id, { isActive: false });
    const r = await db.validateApiKey(k.key);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("key_inactive");
  });
});

describe("apiKeysRepo — isModelAllowedForKey", () => {
  it("unlimited tier allows any model", async () => {
    const k = await db.createApiKey("god", "m-1", { tier: "unlimited" });
    const ctx = (await db.validateApiKey(k.key)).key;
    expect(db.isModelAllowedForKey(ctx, "openai/gpt-4")).toBe(true);
    expect(db.isModelAllowedForKey(ctx, "anthropic/claude")).toBe(true);
  });

  it("restricted with empty allowlist allows any model", async () => {
    const k = await db.createApiKey("free", "m-1", { allowedModels: [] });
    const ctx = (await db.validateApiKey(k.key)).key;
    expect(db.isModelAllowedForKey(ctx, "openai/gpt-4")).toBe(true);
  });

  it("restricted with non-empty allowlist enforces strict match", async () => {
    const k = await db.createApiKey("limited", "m-1", {
      allowedModels: ["openai/gpt-4", "anthropic/claude-3"],
    });
    const ctx = (await db.validateApiKey(k.key)).key;
    expect(db.isModelAllowedForKey(ctx, "openai/gpt-4")).toBe(true);
    expect(db.isModelAllowedForKey(ctx, "anthropic/claude-3")).toBe(true);
    expect(db.isModelAllowedForKey(ctx, "openai/gpt-3.5")).toBe(false);
    expect(db.isModelAllowedForKey(ctx, "google/gemini")).toBe(false);
  });
});

describe("apiKeysRepo — incrementTokenUsed", () => {
  it("increments atomically", async () => {
    const k = await db.createApiKey("count", "m-1");
    const r1 = await db.incrementTokenUsed(k.key, 50);
    expect(r1.tokenUsed).toBe(50);
    const r2 = await db.incrementTokenUsed(k.key, 30);
    expect(r2.tokenUsed).toBe(80);
  });

  it("100 parallel increments → no count loss", async () => {
    const k = await db.createApiKey("race", "m-1");
    const N = 100;
    const promises = [];
    for (let i = 0; i < N; i++) {
      promises.push(db.incrementTokenUsed(k.key, 10));
    }
    await Promise.all(promises);
    const fresh = await db.getApiKeyById(k.id);
    expect(fresh.tokenUsed).toBe(N * 10);
  });

  it("returns null for missing key", async () => {
    const r = await db.incrementTokenUsed("sk-nonexistent", 5);
    expect(r).toBeNull();
  });

  it("ignores non-positive delta", async () => {
    const k = await db.createApiKey("noop", "m-1");
    await db.incrementTokenUsed(k.key, 50);
    expect(await db.incrementTokenUsed(k.key, 0)).toBeNull();
    expect(await db.incrementTokenUsed(k.key, -10)).toBeNull();
    const fresh = await db.getApiKeyById(k.id);
    expect(fresh.tokenUsed).toBe(50);
  });
});

describe("apiKeysRepo — resetApiKeyUsage", () => {
  it("resets tokenUsed to 0", async () => {
    const k = await db.createApiKey("reset", "m-1");
    await db.incrementTokenUsed(k.key, 500);
    expect((await db.getApiKeyById(k.id)).tokenUsed).toBe(500);
    await db.resetApiKeyUsage(k.id);
    expect((await db.getApiKeyById(k.id)).tokenUsed).toBe(0);
  });
});

describe("apiKeysRepo — updateApiKey policy fields", () => {
  it("updates tier", async () => {
    const k = await db.createApiKey("up", "m-1");
    await db.updateApiKey(k.id, { tier: "unlimited" });
    expect((await db.getApiKeyById(k.id)).tier).toBe("unlimited");
  });

  it("updates allowedModels", async () => {
    const k = await db.createApiKey("up", "m-1");
    await db.updateApiKey(k.id, { allowedModels: ["openai/gpt-4"] });
    expect((await db.getApiKeyById(k.id)).allowedModels).toEqual(["openai/gpt-4"]);
  });

  it("clears expiresAt with null", async () => {
    const future = new Date(Date.now() + 86400000).toISOString();
    const k = await db.createApiKey("up", "m-1", { expiresAt: future });
    await db.updateApiKey(k.id, { expiresAt: null });
    expect((await db.getApiKeyById(k.id)).expiresAt).toBeNull();
  });

  it("status reflects derived state", async () => {
    const past = new Date(Date.now() - 1000).toISOString();
    const k = await db.createApiKey("up", "m-1");
    await db.updateApiKey(k.id, { expiresAt: past });
    expect((await db.getApiKeyById(k.id)).status).toBe("expired");

    await db.updateApiKey(k.id, { expiresAt: null, tokenLimit: 10 });
    await db.incrementTokenUsed(k.key, 10);
    expect((await db.getApiKeyById(k.id)).status).toBe("quota_exceeded");

    await db.updateApiKey(k.id, { tier: "unlimited" });
    expect((await db.getApiKeyById(k.id)).status).toBe("unlimited");
  });
});
