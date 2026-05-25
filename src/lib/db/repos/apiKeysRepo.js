import { v4 as uuidv4 } from "uuid";
import { getAdapter } from "../driver.js";

// ─── Constants ──────────────────────────────────────────────────────────
export const KEY_TIER = Object.freeze({
  UNLIMITED: "unlimited", // god mode — bypass all policy checks
  RESTRICTED: "restricted",
});

export const VALIDATION_REASON = Object.freeze({
  OK: "ok",
  NOT_FOUND: "not_found",
  INACTIVE: "key_inactive",
  EXPIRED: "key_expired",
  QUOTA_EXCEEDED: "quota_exceeded",
});

// ─── Helpers ────────────────────────────────────────────────────────────
function parseAllowedModels(raw) {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    const list = parsed.filter((m) => typeof m === "string" && m.trim() !== "");
    return list.length > 0 ? list : null;
  } catch {
    return null;
  }
}

function serializeAllowedModels(value) {
  if (!Array.isArray(value)) return null;
  const list = value.filter((m) => typeof m === "string" && m.trim() !== "");
  return list.length > 0 ? JSON.stringify(list) : null;
}

// ─── Allowed Connection IDs ─────────────────────────────────────────────
// Allowlist entries can be either:
//   • UUID v4 string  → references a row in providerConnections
//   • "noauth:<provider>" → pseudo-id for auth-less providers (Kiro, OpenCode Free, …)
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NOAUTH_RE = /^noauth:[a-z0-9_-]+$/i;

function isValidConnectionToken(value) {
  if (typeof value !== "string") return false;
  const v = value.trim();
  return UUID_RE.test(v) || NOAUTH_RE.test(v);
}

function parseAllowedConnectionIds(raw) {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    const list = parsed.filter(isValidConnectionToken).map((s) => s.trim());
    return list.length > 0 ? list : null;
  } catch {
    return null;
  }
}

function serializeAllowedConnectionIds(value) {
  if (!Array.isArray(value)) return null;
  const seen = new Set();
  const list = [];
  for (const v of value) {
    if (!isValidConnectionToken(v)) continue;
    const t = v.trim();
    if (seen.has(t)) continue;
    seen.add(t);
    list.push(t);
  }
  return list.length > 0 ? JSON.stringify(list) : null;
}

function normalizeTier(raw) {
  // Legacy keys (null) → unlimited (zero behavior change for existing keys)
  if (raw === KEY_TIER.UNLIMITED || raw === KEY_TIER.RESTRICTED) return raw;
  return KEY_TIER.UNLIMITED;
}

function rowToKey(row) {
  if (!row) return null;
  return {
    id: row.id,
    key: row.key,
    name: row.name,
    machineId: row.machineId,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt || null,
    tier: normalizeTier(row.tier),
    expiresAt: row.expiresAt || null,
    tokenLimit: row.tokenLimit == null ? null : Number(row.tokenLimit),
    tokenUsed: row.tokenUsed == null ? 0 : Number(row.tokenUsed),
    allowedModels: parseAllowedModels(row.allowedModels),
    allowedConnectionIds: parseAllowedConnectionIds(row.allowedConnectionIds),
  };
}

function isExpired(expiresAt) {
  if (!expiresAt) return false;
  const ts = Date.parse(expiresAt);
  if (Number.isNaN(ts)) return false;
  return ts <= Date.now();
}

function isQuotaExceeded(tokenLimit, tokenUsed) {
  if (tokenLimit == null) return false;
  return Number(tokenUsed || 0) >= Number(tokenLimit);
}

function deriveStatus(key) {
  if (!key.isActive) return "paused";
  if (key.tier === KEY_TIER.UNLIMITED) return "unlimited";
  if (isExpired(key.expiresAt)) return "expired";
  if (isQuotaExceeded(key.tokenLimit, key.tokenUsed)) return "quota_exceeded";
  return "active";
}

// ─── Read ───────────────────────────────────────────────────────────────
export async function getApiKeys() {
  const db = await getAdapter();
  const rows = db.all(`SELECT * FROM apiKeys ORDER BY createdAt ASC`);
  return rows.map(rowToKey).map((k) => ({ ...k, status: deriveStatus(k) }));
}

export async function getApiKeyById(id) {
  const db = await getAdapter();
  const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
  const key = rowToKey(row);
  return key ? { ...key, status: deriveStatus(key) } : null;
}

export async function getApiKeyByKey(rawKey) {
  if (!rawKey) return null;
  const db = await getAdapter();
  const row = db.get(`SELECT * FROM apiKeys WHERE key = ?`, [rawKey]);
  const key = rowToKey(row);
  return key ? { ...key, status: deriveStatus(key) } : null;
}

// ─── Write ──────────────────────────────────────────────────────────────
/**
 * Create a new API key.
 * @param {string} name
 * @param {string} machineId
 * @param {object} [options]
 * @param {'unlimited'|'restricted'} [options.tier='restricted']
 * @param {string|null} [options.expiresAt]
 * @param {number|null} [options.tokenLimit]
 * @param {string[]|null} [options.allowedModels]
 */
export async function createApiKey(name, machineId, options = {}) {
  if (!machineId) throw new Error("machineId is required");
  const db = await getAdapter();
  const { generateApiKeyWithMachine } = await import("@/shared/utils/apiKey");
  const result = generateApiKeyWithMachine(machineId);

  const tier =
    options.tier === KEY_TIER.UNLIMITED
      ? KEY_TIER.UNLIMITED
      : KEY_TIER.RESTRICTED; // new keys default to restricted (least privilege)

  const expiresAt = options.expiresAt || null;
  const tokenLimit =
    options.tokenLimit != null && options.tokenLimit !== ""
      ? Math.max(0, Math.floor(Number(options.tokenLimit)))
      : null;
  const allowedModelsJson = serializeAllowedModels(options.allowedModels);
  const allowedConnectionIdsJson = serializeAllowedConnectionIds(options.allowedConnectionIds);
  const now = new Date().toISOString();

  const apiKey = {
    id: uuidv4(),
    name,
    key: result.key,
    machineId,
    isActive: true,
    createdAt: now,
    updatedAt: now,
    tier,
    expiresAt,
    tokenLimit,
    tokenUsed: 0,
    allowedModels: parseAllowedModels(allowedModelsJson),
    allowedConnectionIds: parseAllowedConnectionIds(allowedConnectionIdsJson),
  };

  db.run(
    `INSERT INTO apiKeys(id, key, name, machineId, isActive, createdAt, updatedAt, tier, expiresAt, tokenLimit, tokenUsed, allowedModels, allowedConnectionIds)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      apiKey.id, apiKey.key, apiKey.name, apiKey.machineId, 1,
      apiKey.createdAt, apiKey.updatedAt,
      tier, expiresAt, tokenLimit, 0, allowedModelsJson, allowedConnectionIdsJson,
    ]
  );

  return { ...apiKey, status: deriveStatus(apiKey) };
}

/**
 * Update API key fields. Allowed: isActive, name, tier, expiresAt, tokenLimit,
 * allowedModels, tokenUsed (for reset).
 */
export async function updateApiKey(id, data) {
  const db = await getAdapter();
  let result = null;
  db.transaction(() => {
    const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
    if (!row) return;
    const current = rowToKey(row);

    const next = {
      isActive: data.isActive === undefined ? current.isActive : !!data.isActive,
      name: data.name === undefined ? current.name : data.name,
      tier:
        data.tier === KEY_TIER.UNLIMITED || data.tier === KEY_TIER.RESTRICTED
          ? data.tier
          : current.tier,
      expiresAt: data.expiresAt === undefined ? current.expiresAt : (data.expiresAt || null),
      tokenLimit:
        data.tokenLimit === undefined
          ? current.tokenLimit
          : data.tokenLimit == null || data.tokenLimit === ""
            ? null
            : Math.max(0, Math.floor(Number(data.tokenLimit))),
      allowedModels:
        data.allowedModels === undefined
          ? current.allowedModels
          : Array.isArray(data.allowedModels) ? data.allowedModels : null,
      allowedConnectionIds:
        data.allowedConnectionIds === undefined
          ? current.allowedConnectionIds
          : Array.isArray(data.allowedConnectionIds) ? data.allowedConnectionIds : null,
      tokenUsed:
        data.tokenUsed === undefined
          ? current.tokenUsed
          : Math.max(0, Math.floor(Number(data.tokenUsed) || 0)),
    };

    const updatedAt = new Date().toISOString();

    db.run(
      `UPDATE apiKeys
         SET name = ?, isActive = ?, tier = ?, expiresAt = ?, tokenLimit = ?,
             tokenUsed = ?, allowedModels = ?, allowedConnectionIds = ?, updatedAt = ?
       WHERE id = ?`,
      [
        next.name,
        next.isActive ? 1 : 0,
        next.tier,
        next.expiresAt,
        next.tokenLimit,
        next.tokenUsed,
        serializeAllowedModels(next.allowedModels),
        serializeAllowedConnectionIds(next.allowedConnectionIds),
        updatedAt,
        id,
      ]
    );

    const merged = { ...current, ...next, updatedAt };
    result = { ...merged, status: deriveStatus(merged) };
  });
  return result;
}

export async function deleteApiKey(id) {
  const db = await getAdapter();
  const res = db.run(`DELETE FROM apiKeys WHERE id = ?`, [id]);
  return (res?.changes ?? 0) > 0;
}

/**
 * Reset token usage counter for a key (admin action).
 */
export async function resetApiKeyUsage(id) {
  const db = await getAdapter();
  let result = null;
  db.transaction(() => {
    const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
    if (!row) return;
    const updatedAt = new Date().toISOString();
    db.run(`UPDATE apiKeys SET tokenUsed = 0, updatedAt = ? WHERE id = ?`, [updatedAt, id]);
    const merged = { ...rowToKey(row), tokenUsed: 0, updatedAt };
    result = { ...merged, status: deriveStatus(merged) };
  });
  return result;
}

/**
 * Atomically increment tokenUsed counter. Used by usage tracking hook.
 * Counter naik untuk semua tier (audit), tapi hanya tier 'restricted' yang
 * di-enforce di pre-check.
 *
 * @param {string} rawKey - The full API key string (sk-...).
 * @param {number} delta - Tokens to add (>= 0).
 * @returns {Promise<{ id: string, tokenUsed: number, tokenLimit: number|null }|null>}
 */
export async function incrementTokenUsed(rawKey, delta) {
  if (!rawKey || !delta || delta <= 0) return null;
  const db = await getAdapter();
  let result = null;
  db.transaction(() => {
    const row = db.get(`SELECT id, tokenUsed, tokenLimit FROM apiKeys WHERE key = ?`, [rawKey]);
    if (!row) return;
    const next = Math.max(0, Math.floor(Number(row.tokenUsed || 0))) + Math.floor(delta);
    db.run(
      `UPDATE apiKeys SET tokenUsed = ?, updatedAt = ? WHERE id = ?`,
      [next, new Date().toISOString(), row.id]
    );
    result = {
      id: row.id,
      tokenUsed: next,
      tokenLimit: row.tokenLimit == null ? null : Number(row.tokenLimit),
    };
  });
  return result;
}

// ─── Validation ─────────────────────────────────────────────────────────
/**
 * Rich validator. Returns the full key context plus a `valid` + `reason`
 * verdict. Caller may inspect tier/policy to enforce additional checks
 * (e.g. model allowlist) at the request gate.
 *
 * Tier 'unlimited' (god mode) short-circuits expiry + quota checks but
 * remains subject to isActive (paused keys are always rejected).
 *
 * @param {string} rawKey
 * @returns {Promise<{ valid: boolean, reason: string, key?: object }>}
 */
export async function validateApiKey(rawKey) {
  if (!rawKey) return { valid: false, reason: VALIDATION_REASON.NOT_FOUND };
  const db = await getAdapter();
  const row = db.get(`SELECT * FROM apiKeys WHERE key = ?`, [rawKey]);
  if (!row) return { valid: false, reason: VALIDATION_REASON.NOT_FOUND };

  const key = rowToKey(row);

  if (!key.isActive) {
    return { valid: false, reason: VALIDATION_REASON.INACTIVE, key };
  }

  // God mode: skip expiry + quota checks.
  if (key.tier === KEY_TIER.UNLIMITED) {
    return { valid: true, reason: VALIDATION_REASON.OK, key };
  }

  if (isExpired(key.expiresAt)) {
    return { valid: false, reason: VALIDATION_REASON.EXPIRED, key };
  }

  if (isQuotaExceeded(key.tokenLimit, key.tokenUsed)) {
    return { valid: false, reason: VALIDATION_REASON.QUOTA_EXCEEDED, key };
  }

  return { valid: true, reason: VALIDATION_REASON.OK, key };
}

/**
 * Check if a model is allowed for a key. Tier 'unlimited' or empty
 * allowlist means all models are allowed.
 */
export function isModelAllowedForKey(key, modelId) {
  if (!key) return false;
  if (key.tier === KEY_TIER.UNLIMITED) return true;
  if (!Array.isArray(key.allowedModels) || key.allowedModels.length === 0) return true;
  if (!modelId) return true;
  return key.allowedModels.includes(modelId);
}

/**
 * Check whether a provider connection (or noauth pseudo-id) is allowed for a key.
 *
 * @param {object|null} key - resolved key object (from validateApiKey/getApiKey…)
 * @param {object|string|null} conn - one of:
 *     • a connection row/object: { id, provider, ... }
 *     • a string UUID
 *     • a string "noauth:<provider>"
 * @returns {boolean}
 *
 * Rules:
 *  - tier 'unlimited' (god mode) → always true
 *  - allowlist null/empty       → always true (legacy / no restriction)
 *  - connection object with id  → match against UUIDs in allowlist
 *  - connection object with provider but no id (noAuth virtual) → match "noauth:<provider>"
 *  - bare string                → match as-is
 */
export function isConnectionAllowedForKey(key, conn) {
  if (!key) return false;
  if (key.tier === KEY_TIER.UNLIMITED) return true;
  const allow = Array.isArray(key.allowedConnectionIds) ? key.allowedConnectionIds : null;
  if (!allow || allow.length === 0) return true;

  if (conn == null) return false;

  if (typeof conn === "string") {
    return allow.includes(conn.trim());
  }

  // Object form
  if (conn.id && typeof conn.id === "string" && conn.id !== "noauth") {
    if (allow.includes(conn.id)) return true;
  }
  if (conn.provider && typeof conn.provider === "string") {
    const noauthToken = `noauth:${conn.provider}`;
    if (allow.includes(noauthToken)) return true;
  }
  return false;
}

