import { extractApiKey } from "./auth.js";
import { validateApiKey, isModelAllowedForKey, isConnectionAllowedForKey, KEY_TIER, VALIDATION_REASON } from "@/lib/localDb";
import { getSettings } from "@/lib/localDb";
import { errorResponse } from "open-sse/utils/error.js";
import { HTTP_STATUS } from "open-sse/config/runtimeConfig.js";
import * as log from "../utils/logger.js";

/**
 * Enforce API key policy at request gate.
 *
 * Behavior:
 *  - If global setting requireApiKey = false → bypass all checks (legacy behavior).
 *  - If key is missing → 401.
 *  - If key invalid/inactive → 401.
 *  - If key expired → 401 (key_expired).
 *  - If key quota exceeded → 429 (quota_exceeded).
 *  - If model is provided and not in key's allowlist → 403 (model_not_allowed).
 *  - Tier 'unlimited' (god mode) bypasses expiry/quota/allowlist checks.
 *
 * @param {Request} request
 * @param {object} [options]
 * @param {string|string[]|null} [options.model] - Model id(s) the request will hit. Optional.
 *   For combo requests, pass the array of expanded models so all are validated.
 * @param {string} [options.label='AUTH'] - Log label.
 * @returns {Promise<{
 *   ok: boolean,
 *   apiKey: string|null,
 *   keyContext: object|null,
 *   bypass: boolean,
 *   response?: Response,
 * }>}
 */
export async function enforceApiKeyPolicy(request, options = {}) {
  const { model = null, label = "AUTH" } = options;
  const apiKey = extractApiKey(request);

  if (apiKey) {
    log.debug(label, `API Key: ${log.maskKey(apiKey)}`);
  } else {
    log.debug(label, "No API key provided (local mode)");
  }

  const settings = await getSettings();

  // Global bypass — preserves legacy behavior when key gating is off.
  if (!settings.requireApiKey) {
    return { ok: true, apiKey, keyContext: null, bypass: true };
  }

  if (!apiKey) {
    log.warn(label, "Missing API key (requireApiKey=true)");
    return {
      ok: false,
      apiKey: null,
      keyContext: null,
      bypass: false,
      response: errorResponse(HTTP_STATUS.UNAUTHORIZED, "Missing API key"),
    };
  }

  const result = await validateApiKey(apiKey);

  if (!result.valid) {
    const keyId = result.key?.id ? result.key.id.slice(0, 8) : "unknown";
    switch (result.reason) {
      case VALIDATION_REASON.NOT_FOUND:
        log.warn(label, `Invalid API key (not found)`);
        return {
          ok: false, apiKey, keyContext: null, bypass: false,
          response: errorResponse(HTTP_STATUS.UNAUTHORIZED, "Invalid API key"),
        };
      case VALIDATION_REASON.INACTIVE:
        log.warn(label, `Key paused (id=${keyId})`);
        return {
          ok: false, apiKey, keyContext: result.key, bypass: false,
          response: errorResponse(HTTP_STATUS.UNAUTHORIZED, "API key is inactive"),
        };
      case VALIDATION_REASON.EXPIRED:
        log.warn(label, `Key expired (id=${keyId}, expiresAt=${result.key?.expiresAt})`);
        return {
          ok: false, apiKey, keyContext: result.key, bypass: false,
          response: errorResponse(HTTP_STATUS.UNAUTHORIZED, "API key has expired"),
        };
      case VALIDATION_REASON.QUOTA_EXCEEDED:
        log.warn(label, `Key quota exceeded (id=${keyId}, used=${result.key?.tokenUsed}/${result.key?.tokenLimit})`);
        return {
          ok: false, apiKey, keyContext: result.key, bypass: false,
          response: errorResponse(
            HTTP_STATUS.RATE_LIMITED,
            `API key quota exceeded (${result.key?.tokenUsed}/${result.key?.tokenLimit} tokens)`
          ),
        };
      default:
        log.warn(label, `API key rejected (reason=${result.reason})`);
        return {
          ok: false, apiKey, keyContext: result.key || null, bypass: false,
          response: errorResponse(HTTP_STATUS.UNAUTHORIZED, "Invalid API key"),
        };
    }
  }

  // Model allowlist check (only for restricted tier with non-empty allowlist).
  if (model && result.key?.tier === KEY_TIER.RESTRICTED) {
    const models = Array.isArray(model) ? model : [model];
    for (const m of models) {
      if (!isModelAllowedForKey(result.key, m)) {
        log.warn(label, `Model not allowed for key (id=${result.key.id?.slice(0, 8)}, model=${m})`);
        return {
          ok: false, apiKey, keyContext: result.key, bypass: false,
          response: errorResponse(
            HTTP_STATUS.FORBIDDEN,
            `Model '${m}' is not allowed for this API key`
          ),
        };
      }
    }
  }

  return { ok: true, apiKey, keyContext: result.key, bypass: false };
}

/**
 * Lightweight variant for endpoints that need the key context but cannot reject
 * (e.g. /v1/models which is a list view). Returns context if key is valid,
 * or null if missing/invalid/bypassed. Never throws or returns a Response.
 */
export async function resolveApiKeyContext(request) {
  const apiKey = extractApiKey(request);
  const settings = await getSettings();
  if (!settings.requireApiKey) return { apiKey, keyContext: null, bypass: true };
  if (!apiKey) return { apiKey: null, keyContext: null, bypass: false };
  const result = await validateApiKey(apiKey);
  return {
    apiKey,
    keyContext: result.valid ? result.key : null,
    bypass: false,
  };
}

/**
 * Assert that all given models are in the key's allowlist. Used after combo
 * expansion when the model set is only known post-auth. No-op for null keyContext
 * (bypass mode) or 'unlimited' tier.
 *
 * @param {object|null} keyContext - From enforceApiKeyPolicy result.
 * @param {string|string[]} models
 * @param {string} [label='AUTH']
 * @returns {Response|null} Response if rejected, null if allowed.
 */
export function assertModelAllowed(keyContext, models, label = "AUTH") {
  if (!keyContext) return null; // bypass mode or no enforcement
  if (keyContext.tier !== KEY_TIER.RESTRICTED) return null;
  if (!Array.isArray(keyContext.allowedModels) || keyContext.allowedModels.length === 0) return null;

  const list = Array.isArray(models) ? models : [models];
  for (const m of list) {
    if (!m) continue;
    if (!isModelAllowedForKey(keyContext, m)) {
      log.warn(label, `Model not allowed for key (id=${keyContext.id?.slice(0, 8)}, model=${m})`);
      return errorResponse(
        HTTP_STATUS.FORBIDDEN,
        `Model '${m}' is not allowed for this API key`
      );
    }
  }
  return null;
}

/**
 * Resolve the effective account allowlist for a key as a Set, ready to pass
 * into `getProviderCredentials({ allowedConnectionIds })`.
 *
 * Returns null when no restriction should be applied (bypass / unlimited /
 * empty allowlist) so the picker can short-circuit.
 *
 * @param {object|null} keyContext
 * @returns {Set<string>|null}
 */
export function resolveAllowedConnectionSet(keyContext) {
  if (!keyContext) return null;
  if (keyContext.tier !== KEY_TIER.RESTRICTED) return null;
  const list = Array.isArray(keyContext.allowedConnectionIds) ? keyContext.allowedConnectionIds : null;
  if (!list || list.length === 0) return null;
  return new Set(list);
}

/**
 * Defense-in-depth: assert a chosen connection is allowed for the key.
 * Useful when the picker is bypassed (preferred id, or a free/no-auth path).
 *
 * @param {object|null} keyContext
 * @param {object|string|null} conn - connection object {id, provider} or string token
 * @param {string} [label='AUTH']
 * @returns {Response|null}
 */
export function assertAccountAllowed(keyContext, conn, label = "AUTH") {
  if (!keyContext) return null;
  if (keyContext.tier !== KEY_TIER.RESTRICTED) return null;
  if (!Array.isArray(keyContext.allowedConnectionIds) || keyContext.allowedConnectionIds.length === 0) return null;
  if (isConnectionAllowedForKey(keyContext, conn)) return null;

  const label2 = typeof conn === "object" && conn?.provider
    ? `${conn.provider}/${conn.id ? conn.id.slice(0, 8) : "noauth"}`
    : String(conn);
  log.warn(label, `Account not allowed for key (id=${keyContext.id?.slice(0, 8)}, account=${label2})`);
  return errorResponse(
    HTTP_STATUS.FORBIDDEN,
    `Account '${label2}' is not allowed for this API key`
  );
}
