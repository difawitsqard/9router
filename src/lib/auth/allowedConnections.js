import { getProviderConnections } from "@/lib/localDb";
import { AI_PROVIDERS } from "@/shared/constants/providers";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NOAUTH_RE = /^noauth:([a-z0-9_-]+)$/i;

/**
 * Strictly validate an `allowedConnectionIds` payload from API key create/update routes.
 *
 * Accepted shapes:
 * - `null` / `undefined` — no scope (returns `{ ok: true, list: null }`).
 * - `[]` — explicit "scoped to nothing" (returns `{ ok: true, list: [] }`).
 * - `Array<string>` — each entry is either:
 *     - a UUID matching an existing row in `providerConnections`, or
 *     - `noauth:<providerId>` where `<providerId>` is a known noAuth provider in `AI_PROVIDERS`.
 *
 * The list is deduplicated case-insensitively (UUIDs lowercased, noauth providers normalised).
 *
 * @param {unknown} value
 * @returns {Promise<{ ok: true, list: string[]|null } | { ok: false, error: string }>}
 */
export async function validateAllowedConnectionIds(value) {
  if (value == null) return { ok: true, list: null };
  if (!Array.isArray(value)) {
    return { ok: false, error: "allowedConnectionIds must be an array of connection ids or null" };
  }
  if (value.length === 0) return { ok: true, list: [] };

  const conns = await getProviderConnections();
  const validIds = new Set(conns.map((c) => c.id));
  const seen = new Set();
  const out = [];

  for (const raw of value) {
    if (typeof raw !== "string") {
      return { ok: false, error: `allowedConnectionIds entries must be strings, got: ${typeof raw}` };
    }
    const v = raw.trim();

    if (UUID_RE.test(v)) {
      const lc = v.toLowerCase();
      if (seen.has(lc)) continue;
      seen.add(lc);
      if (!validIds.has(v) && !validIds.has(lc)) {
        return { ok: false, error: `Unknown provider connection: ${v}` };
      }
      out.push(v);
      continue;
    }

    const m = v.match(NOAUTH_RE);
    if (m) {
      const providerId = m[1].toLowerCase();
      const token = `noauth:${providerId}`;
      if (seen.has(token)) continue;
      seen.add(token);
      const provider = AI_PROVIDERS[providerId];
      if (!provider || !provider.noAuth) {
        return { ok: false, error: `noauth:${providerId} is not a recognised no-auth provider` };
      }
      out.push(token);
      continue;
    }

    return { ok: false, error: `Invalid allowedConnectionIds entry: ${v}` };
  }

  return { ok: true, list: out };
}
