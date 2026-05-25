/**
 * Branding helpers — single source of truth for the user-facing product name,
 * short name, and description. Values come from environment variables so
 * operators can rebrand the dashboard without forking the code.
 *
 * IMPORTANT: These helpers only affect *display* text. Internal identifiers
 * such as the data directory (`~/.9router`), default API key (`sk_9router`),
 * downstream tool config keys (`provider["9router"]`), and the GitHub URL
 * are intentionally left as fixed identifiers — changing those breaks
 * existing user installations and CLI tool integrations.
 *
 * Supported env vars (all optional):
 *   NEXT_PUBLIC_APP_NAME         — full product name, default "9Router"
 *   NEXT_PUBLIC_APP_SHORT_NAME   — short name (manifest, tab title), default = APP_NAME
 *   NEXT_PUBLIC_APP_TAGLINE      — tagline used in <title>, default existing
 *   NEXT_PUBLIC_APP_DESCRIPTION  — description used in metadata, default existing
 *
 * IMPLEMENTATION NOTE — DO NOT use dynamic `process.env[key]` here. Next.js /
 * webpack inlines NEXT_PUBLIC_* vars into the client bundle ONLY when they are
 * accessed as static property names (e.g. `process.env.NEXT_PUBLIC_APP_NAME`).
 * Dynamic access produces `undefined` on the client → SSR/CSR hydration drift.
 */

const DEFAULT_NAME = "9Router";
const DEFAULT_TAGLINE = "AI Infrastructure Management";
const DEFAULT_DESCRIPTION =
  "One endpoint for all your AI providers. Manage keys, monitor usage, and scale effortlessly.";

// Static reads — these get inlined into the client bundle at build time.
// Trim & coerce to string so non-string values (rare) don't break rendering.
function pick(value, fallback) {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  return trimmed ? trimmed : fallback;
}

const APP_NAME = pick(process.env.NEXT_PUBLIC_APP_NAME, DEFAULT_NAME);
const APP_SHORT_NAME = pick(process.env.NEXT_PUBLIC_APP_SHORT_NAME, APP_NAME);
const APP_TAGLINE = pick(process.env.NEXT_PUBLIC_APP_TAGLINE, DEFAULT_TAGLINE);
const APP_DESCRIPTION = pick(process.env.NEXT_PUBLIC_APP_DESCRIPTION, DEFAULT_DESCRIPTION);

export function getBrandName() {
  return APP_NAME;
}

export function getBrandShortName() {
  return APP_SHORT_NAME;
}

export function getBrandTagline() {
  return APP_TAGLINE;
}

export function getBrandDescription() {
  return APP_DESCRIPTION;
}

/** "9Router - AI Infrastructure Management" — used as <title> and manifest name. */
export function getBrandFullTitle() {
  return APP_TAGLINE ? `${APP_NAME} - ${APP_TAGLINE}` : APP_NAME;
}
