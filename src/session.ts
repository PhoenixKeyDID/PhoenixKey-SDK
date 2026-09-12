/**
 * PhoenixKey SDK — Session Storage
 *
 * Manages session token (24h) and linked-device token (30d) in localStorage.
 * All reads are SSR-safe — return null on server.
 *
 * Spec §2.3 (session TTL), §6.3 (linked device).
 *
 * Keys are scoped by `appId` (`<base>:<appId>`) so two `PhoenixKeyClient`
 * instances sharing one browser origin (two platforms on the same domain)
 * don't read/overwrite each other's session — `logout()` on one no longer
 * wipes the other. `appId` is optional here only so this module stays
 * usable standalone; `PhoenixKeyClient` always supplies it (constructor
 * requires `config.appId` — see client.ts). Omitting it does NOT fall back
 * to the old shared key: it lands in the `DEFAULT_SCOPE` bucket, so an
 * unsuffixed key in storage is always pre-upgrade data and nothing else.
 *
 * Upgrading from an unscoped version costs one re-login, because a legacy
 * blob carries no record of which app wrote it — adopting it into a scope
 * would be a coin flip that hands app A the session app B left behind,
 * which is the very bug being fixed. `purgeLegacy()` therefore deletes
 * those keys rather than migrating them; the client calls it on
 * construction so a live 24h session token and a 30d linked-device token
 * don't sit in `localStorage` forever with nothing left to clear them.
 */

import { SessionMeta, LinkedDevice } from "./types";

const SESSION_KEY = "phoenix_session_token";
const SESSION_META_KEY = "phoenix_session_meta";
const LINKED_DEVICE_KEY = "phoenix_linked_device";

function isBrowser(): boolean {
  return typeof window !== "undefined";
}

/**
 * Bucket used when a caller drives this module directly without an `appId`.
 * It is a real scope, not the bare base key — see the note on legacy keys in
 * the module docblock. A client whose `appId` is literally `"default"` shares
 * this bucket; on one origin that is the same app either way.
 */
const DEFAULT_SCOPE = "default";

/** The three unsuffixed keys written by SDK versions before scoping. */
const LEGACY_KEYS: readonly string[] = [
  SESSION_KEY,
  SESSION_META_KEY,
  LINKED_DEVICE_KEY,
];

function scopedKey(base: string, appId?: string): string {
  return `${base}:${appId || DEFAULT_SCOPE}`;
}

/**
 * Deletes the pre-scoping keys. Idempotent, SSR-safe, and called once per
 * `PhoenixKeyClient` construction — the tokens they hold are still live, and
 * after the upgrade no code path reads or clears them any more.
 */
export function purgeLegacy(): void {
  if (!isBrowser()) return;
  for (const key of LEGACY_KEYS) localStorage.removeItem(key);
}

function parseJwtExp(token: string): number | null {
  try {
    const [, payload] = token.split(".");
    if (!payload) return null;
    const decoded = JSON.parse(
      atob(payload.replace(/-/g, "+").replace(/_/g, "/")),
    );
    return typeof decoded.exp === "number" ? decoded.exp * 1000 : null;
  } catch {
    return null;
  }
}

// ─── Session Token ────────────────────────────────────────────────────────────

/**
 * Returns the stored session token if present and not expired.
 * Returns `null` on server (SSR-safe).
 */
export function getSessionToken(appId?: string): string | null {
  if (!isBrowser()) return null;
  const token = localStorage.getItem(scopedKey(SESSION_KEY, appId));
  if (!token) return null;

  const metaRaw = localStorage.getItem(scopedKey(SESSION_META_KEY, appId));
  if (metaRaw) {
    try {
      const meta = JSON.parse(metaRaw) as SessionMeta;
      if (Date.now() > meta.expiresAt) {
        clearSession(appId);
        return null;
      }
    } catch {
      /* corrupt meta — let server reject */
    }
  }
  return token;
}

/**
 * Stores the session token returned by the approved login flow.
 * TTL is read from the JWT `exp` claim, or defaults to 24h.
 *
 * @param token   `session_token` from `LoginSessionStatus.approved`
 * @param userDid `user_did` from `LoginSessionStatus.approved`
 * @param appId   scopes the storage key — always passed by `PhoenixKeyClient`
 */
export function setSession(token: string, userDid?: string, appId?: string): void {
  if (!isBrowser()) return;
  const exp = parseJwtExp(token) ?? Date.now() + 24 * 60 * 60 * 1000;
  const meta: SessionMeta = { expiresAt: exp, userDid };
  localStorage.setItem(scopedKey(SESSION_KEY, appId), token);
  localStorage.setItem(scopedKey(SESSION_META_KEY, appId), JSON.stringify(meta));
}

/** Removes session token and metadata. Call on logout. */
export function clearSession(appId?: string): void {
  if (!isBrowser()) return;
  localStorage.removeItem(scopedKey(SESSION_KEY, appId));
  localStorage.removeItem(scopedKey(SESSION_META_KEY, appId));
}

/** Returns metadata (expiry, DID) without exposing the raw token. */
export function getSessionMeta(appId?: string): SessionMeta | null {
  if (!isBrowser()) return null;
  const raw = localStorage.getItem(scopedKey(SESSION_META_KEY, appId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SessionMeta;
  } catch {
    return null;
  }
}

/** True if a non-expired session token exists. */
export function isLoggedIn(appId?: string): boolean {
  return getSessionToken(appId) !== null;
}

// ─── Linked Device Token (spec §6.3) ─────────────────────────────────────────

/**
 * Returns the linked-device token if present and not expired (30d TTL).
 * When present, subsequent logins can skip QR — use `pushLinkedDevice()`
 * instead to send a push notification directly to the user's Aladin app.
 */
export function getLinkedDevice(appId?: string): LinkedDevice | null {
  if (!isBrowser()) return null;
  const key = scopedKey(LINKED_DEVICE_KEY, appId);
  const raw = localStorage.getItem(key);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as LinkedDevice;
    if (Date.now() > parsed.expiresAt) {
      localStorage.removeItem(key);
      return null;
    }
    return parsed;
  } catch {
    localStorage.removeItem(key);
    return null;
  }
}

/**
 * Stores the linked-device token from an approved login session.
 * TTL is read from the JWT `exp` claim, or defaults to 30d.
 *
 * @param token `linked_device_token` from `LoginSessionStatus.approved`
 * @param appId scopes the storage key — always passed by `PhoenixKeyClient`
 */
export function setLinkedDevice(token: string, appId?: string): void {
  if (!isBrowser()) return;
  const exp = parseJwtExp(token) ?? Date.now() + 30 * 24 * 60 * 60 * 1000;
  localStorage.setItem(
    scopedKey(LINKED_DEVICE_KEY, appId),
    JSON.stringify({ token, expiresAt: exp }),
  );
}

/** Removes the linked-device token. */
export function clearLinkedDevice(appId?: string): void {
  if (!isBrowser()) return;
  localStorage.removeItem(scopedKey(LINKED_DEVICE_KEY, appId));
}

/** True if a non-expired linked-device token exists (user can skip QR). */
export function hasLinkedDevice(appId?: string): boolean {
  return getLinkedDevice(appId) !== null;
}

/** Clears all PhoenixKey data from localStorage — scoped to this appId only. */
export function clearAll(appId?: string): void {
  clearSession(appId);
  clearLinkedDevice(appId);
}
