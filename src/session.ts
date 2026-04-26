/**
 * PhoenixKey SDK — Session Storage
 *
 * Manages session token (24h) and linked-device token (30d) in localStorage.
 * All reads are SSR-safe — return null on server.
 *
 * Spec §2.3 (session TTL), §6.3 (linked device).
 */

import { SessionMeta, LinkedDevice } from "./types";

const SESSION_KEY = "phoenix_session_token";
const SESSION_META_KEY = "phoenix_session_meta";
const LINKED_DEVICE_KEY = "phoenix_linked_device";

function isBrowser(): boolean {
  return typeof window !== "undefined";
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
export function getSessionToken(): string | null {
  if (!isBrowser()) return null;
  const token = localStorage.getItem(SESSION_KEY);
  if (!token) return null;

  const metaRaw = localStorage.getItem(SESSION_META_KEY);
  if (metaRaw) {
    try {
      const meta = JSON.parse(metaRaw) as SessionMeta;
      if (Date.now() > meta.expiresAt) {
        clearSession();
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
 */
export function setSession(token: string, userDid?: string): void {
  if (!isBrowser()) return;
  const exp = parseJwtExp(token) ?? Date.now() + 24 * 60 * 60 * 1000;
  const meta: SessionMeta = { expiresAt: exp, userDid };
  localStorage.setItem(SESSION_KEY, token);
  localStorage.setItem(SESSION_META_KEY, JSON.stringify(meta));
}

/** Removes session token and metadata. Call on logout. */
export function clearSession(): void {
  if (!isBrowser()) return;
  localStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(SESSION_META_KEY);
}

/** Returns metadata (expiry, DID) without exposing the raw token. */
export function getSessionMeta(): SessionMeta | null {
  if (!isBrowser()) return null;
  const raw = localStorage.getItem(SESSION_META_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SessionMeta;
  } catch {
    return null;
  }
}

/** True if a non-expired session token exists. */
export function isLoggedIn(): boolean {
  return getSessionToken() !== null;
}

// ─── Linked Device Token (spec §6.3) ─────────────────────────────────────────

/**
 * Returns the linked-device token if present and not expired (30d TTL).
 * When present, subsequent logins can skip QR — use `pushLinkedDevice()`
 * instead to send a push notification directly to the user's Aladin app.
 */
export function getLinkedDevice(): LinkedDevice | null {
  if (!isBrowser()) return null;
  const raw = localStorage.getItem(LINKED_DEVICE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as LinkedDevice;
    if (Date.now() > parsed.expiresAt) {
      localStorage.removeItem(LINKED_DEVICE_KEY);
      return null;
    }
    return parsed;
  } catch {
    localStorage.removeItem(LINKED_DEVICE_KEY);
    return null;
  }
}

/**
 * Stores the linked-device token from an approved login session.
 * TTL is read from the JWT `exp` claim, or defaults to 30d.
 *
 * @param token `linked_device_token` from `LoginSessionStatus.approved`
 */
export function setLinkedDevice(token: string): void {
  if (!isBrowser()) return;
  const exp = parseJwtExp(token) ?? Date.now() + 30 * 24 * 60 * 60 * 1000;
  localStorage.setItem(LINKED_DEVICE_KEY, JSON.stringify({ token, expiresAt: exp }));
}

/** Removes the linked-device token. */
export function clearLinkedDevice(): void {
  if (!isBrowser()) return;
  localStorage.removeItem(LINKED_DEVICE_KEY);
}

/** True if a non-expired linked-device token exists (user can skip QR). */
export function hasLinkedDevice(): boolean {
  return getLinkedDevice() !== null;
}

/** Clears all PhoenixKey data from localStorage. */
export function clearAll(): void {
  clearSession();
  clearLinkedDevice();
}