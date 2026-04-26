/**
 * PhoenixKey SDK — Shared Types
 * Derived from PhoenixKey backend spec §2.3, §6.3, §15.1
 */

// ─── Client Config ────────────────────────────────────────────────────────────

export type PhoenixKeyConfig = {
  /** Your app's API key from api.phoenixkey.me/docs */
  apiKey: string;
  /** Your app's registered ID */
  appId: string;
  /** Display name shown to users in Aladin approval screen */
  appName: string;
  /** @default "https://api.phoenixkey.me" */
  apiBaseUrl?: string;
  /** @default "https://api.phoenixkey.me" */
  sseBaseUrl?: string;
  /** @default "mainnet" */
  environment?: "mainnet" | "testnet";
};

// ─── Auth ─────────────────────────────────────────────────────────────────────

/**
 * Returned by POST /auth/session/init
 * Use `temp_token` to authenticate the SSE stream.
 * Use `session_id` for status polling fallback.
 * Use `challenge` if your app implements WebAuthn directly.
 */
export type LoginSessionInit = {
  session_id: string;
  /** base64url-encoded 32-byte WebAuthn nonce */
  challenge: string;
  /** Unix seconds — QR code validity window */
  expires_at: number;
  /** Short-lived JWT for SSE stream authentication only */
  temp_token: string;
};

export type LoginSessionStatus =
  | { status: "pending" }
  | {
      status: "approved";
      /** Long-lived session token (24h). Store via session.set(). */
      session_token: string;
      /** 30-day token enabling push-to-device on next login */
      linked_device_token?: string;
      /** User's Decentralized Identifier on Cardano */
      user_did?: string;
    }
  | { status: "rejected"; reason?: string }
  | { status: "expired" };

// ─── SSE ──────────────────────────────────────────────────────────────────────

export type SseEvent<T = unknown> = {
  /** Defaults to "message" if server sends plain data */
  type: string;
  data: T;
  id?: string;
};

export type SseHandlers<T = unknown> = {
  onMessage: (evt: SseEvent<T>) => void;
  /** Fired on every reconnect — caller should poll status to catch missed events */
  onReconnect?: () => void;
  onRetry?: (attempt: number, delayMs: number) => void;
  onClose?: () => void;
};

// ─── Session ──────────────────────────────────────────────────────────────────

export type SessionMeta = {
  /** Unix milliseconds */
  expiresAt: number;
  userDid?: string;
};

export type LinkedDevice = {
  token: string;
  /** Unix milliseconds */
  expiresAt: number;
};

// ─── Errors ───────────────────────────────────────────────────────────────────

/**
 * Thrown by all SDK methods on non-2xx or network failure.
 *
 * @example
 * ```ts
 * try {
 *   await client.auth.initSession();
 * } catch (err) {
 *   if (err instanceof PhoenixKeyError && err.status === 401) {
 *     // handle unauthorized
 *   }
 * }
 * ```
 */
export class PhoenixKeyError extends Error {
  /** HTTP status code. 0 = network failure / abort. */
  status: number;
  /** Backend error code e.g. "session_expired", "invalid_api_key" */
  code: string;
  /** i18n-friendly key e.g. "errors.unauthorized" */
  userMessageKey: string;
  details?: unknown;

  constructor(init: {
    status: number;
    code?: string;
    message: string;
    userMessageKey?: string;
    details?: unknown;
  }) {
    super(init.message);
    this.name = "PhoenixKeyError";
    this.status = init.status;
    this.code = init.code ?? "unknown";
    this.userMessageKey = init.userMessageKey ?? defaultUserMessageKey(init.status);
    this.details = init.details;
  }
}

function defaultUserMessageKey(status: number): string {
  if (status === 0) return "errors.network";
  if (status === 401 || status === 403) return "errors.unauthorized";
  if (status === 404) return "errors.not_found";
  if (status === 408 || status === 504) return "errors.timeout";
  if (status === 429) return "errors.rate_limited";
  if (status >= 500) return "errors.server";
  return "errors.generic";
}