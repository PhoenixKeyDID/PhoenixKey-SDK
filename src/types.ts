/**
 * PhoenixKey SDK — Shared Types
 *
 * Derived from PhoenixKey backend spec (PhoenixKey_Interface.md v1.4.3) +
 * API.md from PhoenixKey-Database. All field names follow snake_case to
 * match backend Jackson convention.
 */

// ─── Client Config ────────────────────────────────────────────────────────────

export type PhoenixKeyConfig = {
  /**
   * Your app's identifier — sent in `intent.app_id` for sign requests.
   * Should be unique within the Aladin ecosystem (vd: "orilife-web-v1").
   */
  appId: string;

  /**
   * Display name shown to users in mobile (Aladin app) approval screen.
   * Vd: "OriLife", "AladinWork".
   */
  appName: string;

  /**
   * Domain bound to authentication challenge (anti cross-domain replay).
   * Mobile sẽ hiển thị domain này khi yêu cầu user approve — phải khớp
   * với domain thực tế web đang chạy. Vd: "orilife.com", "phoenixkey.me".
   */
  domain: string;

  /** @default "https://api.phoenixkey.me" */
  apiBaseUrl?: string;

  /** @default same as apiBaseUrl */
  sseBaseUrl?: string;

  /** @default "mainnet". Cardano network — match với backend deploy. */
  environment?: "mainnet" | "preprod";

  /**
   * @optional Reserved for Phase 4 client registration.
   * Currently ignored — backend chưa implement API key auth.
   */
  apiKey?: string;
};

// ─── Auth ─────────────────────────────────────────────────────────────────────

/**
 * Returned by POST /auth/session/init.
 *
 * - `temp_token`: short-lived JWT (5 phút) cho SSE stream + status fallback
 * - `session_id`: UUIDv7 — đặt vào QR payload + dùng cho status polling
 * - `challenge`: 32-byte hex random — mobile ký `challenge:domain:timestamp`
 * - `expires_at`: epoch seconds — QR validity window
 */
export type LoginSessionInit = {
  session_id: string;
  challenge: string;
  expires_at: number;
  temp_token: string;
};

/**
 * Returned by GET /auth/session/{id}/status + emitted via SSE event "approved".
 *
 * Khi status = "approved": kèm session_token, linked_device_token, user_did,
 * signature, signed_timestamp (cho 3rd-party verify locally — Phase 3 verifier).
 */
export type LoginSessionStatus = {
  session_id: string;
  status: "pending" | "approved" | "rejected" | "expired";
  /** Long-lived session token (24h). Có khi status="approved". */
  session_token?: string;
  /** 30-day token cho push-to-device flow lần sau. */
  linked_device_token?: string;
  /** User's DID trên Cardano: `did:cardano:<network>:<txHash>`. */
  user_did?: string;
};

/**
 * QR payload (spec PhoenixKey_Interface.md §6.3 line 517-528).
 *
 * Web SDK build payload này từ `LoginSessionInit` + config.domain, encode
 * base64url, render thành QR image. Mobile (Aladin app) scan → base64url
 * decode → JSON.parse → fields:
 *
 * - `v`: schema version, hiện = 1
 * - `sid`: session_id từ /init
 * - `ch`: challenge từ /init
 * - `dom`: domain (orilife.com, phoenixkey.me, ...) — hiển thị cho user thấy
 * - `exp`: expires_at từ /init
 */
export type QrPayload = {
  v: 1;
  sid: string;
  ch: string;
  dom: string;
  exp: number;
};

// ─── Sign Request ─────────────────────────────────────────────────────────────

/**
 * PhoenixKey Signing Standard intent (spec §7.3 + API.md §3).
 *
 * Hiển thị trên mobile cho user xem trước khi ký — chống "blind signing".
 * Canonical form: keys sorted alphabetically, no whitespace.
 *
 * @example
 * ```ts
 * {
 *   type: "TRANSFER",
 *   body: { amount: "100 LAMP", to: "addr1q..." },
 *   domain: "orilife.com",
 *   app_id: "orilife-web-v1",
 *   nonce: "...",  // 32-byte hex random, dùng 1 lần
 *   timestamp: 1714201200,  // epoch seconds
 *   display_text: "Transfer 100 LAMP to shop"
 * }
 * ```
 */
export type SignIntent = {
  /** Intent type: TRANSFER | SEED_EXPORT | KEY_ROTATE | AUTH_PROOF | CUSTOM */
  type: string;
  /** Payload chi tiết — type-specific shape, dynamic. */
  body?: Record<string, unknown> | null;
  domain: string;
  app_id?: string;
  /** 32-byte hex random — replay protection. */
  nonce: string;
  /** Epoch seconds. Server validate ±60s skew khi mobile approve. */
  timestamp: number;
  /** Human-readable summary cho mobile UI. Anti blind-signing. */
  display_text: string;
};

/** Returned by POST /sign/request. */
export type SignRequestCreate = {
  request_id: string;
  expires_at: number;
};

/** Returned by GET /sign/request/{id} (mobile fetch + web polling). */
export type SignRequestPayload = {
  request_id: string;
  user_did: string;
  session_id: string;
  intent: SignIntent;
  status: "pending" | "approved" | "cancelled" | "expired";
  expires_at: number;
};

/** SSE event "signed" payload — emit từ backend khi mobile approve. */
export type SignedEventData = {
  status: "approved";
  request_id: string;
  signature: string;
  public_key_hex: string;
};

/** SSE event "cancelled" payload. */
export type CancelledEventData = {
  status: "cancelled";
  request_id: string;
};

// ─── Identity ─────────────────────────────────────────────────────────────────

export type IdentityRegisterRequest = {
  public_key_hex: string;
  key_origin: "SECURE_ENCLAVE" | "IMPORTED_BIP39" | "DERIVED_CHILD";
  key_role: "owner" | "manager" | "viewer";
  added_by_signature: string;
};

export type IdentityRegisterResponse = {
  user_id: string;
  user_did: string;
  tx_hash: string;
};

export type IdentityPubkey = {
  public_key_hex: string;
  key_role: string;
};

export type IdentityStatus = {
  status: "ACTIVE" | "RECOVERING" | "MIGRATED";
  current_controller_pkh: string;
  sequence: number;
  recovery_deadline?: string | null;
};

export type IdentityHealth = {
  seed_exported: boolean;
  exported_at: string | null;
  active_key_count: number;
  guardian_count: number;
};

/**
 * W3C DID Core Document — ngoại lệ camelCase (W3C spec compliance).
 * Trả về từ GET /identity/{did}/document — đọc từ Cardano inline datum.
 */
export type W3CDIDDocument = {
  "@context": string[];
  id: string;
  controller: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyHex: string;
  }>;
  authentication: string[];
  assertionMethod: string[];
  capabilityInvocation: string[];
  created?: string;
  updated?: string | null;
};

// ─── Activity Logs ────────────────────────────────────────────────────────────

export type ActivityLogItem = {
  id: string;
  user_id: string | null;
  action: string;
  metadata: Record<string, unknown> | null;
  created_at: string;
};

export type ActivityLogPage = {
  logs: ActivityLogItem[];
  next_cursor: string | null;
};

export type ActivityLogQuery = {
  /** 1-100, default 20 */
  limit?: number;
  /** UUID id của item cuối trang trước */
  cursor?: string;
  /** action name (vd "sign_request_approved") */
  filter?: string;
  /** "7d" | "30d" | "all" — default "all" */
  range?: "7d" | "30d" | "all";
};

// ─── Misc ─────────────────────────────────────────────────────────────────────

export type FeeEstimate = {
  type: string;
  magic: number;
  unit: "MAGIC";
};

export type LampNetNode = {
  code: string;
  city: string;
  lat: number;
  lng: number;
  status: "active" | "degraded" | "offline";
};

export type LampNetNodes = {
  nodes: LampNetNode[];
  total: number;
};

export type SupportSession = {
  session_id: string;
  proofchat_url: string;
  note?: string;
};

// ─── SSE ──────────────────────────────────────────────────────────────────────

export type SseEvent<T = unknown> = {
  /** Event name. Defaults to "message" if server sends plain data. */
  type: string;
  data: T;
  id?: string;
};

export type SseHandlers<T = unknown> = {
  onMessage: (evt: SseEvent<T>) => void;
  /** Fired on every reconnect — caller should poll status to catch missed events. */
  onReconnect?: () => void;
  onRetry?: (attempt: number, delayMs: number) => void;
  onClose?: () => void;
};

// ─── Session Storage ──────────────────────────────────────────────────────────

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
 *   if (err instanceof PhoenixKeyError && err.code === "session_expired") {
 *     // handle session expired
 *   }
 * }
 * ```
 */
export class PhoenixKeyError extends Error {
  /** HTTP status code. 0 = network failure / abort. */
  status: number;
  /** Error code (mapped string từ backend integer code). */
  code: string;
  /** Backend integer code (1301, 1302, ...) — debug only, prefer `code`. */
  rawCode?: number;
  /** i18n-friendly key e.g. "errors.unauthorized" */
  userMessageKey: string;
  details?: unknown;

  constructor(init: {
    status: number;
    code?: string;
    rawCode?: number;
    message: string;
    userMessageKey?: string;
    details?: unknown;
  }) {
    super(init.message);
    this.name = "PhoenixKeyError";
    this.status = init.status;
    this.code = init.code ?? "unknown";
    this.rawCode = init.rawCode;
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
