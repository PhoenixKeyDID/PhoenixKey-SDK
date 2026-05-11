/**
 * PhoenixKey SDK — Sign Request Module
 *
 * Web ↔ mobile signature relay (spec PhoenixKey_Interface.md §7 + API.md §3).
 *
 * Flow:
 * 1. `create(intent)` — POST /sign/request → {request_id, expires_at}
 * 2. `openStream()`   — SSE listen event "signed" hoặc "cancelled"
 * 3. (mobile signs intent on phone via biometric)
 * 4. SDK nhận event "signed" với {signature, public_key_hex}
 * 5. (Optional) `cancel(request_id)` — Web hủy request đang pending
 *
 * Security note: intent.timestamp validate ±60s server-side, intent.nonce
 * (32B hex) chống replay. Caller sinh nonce qua {@link randomNonce}.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { ResilientSSE, SseOptions } from "./sse";
import {
  SignIntent,
  SignRequestCreate,
  SignRequestPayload,
  SignedEventData,
  CancelledEventData,
  SseHandlers,
} from "./types";

/** SSE event payload shape multiplex giữa "signed" và "cancelled". */
export type SignSseData = SignedEventData | CancelledEventData;

export class SignRequestModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly sseBaseUrl: string,
    private readonly appId: string,
    private readonly domain: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Sinh nonce ngẫu nhiên 32-byte hex — dùng cho `intent.nonce`.
   * Browser dùng `crypto.getRandomValues`, Node dùng `crypto.randomBytes`.
   */
  randomNonce(): string {
    const bytes = new Uint8Array(32);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      crypto.getRandomValues(bytes);
    } else {
      const nodeCrypto = (globalThis as { crypto?: { randomBytes?: (n: number) => Uint8Array } }).crypto;
      if (nodeCrypto?.randomBytes) {
        const buf = nodeCrypto.randomBytes(32);
        for (let i = 0; i < 32; i++) bytes[i] = buf[i];
      } else {
        throw new Error("randomNonce: no secure RNG available");
      }
    }
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Build intent với defaults từ config (app_id, domain, nonce, timestamp).
   * Caller chỉ cần cung cấp `type`, `body`, `display_text`.
   */
  buildIntent(input: {
    type: string;
    body?: Record<string, unknown> | null;
    display_text: string;
    nonce?: string;
    timestamp?: number;
  }): SignIntent {
    return {
      type: input.type,
      body: input.body ?? null,
      domain: this.domain,
      app_id: this.appId,
      nonce: input.nonce ?? this.randomNonce(),
      timestamp: input.timestamp ?? Math.floor(Date.now() / 1000),
      display_text: input.display_text,
    };
  }

  /**
   * Create sign request — Web tạo yêu cầu user ký.
   *
   * Yêu cầu Bearer session_token (từ login flow). Server lưu Redis (TTL 120s),
   * push notification mobile (stub — log only hiện tại).
   *
   * @param sessionId  session_id của user (từ login). Backend emit SSE event
   *                   "signed" về đúng web client qua channel này.
   * @param intent     intent JSON — build qua {@link buildIntent}.
   *
   * @example
   * ```ts
   * const intent = client.signRequest.buildIntent({
   *   type: "TRANSFER",
   *   body: { amount: "100 LAMP", to: "addr1q..." },
   *   display_text: "Transfer 100 LAMP to shop",
   * });
   * const { request_id } = await client.signRequest.create(currentSessionId, intent);
   * ```
   */
  async create(sessionId: string, intent: SignIntent): Promise<SignRequestCreate> {
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token — user must login first");

    return this.fetch<SignRequestCreate>("/sign/request", {
      method: "POST",
      bearerToken: token,
      body: JSON.stringify({
        session_id: sessionId,
        intent,
      }),
    } as FetchOptions);
  }

  /** Get sign request payload (mobile fetch sau push, hoặc web polling fallback). */
  async get(requestId: string): Promise<SignRequestPayload> {
    return this.fetch<SignRequestPayload>(`/sign/request/${requestId}`, {
      method: "GET",
    });
  }

  /**
   * Listen SSE events "signed" + "cancelled" — share channel với
   * /auth/session/{id}/stream qua cùng sessionId.
   *
   * @example
   * ```ts
   * const stream = client.signRequest.openStream(currentSessionId, sessionToken, {
   *   onMessage: ({ type, data }) => {
   *     if (type === "signed" && data.status === "approved") {
   *       const { signature, public_key_hex } = data;
   *       // Forward {intent, signature, public_key_hex} sang app backend → verify
   *     }
   *     if (type === "cancelled") showToast("User cancelled");
   *   },
   * });
   * await stream.connect();
   * ```
   */
  openStream(
    sessionId: string,
    sessionToken: string,
    handlers: SseHandlers<SignSseData>,
    sseOpts?: Partial<SseOptions>,
  ): ResilientSSE<SignSseData> {
    return new ResilientSSE<SignSseData>(
      {
        url: `/auth/session/${sessionId}/stream`,
        token: sessionToken,
        sseBaseUrl: this.sseBaseUrl,
        ...sseOpts,
      },
      handlers,
    );
  }

  /**
   * Cancel sign request pending. Throw 410 nếu request đã approved/cancelled
   * (chống race mobile-approve vs web-cancel).
   */
  async cancel(requestId: string): Promise<void> {
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token");

    await this.fetch<void>(`/sign/${requestId}/cancel`, {
      method: "POST",
      bearerToken: token,
    } as FetchOptions);
  }
}
