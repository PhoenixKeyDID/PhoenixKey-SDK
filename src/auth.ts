/**
 * PhoenixKey SDK — Auth Module
 *
 * QR-pairing login flow (spec PhoenixKey_Interface.md §6 + API.md §2):
 *
 * 1. `initSession()`      — POST /auth/session/init → {session_id, challenge, temp_token, expires_at}
 * 2. `buildQrPayload()`   — encode QR JSON theo spec §6.3 (base64url)
 * 3. `openStream()`       — SSE stream với temp_token (primary)
 * 4. `getStatus()`        — GET /auth/session/{id}/status (fallback)
 * 5. `pushLinkedDevice()` — POST /auth/session/push (skip QR khi đã linked device)
 *
 * Spec §15.1 (SSE), §15.2 (replay protection)
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { ResilientSSE, SseOptions } from "./sse";
import {
  LoginSessionInit,
  LoginSessionStatus,
  QrPayload,
  SseHandlers,
  LinkedDevice,
} from "./types";

/** base64url encode (browser + Node fallback). */
function base64UrlEncode(input: string): string {
  let b64: string;
  if (typeof btoa === "function") {
    b64 = btoa(input);
  } else {
    // Node fallback — globalThis.Buffer (avoid hard @types/node dep)
    const NodeBuffer = (globalThis as { Buffer?: { from(s: string, enc: string): { toString(enc: string): string } } }).Buffer;
    if (!NodeBuffer) {
      throw new Error("base64UrlEncode: no btoa or Buffer available");
    }
    b64 = NodeBuffer.from(input, "utf8").toString("base64");
  }
  return b64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export class AuthModule {
  private readonly fetch: ReturnType<typeof createFetcher>;
  private readonly sseBaseUrl: string;
  private readonly domain: string;

  constructor(
    baseUrl: string,
    sseBaseUrl: string,
    domain: string,
    private readonly _getLinkedDevice: () => LinkedDevice | null,
  ) {
    this.fetch = createFetcher(baseUrl);
    this.sseBaseUrl = sseBaseUrl;
    this.domain = domain;
  }

  /**
   * Step 1 — Bootstrap a login session.
   *
   * Backend tạo session_id (UUIDv7) + challenge 32B hex + temp_token JWT (5min)
   * và lưu vào Redis với status=pending.
   *
   * @example
   * ```ts
   * const init = await client.auth.initSession();
   * const qrPayload = client.auth.buildQrPayload(init);
   * renderQR(qrPayload);  // dùng `qrcode` library hoặc tương đương
   * ```
   */
  async initSession(): Promise<LoginSessionInit> {
    return this.fetch<LoginSessionInit>("/auth/session/init", {
      method: "POST",
    });
  }

  /**
   * Build QR payload theo spec PhoenixKey_Interface.md §6.3.
   *
   * Schema: `{ v: 1, sid, ch, dom, exp }` → base64url encode JSON.
   *
   * Mobile (Aladin app) scan QR → base64url decode → JSON.parse → đọc fields.
   * Domain trong QR là binding cho signature — mobile sẽ hiển thị domain này
   * cho user thấy trong màn approve, anti phishing.
   *
   * @param init  từ {@link initSession}
   * @param domain  override default `config.domain` (hiếm khi cần)
   *
   * @example
   * ```ts
   * import QRCode from 'qrcode';
   *
   * const init = await client.auth.initSession();
   * const qrPayload = client.auth.buildQrPayload(init);
   * await QRCode.toCanvas(canvasEl, qrPayload, { width: 256 });
   * ```
   */
  buildQrPayload(init: LoginSessionInit, domain?: string): string {
    const payload: QrPayload = {
      v: 1,
      sid: init.session_id,
      ch: init.challenge,
      dom: domain ?? this.domain,
      exp: init.expires_at,
    };
    return base64UrlEncode(JSON.stringify(payload));
  }

  /**
   * Step 2 (primary) — Open SSE stream để nhận event "approved".
   *
   * Khi `onMessage` fire với `data.status === "approved"`:
   * - `data.session_token` → 24h JWT, gọi `client.session.setSession(token, did)` để persist
   * - `data.linked_device_token` → 30d JWT, optional, persist qua `setLinkedDevice()`
   * - `data.user_did` → DID của user
   *
   * Mỗi reconnect, `onReconnect` fire — caller nên gọi `getStatus()` ở đó để
   * catch missed events trong lúc disconnect.
   *
   * @param sessionId  từ initSession().session_id
   * @param tempToken  từ initSession().temp_token (Bearer cho SSE)
   *
   * @example
   * ```ts
   * const stream = client.auth.openStream(init.session_id, init.temp_token, {
   *   onMessage: ({ type, data }) => {
   *     if (type === "approved" && data.status === "approved") {
   *       client.session.setSession(data.session_token!, data.user_did);
   *       if (data.linked_device_token) {
   *         client.session.setLinkedDevice(data.linked_device_token);
   *       }
   *       stream.close();
   *       router.push("/dashboard");
   *     }
   *   },
   *   onReconnect: async () => {
   *     const status = await client.auth.getStatus(init.session_id, init.temp_token);
   *     if (status.status === "approved") {
   *       // resync state
   *     }
   *   },
   * });
   * await stream.connect();
   * ```
   */
  openStream(
    sessionId: string,
    tempToken: string,
    handlers: SseHandlers<LoginSessionStatus>,
    sseOpts?: Partial<SseOptions>,
  ): ResilientSSE<LoginSessionStatus> {
    return new ResilientSSE<LoginSessionStatus>(
      {
        url: `/auth/session/${sessionId}/stream`,
        token: tempToken,
        sseBaseUrl: this.sseBaseUrl,
        ...sseOpts,
      },
      handlers,
    );
  }

  /**
   * Step 2 (fallback) — Poll session status once.
   *
   * Use cases:
   * - Trong `onReconnect` để catch missed SSE events
   * - Environment không hỗ trợ SSE (vd: một số proxies cũ)
   *
   * @example
   * ```ts
   * // Polling loop (prefer SSE)
   * const poll = setInterval(async () => {
   *   const status = await client.auth.getStatus(init.session_id, init.temp_token);
   *   if (status.status === "approved") {
   *     clearInterval(poll);
   *     client.session.setSession(status.session_token!, status.user_did);
   *   } else if (status.status === "expired" || status.status === "rejected") {
   *     clearInterval(poll);
   *   }
   * }, 2000);
   * ```
   */
  async getStatus(
    sessionId: string,
    tempToken: string,
  ): Promise<LoginSessionStatus> {
    return this.fetch<LoginSessionStatus>(`/auth/session/${sessionId}/status`, {
      method: "GET",
      bearerToken: tempToken,
    } as FetchOptions);
  }

  /**
   * Step 2 (return visits) — Push notification tới mobile thay vì hiện QR.
   *
   * Yêu cầu: user đã từng login + linked_device_token đã save (qua
   * `client.session.setLinkedDevice()` trước đó). Flow:
   *
   * 1. Caller gọi `initSession()` để có session_id mới
   * 2. Gọi `pushLinkedDevice(session_id)` — backend gửi push tới mobile
   * 3. Mobile nhận push, mở app, biometric → ký challenge
   * 4. SDK SSE nhận event approved như flow QR thường
   *
   * **⚠ Production**: backend hiện dùng `PushServiceStub` (log only, chưa wire
   * FCM/APNs). Caller nên có fallback hiển thị QR nếu push timeout 5-10s.
   *
   * @example
   * ```ts
   * const init = await client.auth.initSession();
   * const stream = client.auth.openStream(init.session_id, init.temp_token, handlers);
   * await stream.connect();
   *
   * if (client.session.hasLinkedDevice()) {
   *   await client.auth.pushLinkedDevice(init.session_id);
   *   showWaiting('Check your phone for notification...');
   *   setTimeout(() => showQrFallback(client.auth.buildQrPayload(init)), 8000);
   * } else {
   *   showQr(client.auth.buildQrPayload(init));
   * }
   * ```
   */
  async pushLinkedDevice(sessionId: string): Promise<void> {
    const device = this._getLinkedDevice();
    if (!device) {
      throw new Error("No linked device — call setLinkedDevice() first or show QR");
    }
    await this.fetch<void>("/auth/session/push", {
      method: "POST",
      body: JSON.stringify({
        session_id: sessionId,
        linked_device_token: device.token,
      }),
    } as FetchOptions);
  }
}
