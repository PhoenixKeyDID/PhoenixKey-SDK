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
 * Và một bước RIÊNG, sau khi đã đăng nhập:
 *
 * 6. `exchange()`         — POST /auth/token/exchange: đổi thẻ phiên rộng lấy
 *                           thẻ app hẹp cho một app đích.
 *
 * Spec §15.1 (SSE), §15.2 (replay protection)
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { ResilientSSE, SseOptions } from "./sse";
import {
  LoginSessionInit,
  LoginSessionStatus,
  PhoenixKeyError,
  QrPayload,
  SseHandlers,
  LinkedDevice,
  TokenExchangeParams,
  TokenExchangeResponse,
  TokenExchangeResult,
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

  /**
   * Step 3 — Đổi **thẻ phiên** lấy **thẻ app** cho một app đích.
   *
   * ## Vì sao phải đổi, thay vì đưa thẳng thẻ phiên
   *
   * `session_token` là thẻ TOÀN QUYỀN của người dùng, sống 24 giờ
   * (`PHOENIXKEY_SESSION_TTL_SECONDS`, mặc định 86400): nó mở mọi endpoint của
   * người đó — đọc ví, tạo yêu cầu ký, thu hồi thiết bị. Đưa nó cho một app
   * đối tác là trao trọn tài khoản trong một ngày, không thu lại được.
   *
   * `app_token` do lượt đổi này cấp bị ràng vào **đúng một `aud`** (ServiceDID
   * của app đích) và sống ngắn (15 phút mặc định). App nhận được nó không dùng
   * nó ở nơi khác được, và nó tự chết rất nhanh.
   *
   * ## Thẻ app là thẻ mang-là-dùng (bearer), chưa ràng vào khoá
   *
   * `app_token` hiện **không** có ràng buộc sở-hữu-khoá kiểu DPoP: ai cầm được
   * chuỗi thẻ thì dùng được thẻ, nguyên vẹn tới `exp`. Hệ quả cho bên tích hợp:
   * đừng ghi thẻ vào log/URL/analytics, giữ trong bộ nhớ chứ đừng bỏ vào
   * `localStorage`, và đổi thẻ mới khi cần thay vì kéo dài một thẻ.
   *
   * ## Thẻ phiên đi trong THÂN yêu cầu
   *
   * Không bao giờ trong chuỗi truy vấn: tham số URL nằm lại trong lịch sử
   * trình duyệt, header `Referer` gửi sang trang khác, và log truy cập của mọi
   * proxy trên đường. Bài kiểm `test/tokenExchange.test.ts` chốt điều này.
   *
   * ## Hạn dùng đọc từ máy chủ, không viết cứng
   *
   * `expiresAt`/`expiresIn` lấy từ trường `expires_in` nếu máy chủ gửi, ngược
   * lại từ claim `exp` mà chính máy chủ đã ký trong thẻ. Viết cứng 900 giây thì
   * ngày máy chủ đổi TTL, bên tích hợp hết hạn sai lúc mà không có gì báo.
   *
   * ## Lỗi phân biệt được (đều là `PhoenixKeyError`)
   *
   * - `code: "unauthorized"` (401) — thẻ phiên sai kiểu, quá cũ sau khôi phục
   *   tài khoản, hoặc khoá lập phiên đã bị thu hồi → cho người dùng đăng nhập lại.
   * - `code: "signature_invalid"` (403) — thẻ hỏng hoặc đã hết hạn chữ ký.
   * - `code: "redirect_uri_mismatch"` (400) — `redirectUri` không nằm trong
   *   `serviceEndpoint[]` của DID Document thuộc `aud`. Đây là lỗi CẤU HÌNH của
   *   app đích, không phải lỗi người dùng — đăng nhập lại không cứu được.
   * - `code: "service_did_not_found"` (404) — `aud` chưa công bố endpoint nào.
   * - `code: "rate_limited"` (429) — vượt hạn mức lượt đổi trên mỗi thẻ phiên.
   * - `code: "enum_invalid_value"` (400) — `aud` sai khuôn `did:phoenix:…`,
   *   `nonce` quá 64 ký tự, hoặc thiếu trường bắt buộc.
   *
   * @example
   * ```ts
   * const { appToken, expiresIn } = await client.auth.exchange({
   *   sessionToken: client.session.getSessionToken()!,
   *   aud: "did:phoenix:<b32-13>:<hex-64>",   // ServiceDID của app đích
   *   redirectUri: "https://partner.example/callback",
   * });
   * // Gửi appToken sang app đích; nó tự verify qua JWKS bằng `AppTokenVerifier`.
   * scheduleRefresh(expiresIn);   // KHÔNG dùng hằng số 900 ở đây
   * ```
   */
  async exchange(params: TokenExchangeParams): Promise<TokenExchangeResult> {
    const body: Record<string, string> = {
      session_token: params.sessionToken,
      aud: params.aud,
      redirect_uri: params.redirectUri,
    };
    if (params.nonce !== undefined) body.nonce = params.nonce;

    const res = await this.fetch<TokenExchangeResponse>("/auth/token/exchange", {
      method: "POST",
      // Thẻ phiên nằm ở ĐÂY — trong thân yêu cầu. Đường dẫn ở trên không mang
      // tham số truy vấn nào, và không được phép mang.
      body: JSON.stringify(body),
    } as FetchOptions);

    if (!res?.app_token) {
      throw new PhoenixKeyError({
        status: 200,
        code: "malformed_token",
        message: "Token exchange response has no app_token",
      });
    }

    const now = Math.floor(Date.now() / 1000);
    // Ưu tiên trường tường minh của máy chủ; nếu không có thì lấy `exp` mà máy
    // chủ đã ký trong chính thẻ. Không có nhánh nào trả về hằng số.
    const expiresAt =
      typeof res.expires_in === "number"
        ? now + res.expires_in
        : readExpClaim(res.app_token);

    if (expiresAt === undefined) {
      throw new PhoenixKeyError({
        status: 200,
        code: "malformed_token",
        message:
          "Cannot determine app_token lifetime — response has no expires_in and the token has no exp claim",
      });
    }

    return {
      appToken: res.app_token,
      userDid: res.user_did,
      expiresAt,
      expiresIn: expiresAt - now,
    };
  }
}

/**
 * Đọc claim `exp` (epoch giây) từ phần payload của một JWT.
 *
 * **Đây KHÔNG phải phép kiểm tra thẻ.** Không có chữ ký nào được xác minh ở
 * đây; hàm này chỉ để bên đổi thẻ biết thẻ mình vừa nhận sống được bao lâu mà
 * hẹn giờ đổi lại. Bên NHẬN thẻ phải verify thật qua `AppTokenVerifier`
 * (`@phoenixkeydid/phoenixkey-sdk/verifier`) — nó kiểm chữ ký Ed25519 theo
 * JWKS, hạn dùng, và `aud`.
 *
 * Trả `undefined` khi thẻ không tách được ba phần, payload không phải JSON,
 * hoặc không có `exp` kiểu số — bên gọi tự quyết, hàm này không ném.
 */
function readExpClaim(token: string): number | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const b64 = parts[1].replaceAll("-", "+").replaceAll("_", "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    let jsonText: string;
    if (typeof atob === "function") {
      const bin = atob(padded);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      jsonText = new TextDecoder().decode(bytes);
    } else {
      const NodeBuffer = (
        globalThis as { Buffer?: { from(s: string, enc: string): { toString(enc: string): string } } }
      ).Buffer;
      if (!NodeBuffer) return undefined;
      jsonText = NodeBuffer.from(padded, "base64").toString("utf8");
    }
    const payload = JSON.parse(jsonText) as { exp?: unknown };
    return typeof payload.exp === "number" ? payload.exp : undefined;
  } catch {
    return undefined;
  }
}
