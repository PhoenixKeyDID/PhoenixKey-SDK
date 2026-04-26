/**
 * PhoenixKey SDK — Auth Module
 *
 * Manages the full login session lifecycle:
 *
 * 1. `initSession()`      — POST /auth/session/init → QR payload + temp_token
 * 2. `openStream()`       — SSE stream authenticated with temp_token (primary)
 * 3. `getStatus()`        — GET /auth/session/{id}/status (fallback / onReconnect)
 * 4. `pushLinkedDevice()` — POST /auth/session/push (skip QR on return visits)
 *
 * Spec §6.3 (session), §15.1 (SSE)
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { ResilientSSE, SseOptions } from "./sse";
import { LoginSessionInit, LoginSessionStatus, SseHandlers } from "./types";

export class AuthModule {
  private readonly fetch: ReturnType<typeof createFetcher>;
  private readonly sseBaseUrl: string;

  constructor(
    apiKey: string,
    baseUrl: string,
    sseBaseUrl: string,
    private readonly sessionTokenGetter: () => string | null,
  ) {
    this.fetch = createFetcher(apiKey, baseUrl);
    this.sseBaseUrl = sseBaseUrl;
  }

  /**
   * Step 1 — Bootstrap a login session.
   *
   * Returns a `temp_token` (for SSE auth) and a `session_id` (for QR/polling).
   * The QR code your UI renders should encode:
   * `aladin://auth?session={session_id}&app={appId}`
   *
   * @example
   * ```ts
   * const { session_id, temp_token, expires_at } = await client.auth.initSession();
   * renderQR(`aladin://auth?session=${session_id}&app=my-app`);
   * ```
   */
  async initSession(): Promise<LoginSessionInit> {
    return this.fetch<LoginSessionInit>("/auth/session/init", {
      method: "POST",
    });
  }

  /**
   * Step 2 (primary) — Open the SSE stream that pushes the approval event.
   *
   * When `onMessage` fires with `data.status === "approved"`:
   * - Call `client.session.set(data.session_token, data.user_did)` to persist the session
   * - Call `client.session.setLinkedDevice(data.linked_device_token)` if present
   *
   * On every reconnect, `onReconnect` fires — call `getStatus()` there to
   * catch any event missed while the stream was down.
   *
   * @param sessionId  From `initSession().session_id`
   * @param tempToken  From `initSession().temp_token`
   * @param handlers   onMessage, onReconnect, onRetry, onClose
   *
   * @example
   * ```ts
   * const stream = client.auth.openStream(session_id, temp_token, {
   *   onMessage: async ({ data }) => {
   *     if (data.status === "approved") {
   *       client.session.set(data.session_token, data.user_did);
   *       if (data.linked_device_token)
   *         client.session.setLinkedDevice(data.linked_device_token);
   *       stream.close();
   *       router.push("/dashboard");
   *     }
   *   },
   *   onReconnect: () => client.auth.getStatus(session_id, temp_token)
   *     .then(({ data }) => handlers.onMessage({ type: "message", data })),
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
   * Use this:
   * - In `onReconnect` to catch missed SSE events
   * - In environments where SSE is unavailable (some proxies / React Native)
   *
   * @param sessionId  From `initSession().session_id`
   * @param tempToken  From `initSession().temp_token`
   *
   * @example
   * ```ts
   * // Polling loop (use SSE instead when possible)
   * const poll = setInterval(async () => {
   *   const status = await client.auth.getStatus(session_id, temp_token);
   *   if (status.status === "approved") {
   *     clearInterval(poll);
   *     client.session.set(status.session_token, status.user_did);
   *   }
   * }, 2000);
   * ```
   */
  async getStatus(sessionId: string, tempToken: string): Promise<LoginSessionStatus> {
    return this.fetch<LoginSessionStatus>(`/auth/session/${sessionId}/status`, {
      method: "GET",
      headers: { Authorization: `Bearer ${tempToken}` },
    } as FetchOptions);
  }

  /**
   * Step 2 (return visits) — Send a push notification to the user's Aladin app.
   *
   * Only available when `client.session.hasLinkedDevice()` returns true.
   * Skips QR entirely — user just taps the notification and scans fingerprint.
   *
   * @example
   * ```ts
   * if (client.session.hasLinkedDevice()) {
   *   await client.auth.pushLinkedDevice();
   *   // Wait on SSE stream for approval event
   * } else {
   *   // Show QR code
   * }
   * ```
   */
  async pushLinkedDevice(): Promise<void> {
    const device = this._getLinkedDevice?.();
    if (!device) throw new Error("No linked device — show QR instead");

    await this.fetch<void>("/auth/session/push", {
      method: "POST",
      headers: { Authorization: `Bearer ${device.token}` },
      json: false,
    } as FetchOptions);
  }

  // Injected by PhoenixKeyClient to avoid circular dep
  _getLinkedDevice?: () => ReturnType<typeof import("./session")["getLinkedDevice"]>;
}