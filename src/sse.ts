/**
 * PhoenixKey SDK — Resilient SSE Client
 *
 * Wraps @microsoft/fetch-event-source with:
 * - Exponential backoff reconnect (1s → 30s cap)
 * - Auto-fires onReconnect so callers can poll /auth/session/{id}/status
 *   to catch state missed while offline
 * - Heartbeat comments (`: ping`) are silently discarded
 *
 * Spec §15.1
 *
 * @example
 * ```ts
 * const stream = new ResilientSSE<LoginSessionStatus>(
 *   { url: `/auth/session/${sessionId}/stream`, token: tempToken, sseBaseUrl },
 *   {
 *     onMessage: ({ data }) => {
 *       if (data.status === "approved") handleApproved(data);
 *     },
 *     onReconnect: () => pollStatusFallback(sessionId, tempToken),
 *   },
 * );
 * await stream.connect();
 * // Later:
 * stream.close();
 * ```
 */

import { fetchEventSource } from "@microsoft/fetch-event-source";
import { SseEvent, SseHandlers } from "./types";

export type SseOptions = {
  /** Path or full URL. Paths are prefixed with sseBaseUrl. */
  url: string;
  /** Bearer token for Authorization header (use `temp_token` from initSession). */
  token?: string;
  sseBaseUrl: string;
  /** @default 1000 */
  initialDelayMs?: number;
  /** @default 30000 */
  maxDelayMs?: number;
};

export class ResilientSSE<T = unknown> {
  private controller: AbortController | null = null;
  private retryDelay: number;
  private readonly maxDelay: number;
  private readonly initialDelay: number;
  private stopped = false;
  private retryAttempt = 0;

  constructor(
    private readonly opts: SseOptions,
    private readonly handlers: SseHandlers<T>,
  ) {
    this.initialDelay = opts.initialDelayMs ?? 1000;
    this.maxDelay = opts.maxDelayMs ?? 30_000;
    this.retryDelay = this.initialDelay;
  }

  async connect(): Promise<void> {
    if (this.stopped) return;

    this.controller?.abort();
    this.controller = new AbortController();

    const { url, token, sseBaseUrl } = this.opts;
    const base = sseBaseUrl.replace(/\/+$/, "");
    const normalizedPath = url.startsWith("/") ? url : `/${url}`;
    const fullUrl = /^https?:\/\//.test(url) ? url : `${base}${normalizedPath}`;

    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (token) headers.Authorization = `Bearer ${token}`;

    try {
      await fetchEventSource(fullUrl, {
        signal: this.controller.signal,
        headers,
        openWhenHidden: true,

        onopen: async (response) => {
          if (
            response.ok &&
            response.headers.get("content-type")?.includes("text/event-stream")
          ) {
            this.retryDelay = this.initialDelay;
            if (this.retryAttempt > 0) {
              this.handlers.onReconnect?.();
            }
            this.retryAttempt = 0;
            return;
          }
          // 4xx (except 429) — non-retryable
          if (response.status >= 400 && response.status < 500 && response.status !== 429) {
            this.stopped = true;
            throw new Error(`SSE rejected with ${response.status}`);
          }
          throw new Error(`Unexpected SSE response ${response.status}`);
        },

        onmessage: (msg) => {
          if (!msg.data) return;
          let parsed: T;
          try {
            parsed = JSON.parse(msg.data) as T;
          } catch {
            parsed = msg.data as unknown as T;
          }
          this.handlers.onMessage({
            type: msg.event || "message",
            data: parsed,
            id: msg.id || undefined,
          } as SseEvent<T>);
        },

        onerror: (err) => {
          console.warn("[PhoenixKey SSE] connection error — will retry", err);
          throw err;
        },

        onclose: () => {
          throw new Error("SSE stream closed by server");
        },
      });
    } catch (err) {
      if (this.stopped) {
        this.handlers.onClose?.();
        return;
      }
      this.retryAttempt += 1;
      const delay = this.retryDelay;
      this.handlers.onRetry?.(this.retryAttempt, delay);
      console.warn(
        `[PhoenixKey SSE] reconnect attempt ${this.retryAttempt} in ${delay}ms`,
        err,
      );
      setTimeout(() => {
        this.retryDelay = Math.min(this.retryDelay * 2, this.maxDelay);
        void this.connect();
      }, delay);
    }
  }

  /** Permanently closes the SSE connection. Call in component cleanup. */
  close(): void {
    this.stopped = true;
    this.controller?.abort();
    this.handlers.onClose?.();
  }
}