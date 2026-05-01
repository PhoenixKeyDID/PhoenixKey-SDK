/**
 * PhoenixKey SDK — Seed Phrase Export Module
 *
 * Trigger Seed Phrase export flow (spec §9.2). Server tạo SignRequest type
 * `SEED_EXPORT`. Mobile sẽ hiển thị 2-layer cảnh báo bảo mật + biometric
 * trước khi show 24 từ BIP-39.
 *
 * Side-effect khi mobile approve: backend set `users.seed_exported_at = NOW()`
 * → dashboard banner cảnh báo (spec §9.5) cho tới khi user rotate key.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { SignRequestCreate } from "./types";

export class SeedModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Trigger seed export — tạo SignRequest type SEED_EXPORT.
   * Caller sau đó listen SSE event "signed" qua signRequest.openStream để
   * biết khi user approve.
   *
   * @param sessionId    session_id của user (từ login flow)
   * @param displayText  optional override mobile display text
   *
   * @example
   * ```ts
   * const stream = client.signRequest.openStream(currentSessionId, sessionToken, {
   *   onMessage: ({ type, data }) => {
   *     if (type === "signed" && data.status === "approved") {
   *       console.log("Seed export approved — show seed phrase to user");
   *     }
   *   },
   * });
   * await stream.connect();
   *
   * await client.seed.requestExport(currentSessionId);
   * ```
   */
  async requestExport(
    sessionId: string,
    displayText?: string,
  ): Promise<SignRequestCreate> {
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token");

    return this.fetch<SignRequestCreate>("/seed/export-request", {
      method: "POST",
      bearerToken: token,
      body: JSON.stringify({
        session_id: sessionId,
        ...(displayText ? { display_text: displayText } : {}),
      }),
    } as FetchOptions);
  }
}
