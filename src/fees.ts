/**
 * PhoenixKey SDK — Fees Module
 *
 * Cardano fee estimate (MVP hardcode). Phase H sẽ thay bằng BloxBean fee
 * calculator real-time.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { FeeEstimate } from "./types";

export type FeeType =
  | "key_rotation"
  | "create_did"
  | "update_did"
  | "seed_export"
  | "guardian_add"
  | "guardian_remove";

export class FeesModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Estimate Cardano fee theo type. Returns `{ type, magic, unit: "MAGIC" }`.
   *
   * Requires the session Bearer token: `GET /tx/estimate` is not in the
   * server's public list (`AuthRequiredInterceptor`) and answers 401 without
   * it. Throws `Error("Not authenticated")` without calling the network when
   * there is no token.
   */
  async estimate(type: FeeType): Promise<FeeEstimate> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    return this.fetch<FeeEstimate>(`/tx/estimate?type=${encodeURIComponent(type)}`, {
      bearerToken: token,
    } as FetchOptions);
  }
}
