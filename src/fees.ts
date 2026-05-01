/**
 * PhoenixKey SDK — Fees Module
 *
 * Cardano fee estimate (MVP hardcode). Phase H sẽ thay bằng BloxBean fee
 * calculator real-time.
 */

import { createFetcher } from "./fetcher";
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

  constructor(baseUrl: string) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Estimate Cardano fee theo type. Returns `{ type, magic, unit: "MAGIC" }`.
   * Public — không cần auth.
   */
  async estimate(type: FeeType): Promise<FeeEstimate> {
    return this.fetch<FeeEstimate>(`/tx/estimate?type=${encodeURIComponent(type)}`);
  }
}
