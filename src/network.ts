/**
 * PhoenixKey SDK — Network (LampNet) Module
 *
 * LampNet node map (spec §14.4). MVP stub: backend trả 12 mock nodes.
 * Phase H+ sẽ wire data thật khi LampNet API public.
 */

import { createFetcher } from "./fetcher";
import { LampNetNodes } from "./types";

export class NetworkModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(baseUrl: string) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Fetch LampNet node map.
   *
   * @param userDid  optional — Phase H sẽ filter node theo proximity (chưa dùng MVP)
   */
  async getNodes(userDid?: string): Promise<LampNetNodes> {
    const path = userDid
      ? `/identity/nodes?did=${encodeURIComponent(userDid)}`
      : "/identity/nodes";
    return this.fetch<LampNetNodes>(path);
  }
}
