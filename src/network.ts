/**
 * PhoenixKey SDK — Network (LampNet) Module
 *
 * LampNet node map (spec §14.4). MVP stub: backend trả 12 mock nodes.
 * Phase H+ sẽ wire data thật khi LampNet API public.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { LampNetNodes } from "./types";

export class NetworkModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Fetch LampNet node map.
   *
   * Requires the session Bearer token: `GET /identity/nodes` is not in the
   * server's public list (`AuthRequiredInterceptor`) and answers 401 without
   * it. Throws `Error("Not authenticated")` without calling the network when
   * there is no token.
   *
   * @param userDid  optional — Phase H sẽ filter node theo proximity (chưa dùng MVP)
   */
  async getNodes(userDid?: string): Promise<LampNetNodes> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    const path = userDid
      ? `/identity/nodes?did=${encodeURIComponent(userDid)}`
      : "/identity/nodes";
    return this.fetch<LampNetNodes>(path, { bearerToken: token } as FetchOptions);
  }
}
