/**
 * Get LAMP support session (spec §15.8). MVP stub — returns ProofChat URL placeholder.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { SupportSession } from "./types";

export class SupportModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Open a support session (`POST /support/session/init`).
   *
   * Requires the session Bearer token: the route is not in the server's public
   * list (`AuthRequiredInterceptor`). Throws `Error("Not authenticated")`
   * without calling the network when there is no token.
   */
  async initSession(): Promise<SupportSession> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    return this.fetch<SupportSession>("/support/session/init", {
      method: "POST",
      bearerToken: token,
    } as FetchOptions);
  }
}
