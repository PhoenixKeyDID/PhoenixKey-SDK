/**
 * Get LAMP support session (spec §15.8). MVP stub — returns ProofChat URL placeholder.
 */

import { createFetcher } from "./fetcher";
import { SupportSession } from "./types";

export class SupportModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(baseUrl: string) {
    this.fetch = createFetcher(baseUrl);
  }

  async initSession(): Promise<SupportSession> {
    return this.fetch<SupportSession>("/support/session/init", { method: "POST" });
  }
}
