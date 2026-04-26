/**
 * PhoenixKey SDK — Main Client
 *
 * @example
 * ```ts
 * import { PhoenixKeyClient } from "@phoenixkey/sdk";
 *
 * export const phoenix = new PhoenixKeyClient({
 *   apiKey:  process.env.NEXT_PUBLIC_PHOENIXKEY_API_KEY!,
 *   appId:   "orilife",
 *   appName: "OriLife",
 * });
 * ```
 */

import { PhoenixKeyConfig } from "./types";
import { AuthModule } from "./auth";
import * as session from "./session";

export class PhoenixKeyClient {
  readonly auth: AuthModule;
  readonly session: typeof session;

  private readonly config: Required<PhoenixKeyConfig>;

  constructor(config: PhoenixKeyConfig) {
    this.config = {
      apiBaseUrl: "https://api.phoenixkey.me",
      sseBaseUrl: "https://api.phoenixkey.me",
      environment: "mainnet",
      ...config,
    };

    this.session = session;

    this.auth = new AuthModule(
      this.config.apiKey,
      this.config.apiBaseUrl,
      this.config.sseBaseUrl,
      session.getSessionToken,
    );

    // Wire linked-device getter into auth module
    this.auth._getLinkedDevice = session.getLinkedDevice;
  }

  /**
   * Returns true if a non-expired session exists in localStorage.
   * Use to guard routes before the first API call.
   *
   * @example
   * ```ts
   * if (!phoenix.isLoggedIn()) router.push("/login");
   * ```
   */
  isLoggedIn(): boolean {
    return session.isLoggedIn();
  }

  /**
   * Clears all PhoenixKey data (session + linked device) and redirects to login.
   */
  logout(): void {
    session.clearAll();
  }
}