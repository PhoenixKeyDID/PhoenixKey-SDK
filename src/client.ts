/**
 * PhoenixKey SDK — Main Client
 *
 * @example
 * ```ts
 * import { PhoenixKeyClient } from "@phoenixkeydid/phoenixkey-sdk";
 *
 * export const phoenix = new PhoenixKeyClient({
 *   appId:   "orilife-web-v1",
 *   appName: "OriLife",
 *   domain:  "orilife.com",
 *   environment: "mainnet",
 * });
 * ```
 */

import { PhoenixKeyConfig } from "./types";
import { AuthModule } from "./auth";
import { SignRequestModule } from "./signRequest";
import { IdentityModule } from "./identity";
import { ActivityModule } from "./activity";
import { SeedModule } from "./seed";
import { FeesModule } from "./fees";
import { NetworkModule } from "./network";
import { SupportModule } from "./support";
import { WalletModule } from "./wallet";
import { ActivationModule } from "./activation";
import * as session from "./session";

export class PhoenixKeyClient {
  /** QR-pairing login + linked-device flow (spec §6). */
  readonly auth: AuthModule;
  /** Web ↔ mobile sign request relay (spec §7). */
  readonly signRequest: SignRequestModule;
  /** DID resolve, pubkey lookup, health snapshot. */
  readonly identity: IdentityModule;
  /** Activity logs với cursor pagination (spec §10). */
  readonly activity: ActivityModule;
  /** Seed Phrase export flow (spec §9.2). */
  readonly seed: SeedModule;
  /** Cardano fee estimate (MVP hardcode). */
  readonly fees: FeesModule;
  /** LampNet node map (spec §14.4 stub). */
  readonly network: NetworkModule;
  /** Get LAMP support session (spec §15.8 stub). */
  readonly support: SupportModule;
  /** Wallet balance + MAGIC accrual + claim (testnet release). */
  readonly wallet: WalletModule;
  /** Activation package flow — 200k VND → 1001 LAMP + 10 ADA via Genie. */
  readonly activation: ActivationModule;

  /** localStorage helpers. */
  readonly session: typeof session;

  readonly config: Required<Omit<PhoenixKeyConfig, "apiKey">> & { apiKey?: string };

  constructor(config: PhoenixKeyConfig) {
    if (!config.appId) throw new Error("PhoenixKeyClient: appId required");
    if (!config.appName) throw new Error("PhoenixKeyClient: appName required");
    if (!config.domain) throw new Error("PhoenixKeyClient: domain required");

    const apiBaseUrl = config.apiBaseUrl ?? "https://api.phoenixkey.me";

    this.config = {
      appId: config.appId,
      appName: config.appName,
      domain: config.domain,
      apiBaseUrl,
      sseBaseUrl: config.sseBaseUrl ?? apiBaseUrl,
      environment: config.environment ?? "mainnet",
      apiKey: config.apiKey,
    };

    this.session = session;

    this.auth = new AuthModule(
      this.config.apiBaseUrl,
      this.config.sseBaseUrl,
      this.config.domain,
      session.getLinkedDevice,
    );

    this.signRequest = new SignRequestModule(
      this.config.apiBaseUrl,
      this.config.sseBaseUrl,
      this.config.appId,
      this.config.domain,
      session.getSessionToken,
    );

    this.identity = new IdentityModule(
      this.config.apiBaseUrl,
      session.getSessionToken,
    );

    this.activity = new ActivityModule(
      this.config.apiBaseUrl,
      session.getSessionToken,
    );

    this.seed = new SeedModule(
      this.config.apiBaseUrl,
      session.getSessionToken,
    );

    this.fees = new FeesModule(this.config.apiBaseUrl);
    this.network = new NetworkModule(this.config.apiBaseUrl);
    this.support = new SupportModule(this.config.apiBaseUrl);
    this.wallet = new WalletModule(this.config.apiBaseUrl, session.getSessionToken);
    this.activation = new ActivationModule(
      this.config.apiBaseUrl,
      this.config.sseBaseUrl,
      session.getSessionToken,
    );
  }

  /**
   * Returns true if a non-expired session_token exists in localStorage.
   * Use to guard routes before first API call.
   */
  isLoggedIn(): boolean {
    return session.isLoggedIn();
  }

  /** Clears all PhoenixKey data (session + linked device). */
  logout(): void {
    session.clearAll();
  }
}
