/**
 * PhoenixKey SDK — Wallet Module
 *
 * Read user balance (ADA / LAMP / MAGIC), accrued MAGIC, and claim emissions.
 * Read-only by default — no auth needed for balance lookup.
 */

import { createFetcher, FetchOptions } from "./fetcher";

export type Balance = {
  address: string | null;
  balance_lovelace: number;
  balance_lamp: number;
  balance_magic: number;
  magic_accrued: number;
  /** MAGIC per LAMP per slot. String to preserve decimal precision. */
  magic_rate_per_slot: string;
  last_accrual_slot: number;
  current_slot: number;
};

export type MagicClaimResult = {
  claim_id: string;
  amount_magic: number;
  cardano_tx_hash: string;
  status: "PENDING" | "SUBMITTED" | "CONFIRMED" | "FAILED";
};

export class WalletModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Register the user's Cardano wallet address. Mobile calls this after
   * deriving the address from the wallet seed.
   */
  async registerAddress(walletAddress: string): Promise<void> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    await this.fetch<void>("/wallet/register", {
      method: "POST",
      body: JSON.stringify({ wallet_address: walletAddress }),
      bearerToken: token,
    } as FetchOptions);
  }

  /**
   * Get current balance and accrued MAGIC.
   * Public endpoint — no auth required (Cardano addresses are public).
   */
  async getBalance(userDid: string): Promise<Balance> {
    return this.fetch<Balance>(`/wallet/${encodeURIComponent(userDid)}/balance`);
  }

  /**
   * Claim accrued MAGIC. Server mints + sends to user's registered wallet.
   */
  async claimMagic(): Promise<MagicClaimResult> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    return this.fetch<MagicClaimResult>("/wallet/magic/claim", {
      method: "POST",
      bearerToken: token,
    } as FetchOptions);
  }

  /**
   * Compute display-time accrued MAGIC by extrapolating from server snapshot.
   * Useful for real-time UI counters between 15s poll intervals.
   *
   * @param balance     last balance from getBalance()
   * @param currentTime current timestamp (Date.now())
   * @param slotOrigin  Cardano slot 0 epoch milliseconds (preprod or mainnet)
   * @param msPerSlot   1000 for Cardano (1 slot/sec)
   */
  static extrapolateAccrued(
    balance: Balance,
    currentTime: number = Date.now(),
    slotOrigin?: number,
    msPerSlot: number = 1000,
  ): number {
    if (balance.balance_lamp <= 0) return balance.magic_accrued;
    const rate = parseFloat(balance.magic_rate_per_slot);
    if (!Number.isFinite(rate) || rate <= 0) return balance.magic_accrued;

    let elapsedSlots: number;
    if (slotOrigin) {
      const currentSlot = Math.floor((currentTime - slotOrigin) / msPerSlot);
      elapsedSlots = Math.max(0, currentSlot - balance.last_accrual_slot);
    } else {
      // Fallback: assume current_slot is recent
      elapsedSlots = 0;
    }
    return balance.magic_accrued + Math.floor(rate * elapsedSlots * balance.balance_lamp);
  }
}
