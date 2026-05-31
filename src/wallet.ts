/**
 * PhoenixKey SDK — Wallet Module
 *
 * Read user balance (ADA / LAMP / MAGIC), accrued MAGIC, and claim emissions.
 * Read-only by default — no auth needed for balance lookup.
 */

import { createFetcher, FetchOptions } from "./fetcher";

/**
 * Cardano slot 0 epoch milliseconds.
 *
 * Use these with `WalletModule.extrapolateAccrued()` so UI counters tick
 * between balance polls. Picking the wrong constant gives a stale or
 * future-skewed slot — match the environment the server runs against.
 *
 *   - Preprod: 2022-10-25 00:00:00 UTC (preprod restart point used by BE indexer)
 *   - Mainnet: 2020-07-29 21:44:51 UTC (Shelley genesis, system_start in network params)
 *
 * Verified against BE indexer's `system_start` network param (Blockfrost
 * `/epochs/parameters`). If BE ever switches its slot reference, update here
 * in lockstep — future Phase H may expose this via NetworkModule.getSlotOrigin()
 * to avoid client-side constants entirely.
 */
export const PREPROD_SLOT_ORIGIN_MS = 1666656000000;
export const MAINNET_SLOT_ORIGIN_MS = 1596059091000;

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** Decode a bech32 string (BIP-173) to its raw data bytes (checksum dropped). */
function bech32ToBytes(addr: string): Uint8Array {
  const s = addr.toLowerCase();
  const sep = s.lastIndexOf("1");
  if (sep < 1) throw new Error("Invalid bech32 address (no separator)");
  const values: number[] = [];
  for (const ch of s.slice(sep + 1)) {
    const v = BECH32_CHARSET.indexOf(ch);
    if (v === -1) throw new Error(`Invalid bech32 char: ${ch}`);
    values.push(v);
  }
  if (values.length < 6) throw new Error("bech32 data too short");
  const data5 = values.slice(0, values.length - 6); // drop 6-char checksum
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const v of data5) {
    acc = (acc << 5) | v;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/**
 * Extract the 28-byte payment key hash (hex) from a Cardano Shelley bech32
 * address (`addr` / `addr_test`). This is the `ownerPkh` that
 * MagicLampNetwork/MAGIC (vault-based, canonical) expects: the CIP-1852
 * Wallet_Key payment credential that holds LAMP and signs vault spends
 * (vault.ak: `datum.owner ∈ extra_signatories`).
 *
 * Throws if the payment credential is a script hash rather than a key hash.
 */
export function paymentKeyHashFromAddress(address: string): string {
  const bytes = bech32ToBytes(address);
  if (bytes.length < 29) throw new Error("Address too short for a Shelley payment credential");
  const addrType = bytes[0] >> 4; // CIP-19 header: high nibble = address type
  if (addrType & 0b0001) {
    throw new Error("Payment credential is a script hash, not a key hash — not a MAGIC owner key");
  }
  const pkh = bytes.slice(1, 29); // first credential = payment credential (28 bytes)
  return Array.from(pkh, (b) => b.toString(16).padStart(2, "0")).join("");
}

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
   * MAGIC integration bridge — resolve a user's `ownerPkh` for
   * MagicLampNetwork/MAGIC (the canonical vault-based protocol consumed via
   * MagicSDK). Returns the 28-byte hex payment key hash of the user's
   * registered Cardano wallet — what `did.resolvePkh(userId)` provides in the
   * MagicSDK INTEGRATOR_GUIDE.
   *
   * This is the CIP-1852 Wallet_Key payment credential (holds LAMP, signs
   * vault spends per vault.ak `datum.owner`), NOT the TAAD controller key
   * (`IdentityStatus.current_controller_pkh`), which is the identity key and
   * never holds funds.
   *
   * Requires the user to have registered their wallet address
   * (`registerAddress()`); throws otherwise.
   */
  async resolveOwnerPkh(userDid: string): Promise<string> {
    const { address } = await this.getBalance(userDid);
    if (!address) {
      throw new Error(
        `No Cardano wallet registered for ${userDid} — call registerAddress() first.`,
      );
    }
    return paymentKeyHashFromAddress(address);
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
