/**
 * PhoenixKey SDK — Wallet Module
 *
 * Read the signed-in user's own wallets (ADA / LAMP / CARP), MAGIC account
 * and Wakeme vault LAMP. Every read needs the session Bearer token and only
 * works for the DID that owns the session (server `requireSelfDid`).
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
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/** BIP-173 polymod over the 5-bit values (HRP-expansion ∥ data ∥ checksum). */
function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= BECH32_GENERATOR[i];
    }
  }
  return chk >>> 0;
}

/** Expand the human-readable part into 5-bit values per BIP-173. */
function bech32HrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 0x1f);
  return out;
}

/**
 * Decode a bech32 string (BIP-173) to its raw data bytes (checksum dropped).
 *
 * Verifies the 6-symbol BIP-173 checksum (polymod == 1) so a single mistyped
 * character is rejected rather than silently decoded into a garbage key hash.
 * Rejects mixed-case input (BIP-173 forbids it).
 */
function bech32ToBytes(addr: string): Uint8Array {
  const lower = addr.toLowerCase();
  const upper = addr.toUpperCase();
  if (addr !== lower && addr !== upper) {
    throw new Error("Invalid bech32 address (mixed case)");
  }
  const s = lower;
  const sep = s.lastIndexOf("1");
  if (sep < 1) throw new Error("Invalid bech32 address (no separator)");
  const hrp = s.slice(0, sep);
  const values: number[] = [];
  for (const ch of s.slice(sep + 1)) {
    const v = BECH32_CHARSET.indexOf(ch);
    if (v === -1) throw new Error(`Invalid bech32 char: ${ch}`);
    values.push(v);
  }
  if (values.length < 6) throw new Error("bech32 data too short");

  // Verify checksum before trusting any data symbols.
  if (bech32Polymod([...bech32HrpExpand(hrp), ...values]) !== 1) {
    throw new Error("Invalid bech32 address (bad checksum)");
  }

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
 * Throws if the credential is not a payment key hash — i.e. a script payment
 * credential (CIP-19 types 1/3/5/7), or a reward/stake address (types 14/15)
 * or any non-payment header (type > 7). The old code only masked the script
 * low-bit, so a reward address (`stake`/`stake_test`, type 14 = `0b1110`)
 * slipped through and its stake credential was returned as a bogus payment PKH.
 */
export function paymentKeyHashFromAddress(address: string): string {
  const bytes = bech32ToBytes(address);
  if (bytes.length < 29) throw new Error("Address too short for a Shelley payment credential");
  const addrType = bytes[0] >> 4; // CIP-19 header: high nibble = address type

  // Whitelist payment address types {0..7}. Types 14/15 are reward/stake
  // accounts (no payment credential); 8 is Byron; others are undefined.
  if (addrType > 7) {
    throw new Error(
      `Address type ${addrType} is not a payment address (reward/stake or non-Shelley) — ` +
        "expected addr/addr_test (CIP-19 types 0-7), not stake/stake_test",
    );
  }
  // Within payment types, odd types (1/3/5/7) carry a script payment credential.
  if (addrType & 0b0001) {
    throw new Error("Payment credential is a script hash, not a key hash — not a MAGIC owner key");
  }
  const pkh = bytes.slice(1, 29); // first credential = payment credential (28 bytes)
  return Array.from(pkh, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Response of the deprecated `GET /wallet/{did}/balance`.
 *
 * Wire format (server `WalletDtos.BalanceResponse`, snake_case JSON): the
 * on-chain quantities are serialized as decimal STRINGS, because LAMP supply in
 * oildrop (3.6×10¹⁶) exceeds `Number.MAX_SAFE_INTEGER`. Do not `parseInt` them
 * — use `BigInt(value)`.
 */
export type Balance = {
  address: string | null;
  /** Lovelace, decimal string. */
  balance_lovelace: string;
  /** LAMP is a Cardano native token — this balance is real and valid. Oildrop, decimal string. */
  balance_lamp: string;
  /** CARP, decimal string. */
  balance_carp: string;

  // ─── DEPRECATED MAGIC fields (custodial model, conceptually wrong) ──────────
  // The server forces these to 0/"" (WalletDtos.BalanceResponse). MAGIC is NOT
  // a native token and has no per-wallet balance: it is an accounting number in
  // the Vault. Read it from `getAll()` → `magic`. Slated for removal.
  /** @deprecated Always "0" from the server. Use `getAll().magic`. */
  balance_magic: string;
  /** @deprecated Always "0" from the server. Use `getAll().magic`. */
  magic_accrued: string;
  /** @deprecated Always "" from the server. */
  magic_rate_per_slot: string;
  /** @deprecated see magic_accrued. */
  last_accrual_slot: number;
  current_slot: number;
};

/** Address set of one wallet. The Phoenix wallet has only `fixed`; Standard has all three. */
export type WalletAddresses = {
  fixed?: string | null;
  active?: string | null;
  stake?: string | null;
};

/** Lovelace / LAMP / CARP of one wallet — decimal strings (may exceed 2^53). */
export type WalletBalances = {
  lovelace: string;
  lamp: string;
  carp: string;
};

export type WalletEntry = {
  /** "phoenix" or "standard". */
  kind: string;
  addresses: WalletAddresses;
  balances: WalletBalances;
};

/** Why the server could not read the MAGIC account (`magic.source === "unwired"`). */
export type MagicAbsentReason =
  | "NOT_CONFIGURED"
  | "OWNER_UNRESOLVABLE"
  | "UNAUTHORIZED"
  | "READ_FAILED";

/**
 * MAGIC = an accounting number in the Vault, not a wallet balance. When
 * `source` is `"unwired"` the four numeric fields are `null` and
 * `magic_absent_reason` says why — render "—" (or "retry" for `READ_FAILED`),
 * never "0 MAGIC". Quantities are nanogic (1 MAGIC = 10⁹ nanogic), decimal strings.
 */
export type MagicAccount = {
  source: "vault" | "unwired";
  /** Spendable today. */
  available: string | null;
  /** Cumulative accrued. */
  accrued: string | null;
  /** Expired (MAGIC is use-it-or-lose-it per epoch). */
  expired: string | null;
  /** 0 = no vault; > 0 = has vaults (and a balance of 0 is real). */
  vault_count: number | null;
  magic_absent_reason: MagicAbsentReason | null;
};

/** LAMP held in the Wakeme vault, read from the on-chain inline datum (oildrop, decimal strings). */
export type VaultLamp = {
  owned_lamp: string;
  conditional_lamp: string;
  reclaimed_to_pot: string;
  d_unit: string;
};

/** Why `vault` is `null` in {@link WalletsAll}. `READ_FAILED` must be shown as "retry", not "you have none". */
export type VaultAbsentReason =
  | "SERVED_BY_WAKEME_SERVICE"
  | "NOT_DEPLOYED"
  | "NO_VAULT_FOR_USER"
  | "READ_FAILED";

/** Response of `GET /wallet/{did}/all` (server `WalletsAllResponse`). */
export type WalletsAll = {
  wallets: WalletEntry[];
  magic: MagicAccount;
  vault: VaultLamp | null;
  /** `null` when `vault` is not null. */
  vault_absent_reason: VaultAbsentReason | null;
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
   * Get the Phoenix wallet address and its lovelace / LAMP / CARP balance.
   *
   * Requires the session Bearer token, and `userDid` must be the DID of that
   * session: the server (`WalletController.balance` → `requireSelfDid`) answers
   * 401 without a token and refuses another DID's wallet. Throws
   * `Error("Not authenticated")` without calling the network when there is no
   * token.
   *
   * @deprecated The server endpoint is deprecated (`@Deprecated(forRemoval)`);
   * its five MAGIC fields are always 0/"". Use {@link WalletModule.getAll}.
   */
  async getBalance(userDid: string): Promise<Balance> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    return this.fetch<Balance>(`/wallet/${encodeURIComponent(userDid)}/balance`, {
      bearerToken: token,
    } as FetchOptions);
  }

  /**
   * Both wallets (Phoenix + Standard), the MAGIC account and the Wakeme vault
   * LAMP in one call (`GET /wallet/{did}/all`).
   *
   * Requires the session Bearer token; `userDid` must be the session's own DID
   * (server `requireSelfDid`). Throws `Error("Not authenticated")` without a
   * token, before any network call.
   *
   * Check `magic.source` and `vault_absent_reason` before rendering numbers:
   * "unwired" / "READ_FAILED" mean the server could not read, which is not
   * the same as a zero balance.
   */
  async getAll(userDid: string): Promise<WalletsAll> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    return this.fetch<WalletsAll>(`/wallet/${encodeURIComponent(userDid)}/all`, {
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
   * (`registerAddress()`); throws otherwise. It reads through `getBalance`, so
   * it needs the session of `userDid` itself — the server does not let one DID
   * look up another's wallet. Throws `Error("Not authenticated")` without a
   * session token.
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
   * @deprecated The per-wallet MAGIC accrual model this extrapolates was
   * dropped. MAGIC is an accounting number in the Vault of the Wakeme
   * service — generated inside each vault from locked LAMP, never accrued at
   * a per-wallet per-slot rate — so there is no client-side rate to
   * extrapolate, and the deprecated balance route always returns
   * `magic_rate_per_slot` as `""`. Slated for removal.
   *
   * Replacement reads (no 1:1 extrapolation successor):
   *   - `getAll(userDid)` — the `magic` block (`MagicAccount`: `source`,
   *     `available` / `accrued` / `expired`, nanogic decimal strings); check
   *     `source === "unwired"` before rendering numbers;
   *   - `wakeme.getVaultMagic(did)` — daily MAGIC yield, read-only.
   * See INTEGRATION.md §2.1 for the live endpoint map.
   *
   * Compute display-time accrued MAGIC by extrapolating from server snapshot.
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
    // Wire quantities are decimal strings (see `Balance`); this deprecated
    // helper works in JS numbers, so precision above 2^53 is not preserved.
    const lamp = Number(balance.balance_lamp);
    const accrued = Number(balance.magic_accrued);
    if (!(lamp > 0)) return accrued;
    const rate = parseFloat(balance.magic_rate_per_slot);
    if (!Number.isFinite(rate) || rate <= 0) return accrued;

    let elapsedSlots: number;
    if (slotOrigin) {
      const currentSlot = Math.floor((currentTime - slotOrigin) / msPerSlot);
      elapsedSlots = Math.max(0, currentSlot - balance.last_accrual_slot);
    } else {
      // Fallback: assume current_slot is recent
      elapsedSlots = 0;
    }
    return accrued + Math.floor(rate * elapsedSlots * lamp);
  }
}
