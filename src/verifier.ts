/**
 * @phoenixkeydid/phoenixkey-sdk/verifier
 *
 * Verify-only sub-package for 3rd-party backends. Resolves a user DID's
 * public key, then verifies ECDSA P-256 (prime256v1) signatures locally without
 * touching the PhoenixKey relay server (Path A pattern).
 *
 * Use case: OriLife / AladinWork backend receives `{intent, signature}` from
 * its frontend → calls `verifier.verifyIntent(...)` → trusts the user_did.
 */

import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { SignIntent, PhoenixKeyError } from "./types";
import { encodeRpAuthV1, encodeLegacyConcat } from "./envelope";

export type VerifierConfig = {
  /** PhoenixKey API base URL. Default: "https://api.phoenixkey.me". */
  phoenixkeyApiUrl?: string;
  /**
   * Upper bound on how long a resolved key may stay in the in-memory cache, ms.
   * Default: 5 minutes. This is a ceiling, never a guarantee — an entry is only
   * cached at all when the resolver can tell whether it is still the live key
   * (see `allowUnidentifiedKeyCache`).
   */
  cacheTtlMs?: number;
  /**
   * Cache keys even when `/identity/{did}/pubkey` returns no `key_id`/`status`.
   * Default: `false`.
   *
   * A response without `key_id` carries no way to notice a rotation, so caching
   * it means a key revoked right now keeps verifying until the TTL runs out —
   * exactly the window a thief needs after the victim rotates. Leaving this
   * `false` trades one lookup per verification for closing that window.
   *
   * Turn it on only when the extra round trip is genuinely unaffordable and the
   * flow is not security-critical. Once the backend ships `key_id` (see
   * PhoenixKey-Database#175) this flag stops mattering: identified keys are
   * cached regardless.
   */
  allowUnidentifiedKeyCache?: boolean;
  /**
   * Accept the legacy `${challenge}:${domain}:${timestamp}` message form in
   * addition to the `PHOENIXKEY_RP_AUTH:v1` envelope. Default: `true` during
   * the migration window.
   *
   * The legacy form is not injective — see `verifyAuthProof`. Turn this off as
   * soon as your callers have moved.
   */
  acceptLegacyEnvelope?: boolean;
};

export type VerifyAuthProofRequest = {
  user_did: string;
  signature: string;
  challenge: string;
  domain: string;
  timestamp: number;
};

export type VerifyIntentRequest = {
  user_did: string;
  intent: SignIntent;
  signature: string;
};

export type VerifyResult = {
  valid: boolean;
  user_did: string;
  /** Reason for failure (if !valid). */
  reason?: string;
  /**
   * Which message form the signature matched (auth-proof flow only).
   * `"legacy"` means the caller has not moved to `PHOENIXKEY_RP_AUTH:v1` yet —
   * log it so the migration is measurable.
   */
  envelope?: "v1" | "legacy";
};

const DEFAULT_CACHE_TTL = 5 * 60 * 1000;
const TIMESTAMP_SKEW_SEC = 60;

/** What `/identity/{did}/pubkey` gives back, once unwrapped from the envelope. */
export type ResolvedKey = {
  publicKeyHex: string;
  /** `authorized_keys.id` — absent until PhoenixKey-Database#175 ships. */
  keyId?: string;
  /** `active` | `revoked` — absent until PhoenixKey-Database#175 ships. */
  status?: string;
};

export class PhoenixKeyVerifier {
  private readonly phoenixkeyApiUrl: string;
  private readonly cache = new Map<string, { key: ResolvedKey; expiresAt: number }>();
  private readonly cacheTtl: number;
  private readonly allowUnidentifiedKeyCache: boolean;
  private readonly acceptLegacyEnvelope: boolean;

  constructor(config: VerifierConfig = {}) {
    this.phoenixkeyApiUrl = (config.phoenixkeyApiUrl ?? "https://api.phoenixkey.me").replace(/\/+$/, "");
    this.cacheTtl = config.cacheTtlMs ?? DEFAULT_CACHE_TTL;
    this.allowUnidentifiedKeyCache = config.allowUnidentifiedKeyCache ?? false;
    this.acceptLegacyEnvelope = config.acceptLegacyEnvelope ?? true;
  }

  /**
   * Verify the auth proof returned from a PhoenixKey login flow.
   *
   * Rebuilds the signed bytes under the `PHOENIXKEY_RP_AUTH:v1` envelope
   * (length-framed, domain-separated — see `RP-AUTH-ENVELOPE.md`) and verifies
   * the signature against the pubkey resolved from `user_did`.
   * Also enforces ±60s timestamp skew.
   *
   * During the migration window this also accepts the legacy
   * `${challenge}:${domain}:${timestamp}` form. That form is NOT injective —
   * `{challenge:"a", domain:"b:c"}` and `{challenge:"a:b", domain:"c"}` build
   * the same bytes, so a signature obtained for one relying party verifies at
   * another. Set `acceptLegacyEnvelope: false` to refuse it once your callers
   * have moved. `VerifyResult.envelope` tells you which form matched, so you
   * can measure the migration instead of guessing.
   */
  async verifyAuthProof(req: VerifyAuthProofRequest): Promise<VerifyResult> {
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - req.timestamp) > TIMESTAMP_SKEW_SEC) {
      return { valid: false, user_did: req.user_did, reason: "timestamp_skew" };
    }

    const v1 = await this.verifySignatureFor(req.user_did, encodeRpAuthV1(req), req.signature);
    if (v1.valid) return { ...v1, envelope: "v1" };
    if (!this.acceptLegacyEnvelope) return v1;

    const legacy = await this.verifySignatureFor(req.user_did, encodeLegacyConcat(req), req.signature);
    // Trả lý do của v1 khi cả hai đều trượt — v1 là khuôn đúng, lý do của nó mới
    // là thứ người tích hợp cần đọc.
    return legacy.valid ? { ...legacy, envelope: "legacy" } : v1;
  }

  /**
   * Verify a signed intent (sign-request flow).
   *
   * Recomputes canonical JSON of the intent (keys sorted, no whitespace),
   * SHA-256 hashes it, then verifies the signature. Caller is responsible for
   * checking nonce uniqueness in their own DB to prevent replay.
   */
  async verifyIntent(req: VerifyIntentRequest): Promise<VerifyResult> {
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - req.intent.timestamp) > TIMESTAMP_SKEW_SEC) {
      return { valid: false, user_did: req.user_did, reason: "timestamp_skew" };
    }
    const messageBytes = canonicalJsonBytes(req.intent);
    return this.verifySignatureFor(req.user_did, messageBytes, req.signature);
  }

  /** Resolve pubkey (cached) — exposed for advanced use cases. */
  async resolvePubkey(userDid: string): Promise<string> {
    return (await this.resolveKey(userDid)).publicKeyHex;
  }

  /**
   * Resolve the full key record — hex, and (when the backend supplies them)
   * `keyId` + `status`.
   *
   * A key is only cached when the response identifies it (`key_id` present),
   * because without an identifier there is nothing to notice a rotation by.
   * A revoked key is rejected outright, never cached, and never verified
   * against.
   */
  async resolveKey(userDid: string): Promise<ResolvedKey> {
    const cached = this.cache.get(userDid);
    if (cached && cached.expiresAt > Date.now()) return cached.key;
    if (cached) this.cache.delete(userDid);

    const key = await this.resolveViaPhoenixKey(userDid);

    if (key.status !== undefined && key.status.toLowerCase() !== "active") {
      throw new PhoenixKeyError({
        status: 200,
        code: "key_revoked",
        message: `Authorized key for ${userDid} is not active (status=${key.status})`,
      });
    }

    // No `keyId` ⇒ a later rotation is invisible to us ⇒ do not hold the key.
    if (key.keyId !== undefined || this.allowUnidentifiedKeyCache) {
      this.cache.set(userDid, { key, expiresAt: Date.now() + this.cacheTtl });
    }
    return key;
  }

  /**
   * Drop a cached key. Call this the moment you learn a DID rotated — a
   * revocation webhook, a failed verification, a support ticket. Returns
   * whether an entry was actually held.
   */
  invalidate(userDid: string): boolean {
    return this.cache.delete(userDid);
  }

  /** Drop every cached key. */
  clearCache(): void {
    this.cache.clear();
  }

  private async verifySignatureFor(
    userDid: string,
    messageBytes: Uint8Array,
    signatureHex: string,
  ): Promise<VerifyResult> {
    let pubkeyHex: string;
    try {
      pubkeyHex = (await this.resolveKey(userDid)).publicKeyHex;
    } catch (e) {
      const code = e instanceof PhoenixKeyError ? e.code : "resolve_failed";
      return {
        valid: false,
        user_did: userDid,
        reason: `${code}: ${e instanceof Error ? e.message : String(e)}`,
      };
    }

    try {
      const msgHash = sha256(messageBytes);
      const valid = p256.verify(hexToBytes(signatureHex), msgHash, hexToBytes(pubkeyHex));
      return { valid, user_did: userDid, reason: valid ? undefined : "signature_invalid" };
    } catch (e) {
      return {
        valid: false,
        user_did: userDid,
        reason: `verify_failed: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  }

  private async resolveViaPhoenixKey(userDid: string): Promise<ResolvedKey> {
    const url = `${this.phoenixkeyApiUrl}/identity/${encodeURIComponent(userDid)}/pubkey`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) {
      throw new PhoenixKeyError({
        status: res.status,
        code: "resolve_failed",
        message: `PhoenixKey pubkey lookup failed: ${res.status}`,
      });
    }
    // Field names on the wire are snake_case — the backend sets
    // `spring.jackson.property-naming-strategy: SNAKE_CASE` globally.
    const body = (await res.json()) as {
      code?: number;
      result?: { public_key_hex?: string; key_id?: string; status?: string };
    };
    const pubkey = body?.result?.public_key_hex;
    if (!pubkey) throw new Error("Empty pubkey in response");
    return {
      publicKeyHex: pubkey,
      keyId: body.result?.key_id,
      status: body.result?.status,
    };
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) throw new Error("Hex length must be even");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Canonical JSON serialization — keys sorted alphabetically at every level,
 * no whitespace. Matches backend `SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS`.
 */
function canonicalJsonBytes(obj: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJsonString(obj));
}

function canonicalJsonString(obj: unknown): string {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj === "number" || typeof obj === "boolean") return JSON.stringify(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalJsonString).join(",")}]`;
  if (typeof obj === "object") {
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    const parts = keys.map((k) => {
      const v = (obj as Record<string, unknown>)[k];
      return v === undefined ? null : `${JSON.stringify(k)}:${canonicalJsonString(v)}`;
    }).filter((p): p is string => p !== null);
    return `{${parts.join(",")}}`;
  }
  return "null";
}
