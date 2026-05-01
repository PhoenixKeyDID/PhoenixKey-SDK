/**
 * @phoenixkeydid/phoenixkey-sdk/verifier
 *
 * Verify-only sub-package for 3rd-party backends. Resolves a user DID's
 * public key, then verifies ECDSA secp256k1 DER signatures locally without
 * touching the PhoenixKey relay server (Path A pattern).
 *
 * Use case: OriLife / AladinWork backend receives `{intent, signature}` from
 * its frontend → calls `verifier.verifyIntent(...)` → trusts the user_did.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { SignIntent, PhoenixKeyError } from "./types";

export type VerifierConfig = {
  /**
   * Resolve pubkey from DID. Two modes:
   * - "phoenixkey" (default): GET {phoenixkeyApiUrl}/identity/{did}/pubkey
   * - "cardano": query Blockfrost directly — no PhoenixKey dependency
   */
  pubkeyResolver?: "phoenixkey" | "cardano";
  /** PhoenixKey API base URL. Default: "https://api.phoenixkey.me". */
  phoenixkeyApiUrl?: string;
  /** Blockfrost project ID (mainnet/preprod). Required if resolver = "cardano". */
  blockfrostKey?: string;
  /** Cardano network. Default: "mainnet". */
  network?: "mainnet" | "preprod";
  /** TTL for in-memory pubkey cache, ms. Default: 5 minutes. */
  cacheTtlMs?: number;
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
};

const DEFAULT_CACHE_TTL = 5 * 60 * 1000;
const TIMESTAMP_SKEW_SEC = 60;

export class PhoenixKeyVerifier {
  private readonly resolver: "phoenixkey" | "cardano";
  private readonly phoenixkeyApiUrl: string;
  private readonly blockfrostKey?: string;
  private readonly network: "mainnet" | "preprod";
  private readonly cache = new Map<string, { pubkey: string; expiresAt: number }>();
  private readonly cacheTtl: number;

  constructor(config: VerifierConfig = {}) {
    this.resolver = config.pubkeyResolver ?? "phoenixkey";
    this.phoenixkeyApiUrl = (config.phoenixkeyApiUrl ?? "https://api.phoenixkey.me").replace(/\/+$/, "");
    this.blockfrostKey = config.blockfrostKey;
    this.network = config.network ?? "mainnet";
    this.cacheTtl = config.cacheTtlMs ?? DEFAULT_CACHE_TTL;

    if (this.resolver === "cardano" && !this.blockfrostKey) {
      throw new Error("blockfrostKey required when pubkeyResolver = 'cardano'");
    }
  }

  /**
   * Verify the auth proof returned from a PhoenixKey login flow.
   *
   * Recomputes the message `${challenge}:${domain}:${timestamp}` and verifies
   * the user's signature against the pubkey resolved from `user_did`.
   * Also enforces ±60s timestamp skew.
   */
  async verifyAuthProof(req: VerifyAuthProofRequest): Promise<VerifyResult> {
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - req.timestamp) > TIMESTAMP_SKEW_SEC) {
      return { valid: false, user_did: req.user_did, reason: "timestamp_skew" };
    }
    const message = `${req.challenge}:${req.domain}:${req.timestamp}`;
    const messageBytes = new TextEncoder().encode(message);
    return this.verifySignatureFor(req.user_did, messageBytes, req.signature);
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
    const cached = this.cache.get(userDid);
    if (cached && cached.expiresAt > Date.now()) return cached.pubkey;

    const pubkey = this.resolver === "phoenixkey"
      ? await this.resolveViaPhoenixKey(userDid)
      : await this.resolveViaCardano(userDid);

    this.cache.set(userDid, { pubkey, expiresAt: Date.now() + this.cacheTtl });
    return pubkey;
  }

  private async verifySignatureFor(
    userDid: string,
    messageBytes: Uint8Array,
    signatureHex: string,
  ): Promise<VerifyResult> {
    let pubkeyHex: string;
    try {
      pubkeyHex = await this.resolvePubkey(userDid);
    } catch (e) {
      return {
        valid: false,
        user_did: userDid,
        reason: `resolve_failed: ${e instanceof Error ? e.message : String(e)}`,
      };
    }

    try {
      const msgHash = sha256(messageBytes);
      const valid = secp256k1.verify(hexToBytes(signatureHex), msgHash, hexToBytes(pubkeyHex));
      return { valid, user_did: userDid, reason: valid ? undefined : "signature_invalid" };
    } catch (e) {
      return {
        valid: false,
        user_did: userDid,
        reason: `verify_failed: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  }

  private async resolveViaPhoenixKey(userDid: string): Promise<string> {
    const url = `${this.phoenixkeyApiUrl}/identity/${encodeURIComponent(userDid)}/pubkey`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) {
      throw new PhoenixKeyError({
        status: res.status,
        code: "resolve_failed",
        message: `PhoenixKey pubkey lookup failed: ${res.status}`,
      });
    }
    const body = (await res.json()) as { code?: number; result?: { public_key_hex: string } };
    const pubkey = body?.result?.public_key_hex;
    if (!pubkey) throw new Error("Empty pubkey in response");
    return pubkey;
  }

  /**
   * Decentralized resolver — read DID Document directly from Cardano via
   * Blockfrost. No PhoenixKey server dependency. Supports the
   * `did:cardano:<network>:<txHash>` format.
   */
  private async resolveViaCardano(userDid: string): Promise<string> {
    const txHash = extractTxHashFromDid(userDid);
    if (!txHash) throw new Error(`Invalid DID format: ${userDid}`);

    const baseUrl = this.network === "mainnet"
      ? "https://cardano-mainnet.blockfrost.io/api/v0"
      : "https://cardano-preprod.blockfrost.io/api/v0";

    const res = await fetch(`${baseUrl}/txs/${txHash}/utxos`, {
      headers: { project_id: this.blockfrostKey! },
    });
    if (!res.ok) throw new Error(`Blockfrost: ${res.status}`);

    const data = (await res.json()) as { outputs: Array<{ inline_datum?: string }> };
    const out = data.outputs.find((o) => o.inline_datum);
    if (!out?.inline_datum) throw new Error("No inline datum in tx");

    // BytesPlutusData CBOR: 5840xxxx (single chunk) or 5fxxxx...ff (chunked).
    // For typical DID docs (small JSON), single chunk pattern dominates.
    const datumJsonBytes = decodeBytesPlutusData(out.inline_datum);
    const doc = JSON.parse(new TextDecoder().decode(datumJsonBytes)) as {
      verificationMethod?: Array<{ publicKeyHex?: string }>;
    };
    const pubkey = doc.verificationMethod?.[0]?.publicKeyHex;
    if (!pubkey) throw new Error("No publicKeyHex in DID Document");
    return pubkey;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const DID_PATTERN = /^did:cardano:[^:]+:([a-f0-9]{64})$/;

function extractTxHashFromDid(did: string): string | null {
  const m = DID_PATTERN.exec(did);
  return m ? m[1] : null;
}

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

/**
 * Decode BytesPlutusData CBOR (tags 24 / single-chunk / chunked).
 * Minimal implementation — handles the patterns CardanoServiceImpl produces:
 * 0x58<len><bytes> (short), 0x59<len_2byte><bytes>, 0x5a<len_4byte><bytes>,
 * or 0x5f<chunk>...<chunk>0xff (indefinite-length).
 */
function decodeBytesPlutusData(hex: string): Uint8Array {
  const buf = hexToBytes(hex);
  let i = 0;
  const first = buf[i++];

  // Indefinite-length byte string: 0x5f ... 0xff
  if (first === 0x5f) {
    const chunks: Uint8Array[] = [];
    while (buf[i] !== 0xff) {
      const chunkHead = buf[i++];
      const len = readCborLen(buf, i, chunkHead - 0x40);
      i += len.bytesRead;
      chunks.push(buf.slice(i, i + len.value));
      i += len.value;
    }
    return concatBytes(chunks);
  }

  // Definite-length byte string: 0x40..0x5b (major type 2)
  if (first >= 0x40 && first < 0x5c) {
    const len = readCborLen(buf, i, first - 0x40);
    return buf.slice(i + len.bytesRead, i + len.bytesRead + len.value);
  }

  throw new Error(`Unsupported CBOR head byte: 0x${first.toString(16)}`);
}

function readCborLen(
  buf: Uint8Array,
  start: number,
  shortVal: number,
): { value: number; bytesRead: number } {
  if (shortVal < 24) return { value: shortVal, bytesRead: 0 };
  if (shortVal === 24) return { value: buf[start], bytesRead: 1 };
  if (shortVal === 25) return { value: (buf[start] << 8) | buf[start + 1], bytesRead: 2 };
  if (shortVal === 26) {
    return {
      value: buf[start] * 0x1_00_00_00 + buf[start + 1] * 0x1_00_00 + buf[start + 2] * 0x1_00 + buf[start + 3],
      bytesRead: 4,
    };
  }
  throw new Error(`CBOR length 8-byte not supported`);
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}
