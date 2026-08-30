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
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { SignIntent, PhoenixKeyError, KeyRole, keyRoleFromClaim } from "./types";

export type VerifierConfig = {
  /** PhoenixKey API base URL. Default: "https://api.phoenixkey.me". */
  phoenixkeyApiUrl?: string;
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
  private readonly phoenixkeyApiUrl: string;
  private readonly cache = new Map<string, { pubkey: string; expiresAt: number }>();
  private readonly cacheTtl: number;

  constructor(config: VerifierConfig = {}) {
    this.phoenixkeyApiUrl = (config.phoenixkeyApiUrl ?? "https://api.phoenixkey.me").replace(/\/+$/, "");
    this.cacheTtl = config.cacheTtlMs ?? DEFAULT_CACHE_TTL;
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

    const pubkey = await this.resolveViaPhoenixKey(userDid);

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

// ─── app_token verification (Path B — token exchange, JWKS) ────────────────────
//
// `PhoenixKeyVerifier` above verifies a USER's own P-256 signature (Path A —
// no server round-trip). `AppTokenVerifier` below verifies the SERVER's
// Ed25519 signature on an `app_token` minted by `POST /auth/token/exchange`
// for a ServiceDID `aud` — the shape a 3rd-party backend actually receives
// after a user completes SSO into it. Different key, different signer,
// different trust question ("did PhoenixKey vouch for this key_role?" vs
// "did this user sign this exact intent?") — kept as a separate class rather
// than overloading `PhoenixKeyVerifier`.

/**
 * Claims carried by an `app_token`, AFTER signature verification.
 *
 * `key_role` is already normalized via {@link keyRoleFromClaim} (fail-safe —
 * see `types.ts`): a token minted before the backend had role claims, or one
 * with a corrupted/unknown role string, comes back `"viewer"` here — read
 * that as "chưa biết vai", not "quyền bị hạn chế cố ý".
 */
export type AppTokenClaims = {
  iss: string;
  sub: string;
  /** ServiceDID this token was minted for. Raw JWT `aud` may be a string or a 1-element array — normalized to string here. */
  aud: string;
  iat: number;
  exp: number;
  nonce?: string;
  /** `authorized_keys.id` of the device key that opened the underlying session, if present. */
  key_id?: string;
  key_role: KeyRole;
};

export type AppTokenVerifierConfig = {
  /** PhoenixKey API base URL. Default: "https://api.phoenixkey.me". */
  phoenixkeyApiUrl?: string;
  /** TTL for in-memory JWKS cache, ms. Default: 1 hour (matches server `Cache-Control`). */
  jwksCacheTtlMs?: number;
};

type Jwk = { kty: string; crv: string; x: string; use?: string; alg?: string; kid?: string };
type Jwks = { keys: Jwk[] };
type JwtHeader = { alg: string; kid?: string; typ?: string };

const DEFAULT_JWKS_CACHE_TTL = 60 * 60 * 1000;

/**
 * Verifies an `app_token` JWT's Ed25519 signature against PhoenixKey's
 * published JWKS (`GET /.well-known/jwks.json`), then returns its claims.
 *
 * **Invariant this class exists to hold: claims are NEVER read before the
 * signature has been verified.** Do not add a "just decode the payload, I
 * trust the caller" shortcut anywhere that touches `key_role` — that claim is
 * what gates owner-only actions on the integrator's own backend, so a forged
 * or tampered token that skips verification is a privilege escalation, not a
 * parsing bug. See `test/appToken.test.ts` for the enforced regression.
 *
 * @example
 * ```ts
 * import { AppTokenVerifier } from "@phoenixkeydid/phoenixkey-sdk/verifier";
 *
 * const verifier = new AppTokenVerifier();
 * const claims = await verifier.verify(appToken, "did:phoenix:svc:orilife");
 * if (!keyRoleAtLeast(claims.key_role, "manager")) {
 *   throw new Error("This session cannot perform signing actions");
 * }
 * ```
 */
export class AppTokenVerifier {
  private readonly phoenixkeyApiUrl: string;
  private readonly jwksCacheTtl: number;
  private cachedJwks: { jwks: Jwks; expiresAt: number } | null = null;

  constructor(config: AppTokenVerifierConfig = {}) {
    this.phoenixkeyApiUrl = (config.phoenixkeyApiUrl ?? "https://api.phoenixkey.me").replace(/\/+$/, "");
    this.jwksCacheTtl = config.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL;
  }

  /**
   * Verify `token`'s signature + expiry (and `aud`, if given), then return
   * its claims. Throws `PhoenixKeyError` on any failure — malformed token,
   * unknown `kid`, bad signature, expired, or `aud` mismatch. Never returns
   * claims for a token that failed verification.
   *
   * @param token        the `app_token` string (3-segment JWT)
   * @param expectedAud  if given, reject tokens minted for a different `aud`
   */
  async verify(token: string, expectedAud?: string): Promise<AppTokenClaims> {
    const { header, payload, signingInput, signature } = splitToken(token);

    if (header.alg !== "EdDSA") {
      throw new PhoenixKeyError({
        status: 0,
        code: "unsupported_alg",
        message: `Unsupported app_token alg: ${header.alg}`,
      });
    }

    const pubkey = await this.resolvePubkey(header.kid);

    let signatureValid: boolean;
    try {
      signatureValid = ed25519.verify(signature, signingInput, pubkey);
    } catch {
      signatureValid = false;
    }
    // ── Gate 1 (mutation-tested): no claim below this line is reachable
    // unless the Ed25519 signature over header+payload verified above. ──
    if (!signatureValid) {
      throw new PhoenixKeyError({
        status: 0,
        code: "signature_invalid",
        message: "app_token signature verification failed",
      });
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = typeof payload.exp === "number" ? payload.exp : undefined;
    // ── Gate 2 (mutation-tested): expired tokens are rejected even though
    // their signature is valid — a verified-but-stale token is still unusable. ──
    if (exp === undefined || now >= exp) {
      throw new PhoenixKeyError({
        status: 0,
        code: "token_expired",
        message: "app_token has expired",
      });
    }

    const audValues = Array.isArray(payload.aud)
      ? payload.aud
      : payload.aud !== undefined
        ? [payload.aud]
        : [];
    if (expectedAud && !audValues.includes(expectedAud)) {
      throw new PhoenixKeyError({
        status: 0,
        code: "aud_mismatch",
        message: "app_token was not minted for the expected aud (ServiceDID)",
      });
    }

    return {
      iss: typeof payload.iss === "string" ? payload.iss : "",
      sub: typeof payload.sub === "string" ? payload.sub : "",
      aud: typeof audValues[0] === "string" ? audValues[0] : "",
      iat: typeof payload.iat === "number" ? payload.iat : 0,
      exp,
      nonce: typeof payload.nonce === "string" ? payload.nonce : undefined,
      key_id: typeof payload.key_id === "string" ? payload.key_id : undefined,
      // Fail-safe normalize — see types.ts docstring. Applies equally to a
      // legit pre-rollout token (no key_role claim at all) and to a token
      // whose key_role claim is some unrecognized string.
      key_role: keyRoleFromClaim(
        typeof payload.key_role === "string" ? payload.key_role : undefined,
      ),
    };
  }

  private async resolvePubkey(kid: string | undefined): Promise<Uint8Array> {
    const jwks = await this.getJwks();
    const key = kid ? jwks.keys.find((k) => k.kid === kid) : jwks.keys[0];
    if (!key) {
      throw new PhoenixKeyError({
        status: 0,
        code: "jwks_key_not_found",
        message: `No JWKS key found for kid=${kid ?? "(none)"}`,
      });
    }
    if (key.kty !== "OKP" || key.crv !== "Ed25519") {
      throw new PhoenixKeyError({
        status: 0,
        code: "jwks_key_not_found",
        message: `Unsupported JWK kty/crv: ${key.kty}/${key.crv}`,
      });
    }
    return base64UrlToBytes(key.x);
  }

  private async getJwks(): Promise<Jwks> {
    if (this.cachedJwks && this.cachedJwks.expiresAt > Date.now()) {
      return this.cachedJwks.jwks;
    }
    const url = `${this.phoenixkeyApiUrl}/.well-known/jwks.json`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) {
      throw new PhoenixKeyError({
        status: res.status,
        code: "jwks_fetch_failed",
        message: `JWKS fetch failed: HTTP ${res.status}`,
      });
    }
    const jwks = (await res.json()) as Jwks;
    this.cachedJwks = { jwks, expiresAt: Date.now() + this.jwksCacheTtl };
    return jwks;
  }
}

function splitToken(token: string): {
  header: JwtHeader;
  payload: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
} {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new PhoenixKeyError({
      status: 0,
      code: "malformed_token",
      message: "app_token must have exactly 3 JWT segments",
    });
  }
  const [headerB64, payloadB64, sigB64] = parts;

  let header: JwtHeader;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(base64UrlToUtf8(headerB64)) as JwtHeader;
    payload = JSON.parse(base64UrlToUtf8(payloadB64)) as Record<string, unknown>;
  } catch {
    throw new PhoenixKeyError({
      status: 0,
      code: "malformed_token",
      message: "app_token header/payload is not valid JSON",
    });
  }

  return {
    header,
    payload,
    // JWS signing input is the exact ASCII bytes of `${header}.${payload}`
    // BEFORE any decoding — not a re-serialization of the parsed JSON.
    signingInput: new TextEncoder().encode(`${headerB64}.${payloadB64}`),
    signature: base64UrlToBytes(sigB64),
  };
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replaceAll("-", "+").replaceAll("_", "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  if (typeof atob === "function") {
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  const NodeBuffer = (globalThis as { Buffer?: { from(s: string, enc: string): Uint8Array } }).Buffer;
  if (!NodeBuffer) {
    throw new Error("base64UrlToBytes: no atob or Buffer available");
  }
  return new Uint8Array(NodeBuffer.from(padded, "base64"));
}

function base64UrlToUtf8(b64url: string): string {
  return new TextDecoder().decode(base64UrlToBytes(b64url));
}
