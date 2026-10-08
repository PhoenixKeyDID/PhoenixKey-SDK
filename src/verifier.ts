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
import { SignIntent, PhoenixKeyError, IdentityPubkey, KeyRole, keyRoleFromClaim } from "./types";
import { encodeRpAuthV1, encodeLegacyConcat } from "./envelope";

export type VerifierConfig = {
  /**
   * PhoenixKey API base URL, including the `/api/v1` context path.
   * Default: "https://api.phoenixkey.me/api/v1".
   *
   * The backend serves every route under `/api/v1`; the bare origin returns 404.
   */
  phoenixkeyApiUrl?: string;
  /**
   * TTL for in-memory key cache, ms. **Default: `0` — no caching.**
   *
   * The revocation gate rejects a key the *server* reports as revoked, but a
   * cached entry was fetched while the key was still active, so it carries
   * `status: "active"` and passes the gate. Any TTL above zero is therefore a
   * window in which a key the user has already rotated away still verifies.
   *
   * That window sits exactly on the event it matters for: people rotate keys
   * **after** a compromise. A default of five minutes spent that window on the
   * victim to save the integrator a network call. The default now runs the
   * other way — correctness first, and caching is opted into knowingly:
   *
   * ```ts
   * new PhoenixKeyVerifier({ cacheTtlMs: 30_000 })  // 30s window, eyes open
   * ```
   *
   * Set it only if the extra `GET /identity/{did}/pubkey` per verify is
   * measurably too expensive, and size it against how long you are willing to
   * accept a stolen key after its owner has already replaced it.
   */
  cacheTtlMs?: number;
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

/**
 * No cache by default — see `cacheTtlMs`. A stale entry keeps a rotated-away key
 * verifying for the length of the TTL, and this is a verifier: the safe value is
 * the one that costs a request, not the one that costs a compromise.
 */
const DEFAULT_CACHE_TTL = 0;
const TIMESTAMP_SKEW_SEC = 60;

export class PhoenixKeyVerifier {
  private readonly phoenixkeyApiUrl: string;
  private readonly cache = new Map<string, { key: IdentityPubkey; expiresAt: number }>();
  private readonly cacheTtl: number;
  private readonly acceptLegacyEnvelope: boolean;

  constructor(config: VerifierConfig = {}) {
    this.phoenixkeyApiUrl = (config.phoenixkeyApiUrl ?? "https://api.phoenixkey.me/api/v1").replace(/\/+$/, "");
    this.cacheTtl = config.cacheTtlMs ?? DEFAULT_CACHE_TTL;
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

    // Tra khoá MỘT lần rồi thử từng khuôn trên chính khoá đó. Nếu để mỗi khuôn
    // tự tra, thì với `cacheTtlMs: 0` — cấu hình mà một hệ cần thu hồi lan ngay
    // sẽ đặt — mỗi lượt verify thành HAI lượt gọi mạng, và không ai thấy vì
    // kết quả vẫn đúng.
    const resolved = await this.resolveForVerify(req.user_did);
    if ("failure" in resolved) return resolved.failure;
    const key = resolved.key;

    const v1 = this.verifyWithKey(key, req.user_did, encodeRpAuthV1(req), req.signature);
    if (v1.valid) return { ...v1, envelope: "v1" };
    if (!this.acceptLegacyEnvelope) return v1;

    const legacy = this.verifyWithKey(key, req.user_did, encodeLegacyConcat(req), req.signature);
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
    const resolved = await this.resolveForVerify(req.user_did);
    if ("failure" in resolved) return resolved.failure;
    return this.verifyWithKey(resolved.key, req.user_did, canonicalJsonBytes(req.intent), req.signature);
  }

  /**
   * Resolve bản ghi khoá đầy đủ (có bộ nhớ đệm) — gồm cả `status`/`revoked_at`.
   *
   * KHÔNG lọc theo trạng thái: trả đúng thứ máy chủ trả, kể cả khoá đã thu hồi.
   * Bên gọi tự quyết. Muốn thứ đã lọc thì dùng {@link resolvePubkey}.
   */
  async resolveKey(userDid: string): Promise<IdentityPubkey> {
    const cached = this.cache.get(userDid);
    if (cached && cached.expiresAt > Date.now()) return cached.key;

    const key = await this.resolveViaPhoenixKey(userDid);

    if (this.cacheTtl > 0) {
      this.cache.set(userDid, { key, expiresAt: Date.now() + this.cacheTtl });
    }
    return key;
  }

  /**
   * Resolve pubkey hex của khoá owner hiện hành — exposed for advanced use cases.
   *
   * **Ném lỗi khi khoá đã bị thu hồi.** Máy chủ trả 200 cho khoá đã thu hồi
   * (để phân biệt với DID chưa từng tồn tại), nên trả thẳng chuỗi hex ở đây
   * mà không xét trạng thái sẽ khiến bên gọi verify hợp lệ một chữ ký ký
   * bằng khoá đã mất. Cần bản ghi thô thì gọi {@link resolveKey}.
   */
  async resolvePubkey(userDid: string): Promise<string> {
    const key = await this.resolveKey(userDid);
    assertKeyUsable(key);
    return key.public_key_hex;
  }

  /**
   * Tra khoá và chạy cổng thu hồi. Trả về khoá dùng được, hoặc lý do trượt.
   *
   * Tách khỏi phần kiểm chữ ký để người gọi thử được NHIỀU khuôn ký trên cùng
   * một lượt tra, thay vì tra lại mỗi khuôn.
   */
  private async resolveForVerify(
    userDid: string,
  ): Promise<{ key: IdentityPubkey } | { failure: VerifyResult }> {
    let key: IdentityPubkey;
    try {
      key = await this.resolveKey(userDid);
    } catch (e) {
      return {
        failure: {
          valid: false,
          user_did: userDid,
          reason: `resolve_failed: ${e instanceof Error ? e.message : String(e)}`,
        },
      };
    }
    // Khoá đã thu hồi vẫn trả 200 kèm status — không xét ở đây thì một khoá
    // bị mất vẫn ký hợp lệ được sau khi chủ DID đã thu hồi nó.
    if (!isKeyUsable(key)) {
      return {
        failure: {
          valid: false,
          user_did: userDid,
          reason: key.revoked_at ? `key_revoked: ${key.revoked_at}` : "key_revoked",
        },
      };
    }
    return { key };
  }

  /** Kiểm chữ ký trên một khoá ĐÃ tra và ĐÃ qua cổng thu hồi. Không gọi mạng. */
  private verifyWithKey(
    key: IdentityPubkey,
    userDid: string,
    messageBytes: Uint8Array,
    signatureHex: string,
  ): VerifyResult {
    const pubkeyHex = key.public_key_hex;

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

  private async resolveViaPhoenixKey(userDid: string): Promise<IdentityPubkey> {
    const url = `${this.phoenixkeyApiUrl}/identity/${encodeURIComponent(userDid)}/pubkey`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) {
      throw new PhoenixKeyError({
        status: res.status,
        code: "resolve_failed",
        message: `PhoenixKey pubkey lookup failed: ${res.status}`,
      });
    }
    const body = (await res.json()) as { code?: number; result?: IdentityPubkey };
    const key = body?.result;
    if (!key?.public_key_hex) throw new Error("Empty pubkey in response");
    return key;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Khoá dùng được để verify hay không.
 *
 * Đóng mặc định theo hướng an toàn: chỉ `status === "active"` mới qua. Máy chủ
 * khai `status` chỉ có hai giá trị `active`/`revoked` và không bao giờ null;
 * một giá trị lạ (bản máy chủ cũ hơn, proxy cắt trường) được coi là KHÔNG dùng
 * được, vì đoán sai theo hướng kia là chấp nhận chữ ký của khoá đã mất.
 */
function isKeyUsable(key: IdentityPubkey): boolean {
  return key.status === "active";
}

function assertKeyUsable(key: IdentityPubkey): void {
  if (isKeyUsable(key)) return;
  throw new PhoenixKeyError({
    status: 200,
    code: "key_revoked",
    message: key.revoked_at
      ? `Owner key was revoked at ${key.revoked_at}`
      : `Owner key is not active (status=${String(key.status)})`,
  });
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
  /**
   * PhoenixKey API base URL, **including the `/api/v1` context path**.
   * Default: `"https://api.phoenixkey.me/api/v1"` — same shape as
   * {@link VerifierConfig.phoenixkeyApiUrl}.
   *
   * The context path is not optional. Every route the backend serves lives
   * under `/api/v1`, JWKS included; the bare origin returns 404. Measured
   * 2026-09-08 against production:
   *
   * ```
   * GET https://api.phoenixkey.me/api/v1/.well-known/jwks.json → 200 {"keys":[…]}
   * GET https://api.phoenixkey.me/.well-known/jwks.json         → 404
   * ```
   *
   * The old default here was the bare origin, so an integrator who
   * constructed `new AppTokenVerifier()` — exactly what the docs told them to
   * write — could never verify a single `app_token`: every call died at
   * `jwks_fetch_failed`. That is the last link of the login handover, so the
   * whole capability was dark for anyone using the default.
   *
   * RFC 8615 does want `.well-known` at the domain root, and one day an nginx
   * rewrite may put it there. Until that rewrite exists **and is measured**,
   * this default points at the path that actually answers.
   */
  phoenixkeyApiUrl?: string;
  /** TTL for in-memory JWKS cache, ms. Default: 1 hour (matches server `Cache-Control`). */
  jwksCacheTtlMs?: number;
  /**
   * Key pinning: RFC 7638 SHA-256 thumbprints (base64url, 43 chars) of the
   * JWKs you trust. Compute them with {@link ed25519JwkThumbprint}, from a
   * JWKS you checked OUT OF BAND (not from the same HTTPS fetch the verifier
   * makes).
   *
   * When set, any JWK in the downloaded JWKS whose thumbprint is not listed is
   * ignored, and a token whose `kid` points only at such a key is rejected
   * with `jwks_key_not_pinned` — there is no fallback to another key.
   *
   * Why: TLS ends at the CDN edge. A bad or coerced CDN can serve a JWKS with
   * an extra attacker `kid`, and the attacker then mints `app_token`s for any
   * DID. Pinning takes the CDN (and the network path) out of the trust base
   * for key selection.
   *
   * An empty array is a configuration error and throws at construction: an
   * empty list that silently let everything through would look identical to
   * "pinned". Omit the option to keep the legacy trust-the-JWKS behaviour
   * (a one-time warning is emitted on first use).
   */
  pinnedJwkThumbprints?: string[];
  /**
   * Receives the one-time "no key pinning" warning. Default: `console.warn`.
   * Pass your own logger, or `() => {}` to acknowledge the risk and silence it.
   */
  onWarning?: (message: string) => void;
};

type Jwk = { kty: string; crv: string; x: string; use?: string; alg?: string; kid?: string };
type Jwks = { keys: Jwk[] };
type JwtHeader = { alg: string; kid?: string; typ?: string };

const DEFAULT_JWKS_CACHE_TTL = 60 * 60 * 1000;

/** SHA-256 digest, base64url without padding = always 43 chars. */
const THUMBPRINT_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * RFC 7638 JWK thumbprint (SHA-256, base64url) of an OKP/Ed25519 public JWK.
 *
 * Hashes the UTF-8 bytes of `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` — the
 * required members only, in lexicographic order, no whitespace. `kid`, `use`
 * and `alg` do NOT enter the hash, so the thumbprint identifies the key
 * material and cannot be reassigned by relabelling.
 *
 * Throws `PhoenixKeyError` (`invalid_jwk`) if the input is not an Ed25519 OKP
 * JWK with a base64url `x`.
 *
 * ```ts
 * ed25519JwkThumbprint({ kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" })
 * // → "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"   (RFC 8037 Appendix A.3)
 * ```
 */
export function ed25519JwkThumbprint(jwk: { kty: string; crv: string; x: string }): string {
  if (
    jwk === null ||
    typeof jwk !== "object" ||
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    typeof jwk.x !== "string" ||
    !/^[A-Za-z0-9_-]+$/.test(jwk.x)
  ) {
    throw new PhoenixKeyError({
      status: 0,
      code: "invalid_jwk",
      message: "ed25519JwkThumbprint expects an OKP/Ed25519 JWK with a base64url 'x'",
    });
  }
  // Built by hand, not JSON.stringify(jwk): the member order and the absence
  // of other members are exactly what RFC 7638 §3.2 pins down.
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`;
  return bytesToBase64Url(sha256(new TextEncoder().encode(canonical)));
}

/**
 * Đường mặc định tới JWKS — GỒM context-path `/api/v1`.
 *
 * Tách thành hằng số có tên để bài kiểm ghim được đúng CHUỖI này (xem
 * `test/jwksUrl.test.ts`), chứ không ghim tên hàm dựng URL. Ghim tên thì đổi
 * chuỗi vẫn xanh, mà chuỗi mới là thứ quyết định lượt gọi đi tới đâu.
 */
export const DEFAULT_PHOENIXKEY_API_URL = "https://api.phoenixkey.me/api/v1";

/** Hậu tố JWKS ghép sau `phoenixkeyApiUrl`. */
export const JWKS_PATH = "/.well-known/jwks.json";

/**
 * Verifies an `app_token` JWT's Ed25519 signature against PhoenixKey's
 * published JWKS (`GET /api/v1/.well-known/jwks.json` — the context path is
 * part of the address, see {@link AppTokenVerifierConfig.phoenixkeyApiUrl}),
 * then returns its claims.
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
  private readonly pinned: ReadonlySet<string> | null;
  private readonly onWarning: (message: string) => void;
  private warnedUnpinned = false;
  private cachedJwks: { jwks: Jwks; expiresAt: number } | null = null;

  constructor(config: AppTokenVerifierConfig = {}) {
    this.phoenixkeyApiUrl = (config.phoenixkeyApiUrl ?? DEFAULT_PHOENIXKEY_API_URL).replace(/\/+$/, "");
    this.jwksCacheTtl = config.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL;
    this.onWarning = config.onWarning ?? ((m) => console.warn(m));

    // `undefined` = not pinning (legacy). ANY other value must be a valid,
    // non-empty list — `null`, `[]`, a string or a malformed entry throws
    // here rather than degrading to "no pinning" while looking pinned.
    const pins = config.pinnedJwkThumbprints;
    if (pins === undefined) {
      this.pinned = null;
    } else {
      if (!Array.isArray(pins) || pins.length === 0) {
        throw new PhoenixKeyError({
          status: 0,
          code: "invalid_pinned_thumbprints",
          message:
            "pinnedJwkThumbprints must be a non-empty array of RFC 7638 thumbprints. " +
            "An empty list would accept nothing (or, worse, be mistaken for 'pinned'); " +
            "omit the option to run without pinning.",
        });
      }
      for (const t of pins) {
        if (typeof t !== "string" || !THUMBPRINT_PATTERN.test(t)) {
          throw new PhoenixKeyError({
            status: 0,
            code: "invalid_pinned_thumbprints",
            message:
              "pinnedJwkThumbprints entries must be 43-char base64url SHA-256 thumbprints " +
              "(see ed25519JwkThumbprint)",
          });
        }
      }
      this.pinned = new Set(pins);
    }
  }

  /**
   * Verify `token`'s signature, expiry **and `aud`**, then return its claims.
   * Throws `PhoenixKeyError` on any failure — malformed token, missing or
   * unknown `kid`, bad signature, expired, or `aud` mismatch. Never returns
   * claims for a token that failed verification.
   *
   * `expectedAud` is REQUIRED. It used to be optional, and that was a
   * dangerous default: a caller who wrote `verify(token)` type-checked fine,
   * got no warning, and silently ran with the audience gate switched off. A
   * token is minted for ONE service — without this check, service B accepts a
   * token minted for service A and logs the attacker in as A's user. Pass your
   * own ServiceDID here; it is the only value that makes this token yours.
   *
   * If you genuinely cannot bind an audience, call
   * {@link verifyWithoutAudience} instead — so that the choice is visible at
   * the call site and in review, rather than hidden in an omitted argument.
   *
   * @param token        the `app_token` string (3-segment JWT)
   * @param expectedAud  your ServiceDID — tokens minted for any other `aud`
   *                     are rejected
   */
  async verify(token: string, expectedAud: string): Promise<AppTokenClaims> {
    // Runtime guard, not just a type: this package ships to plain JavaScript
    // callers too, where the compiler never runs and `verify(token)` would
    // otherwise sail straight through with the gate off.
    if (typeof expectedAud !== "string" || expectedAud.length === 0) {
      throw new PhoenixKeyError({
        status: 0,
        code: "expected_aud_required",
        message:
          "verify() requires expectedAud (your ServiceDID). To skip the audience check deliberately, call verifyWithoutAudience().",
      });
    }
    return this.verifyInternal(token, expectedAud);
  }

  /**
   * Verify signature + expiry but **not** `aud`. Only correct when the caller
   * has some other binding that ties the token to itself; otherwise any token
   * minted for any service is accepted, including one obtained by luring the
   * user into signing in to an attacker's service.
   *
   * Named so the omission is legible: a reader of the call site can see the
   * audience check is off without opening this file.
   */
  async verifyWithoutAudience(token: string): Promise<AppTokenClaims> {
    return this.verifyInternal(token, undefined);
  }

  private async verifyInternal(token: string, expectedAud?: string): Promise<AppTokenClaims> {
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
    if (this.pinned === null && !this.warnedUnpinned) {
      this.warnedUnpinned = true;
      this.onWarning(
        "[PhoenixKey AppTokenVerifier] No key pinning: signing keys are trusted from the JWKS " +
          "fetched over HTTPS. A CDN or network path that serves an extra kid lets an attacker " +
          "mint app_tokens. Set pinnedJwkThumbprints (see ed25519JwkThumbprint).",
      );
    }
    // `kid` is required. The old fallback to `keys[0]` meant a token carrying
    // no `kid` was checked against whichever key happened to come first in a
    // JSON array served by the API — so the outcome depended on the server's
    // response ordering rather than on the token. Today the JWKS holds one
    // key and the two behaviours coincide; the first signing-key rotation
    // puts a second key in that array and they stop coinciding, silently.
    // Every token this verifier accepts (alg=EdDSA) is minted with a `kid`.
    if (!kid) {
      throw new PhoenixKeyError({
        status: 0,
        code: "jwks_key_not_found",
        message: "app_token header is missing kid — cannot select a JWKS key",
      });
    }
    let candidates = jwks.keys;
    if (this.pinned !== null) {
      const pinned = this.pinned;
      // Filter BEFORE selecting by kid, so a duplicate kid planted ahead of
      // the real key cannot shadow it, and a key that is not pinned is never
      // a candidate at all.
      candidates = jwks.keys.filter((k) => isPinned(k, pinned));
      if (!candidates.some((k) => k.kid === kid) && jwks.keys.some((k) => k.kid === kid)) {
        throw new PhoenixKeyError({
          status: 0,
          code: "jwks_key_not_pinned",
          message:
            `JWKS key kid=${kid} is not in pinnedJwkThumbprints — refusing to use it. ` +
            `If PhoenixKey rotated its signing key, verify the new JWKS out of band and ` +
            `add its thumbprint; otherwise the JWKS you were served may be forged.`,
        });
      }
    }
    const key = candidates.find((k) => k.kid === kid);
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
    const url = `${this.phoenixkeyApiUrl}${JWKS_PATH}`;
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) {
      throw new PhoenixKeyError({
        status: res.status,
        code: "jwks_fetch_failed",
        // Nói ra ĐƯỜNG đã gọi, và nêu nghi phạm số một khi là 404. Bản trước
        // chỉ nói "HTTP 404" — người tích hợp không có cách nào biết là mình
        // thiếu context-path `/api/v1`, vì họ có gõ đường nào đâu, họ dùng mặc
        // định. Một lỗi không tự chỉ ra được chỗ sửa thì tốn hàng giờ.
        message:
          `JWKS fetch failed: HTTP ${res.status} tại ${url}` +
          (res.status === 404
            ? ` — kiểm tra 'phoenixkeyApiUrl' đã kèm context-path chưa. ` +
              `Máy chủ phục vụ MỌI tuyến dưới '/api/v1'; gốc miền trần trả 404. ` +
              `Mặc định đúng: '${DEFAULT_PHOENIXKEY_API_URL}'.`
            : ""),
      });
    }
    const jwks = (await res.json()) as Jwks;
    // Hỏng-đóng: một phản hồi 200 mà không có mảng `keys` (proxy trả trang lỗi,
    // bản máy chủ khác khuôn) sẽ làm `resolvePubkey` ném TypeError trần —
    // không đọc ra được nguyên nhân, và thứ hỏng lại bị ĐỆM nguyên một giờ.
    if (!Array.isArray(jwks?.keys)) {
      throw new PhoenixKeyError({
        status: res.status,
        code: "jwks_fetch_failed",
        message: `JWKS tại ${url} trả 200 nhưng thân không có mảng 'keys'`,
      });
    }
    this.cachedJwks = { jwks, expiresAt: Date.now() + this.jwksCacheTtl };
    return jwks;
  }
}

function isPinned(key: Jwk, pinned: ReadonlySet<string>): boolean {
  try {
    return pinned.has(ed25519JwkThumbprint(key));
  } catch {
    // Not an Ed25519 OKP JWK (or malformed): it can never match a pin.
    return false;
  }
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 =
    typeof btoa === "function"
      ? btoa(bin)
      : (globalThis as { Buffer: { from(s: string, enc: string): { toString(enc: string): string } } }).Buffer.from(
          bin,
          "binary",
        ).toString("base64");
  return b64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
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
