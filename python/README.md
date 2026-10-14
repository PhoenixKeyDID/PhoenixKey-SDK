# phoenixkey-sdk (Python)

Verify-only Python client for **PhoenixKey** identity. It lets a Python backend check
a PhoenixKey signature without re-implementing the rules: which key counts, which role
may sign, what the signed bytes are. Those rules live in this SDK, and the Python code
returns the **same result as the TypeScript package** on the same input. That claim is
tested, not asserted: `tests/vectors/vectors.json` is produced by running the TypeScript
code (see [Cross-language vectors](#cross-language-vectors)).

What it covers:

| You receive | Use |
|---|---|
| `{intent, signature}` from a sign-request flow | `PhoenixKeyVerifier.verify_intent` |
| `{user_did, signature, challenge, domain, timestamp}` from a login flow | `PhoenixKeyVerifier.verify_auth_proof` |
| an `app_token` (JWT) after SSO into your service | `AppTokenVerifier.verify` |

It does **not** start login or sign flows (QR, SSE, sessions); that stays in the
TypeScript client. It is synchronous; in an async server run it in a worker thread.

## Install

Requires Python 3.10+. The only runtime dependency is [`cryptography`](https://pypi.org/project/cryptography/).

```bash
pip install "git+https://github.com/PhoenixKeyDID/PhoenixKey-SDK.git#subdirectory=python"
# or, from a checkout:
pip install ./python
```

## Verify a signed intent

```python
from phoenixkey_sdk import PhoenixKeyVerifier

verifier = PhoenixKeyVerifier()   # https://api.phoenixkey.me/api/v1

result = verifier.verify_intent(
    user_did=user_did,
    intent=intent,                       # the dict the user signed
    signature=signature_hex,             # compact r||s or DER, hex
    public_key_hex=signed_event["public_key_hex"],   # see below
)

if not result.valid:
    raise PermissionError(result.reason)   # e.g. "signature_invalid"
# result.user_did is now trustworthy. Still check intent["nonce"] for replay in YOUR store.
```

`intent` has the fields `type`, `body`, `domain`, `nonce`, `timestamp` (epoch seconds),
`display_text` and optionally `app_id`. The signed bytes are its canonical JSON
(keys sorted at every level, no whitespace), hashed with SHA-256; the Python canonicalizer
matches the TypeScript bytes exactly, including key order for non-BMP characters and
JavaScript's number formatting.

### Several devices: pass `public_key_hex`

A DID can have several owner keys at once (one per device). Without a hint the verifier
only knows the **newest** owner key, so a signature from another device is rejected.
Pass the `public_key_hex` carried by the `signed` event and the verifier asks the
server for exactly that key (`GET /identity/{did}/pubkey?key=<hex>`).

The hint is only used to look up. The signature is always checked against the key the
server returns for that exact (DID, key), and the lookup is refused when:

* the key is not `active` (`key_revoked`),
* its role is not `owner` (`key_role_not_owner`),
* the server returns a different key from the one asked for (`key_mismatch`),
* the server answers 404 for the key (`resolve_failed: ...404`). It never falls back to
  the newest key.

## Verify a login proof

```python
result = verifier.verify_auth_proof(
    user_did=user_did,
    signature=signature_hex,
    challenge=challenge,
    domain="example.com",
    timestamp=timestamp,
)
```

The signed bytes follow the `PHOENIXKEY_RP_AUTH:v1` envelope (length-framed, domain
separated, see `RP-AUTH-ENVELOPE.md` in the repository root). While you migrate, the
legacy `challenge:domain:timestamp` form is also accepted (`result.envelope == "legacy"`);
it is not injective, so turn it off as soon as callers have moved:
`PhoenixKeyVerifier(accept_legacy_envelope=False)`.

**Limitation (same as the TypeScript SDK):** `verify_auth_proof` has no
`public_key_hex` parameter. It checks the signature against the **newest owner key** of
the DID only. A login signed by an older, still-active device key is reported as
`signature_invalid`.

## Verify an `app_token`

```python
from phoenixkey_sdk import AppTokenVerifier, PhoenixKeyError, key_role_at_least

# Pin the server's signing key(s): thumbprints computed from a JWKS you checked out of band.
# (The value below is the RFC 8037 sample key's thumbprint -- replace it with your own.)
tokens = AppTokenVerifier(pinned_jwk_thumbprints=["kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"])
try:
    claims = tokens.verify(app_token, expected_aud="did:phoenix:svc:your-service")
except PhoenixKeyError as e:
    ...  # e.code: malformed_token | unsupported_alg | jwks_fetch_failed |
         #         jwks_key_not_found | jwks_key_not_pinned | signature_invalid |
         #         token_expired | aud_mismatch

if not key_role_at_least(claims.key_role, "manager"):
    raise PermissionError("this session cannot perform signing actions")
```

* The Ed25519 signature is checked against the JWKS key whose `kid` equals the token's
  `kid`. A token without `kid` is rejected; there is no "use the first key" fallback.
* Claims are returned only after the signature, expiry and audience have all passed.
* `expected_aud` is required and must be your own ServiceDID. Use
  `verify_without_audience` only if you bind the token to yourself another way.
* `key_role` is normalised fail-safe: missing or unknown becomes `"viewer"`.
* **Pin the signing key.** TLS ends at the CDN edge: a bad or coerced CDN can serve a JWKS
  with an extra `kid`, and its holder then mints `app_token`s for any DID. Pass
  `pinned_jwk_thumbprints=[...]`, the RFC 7638 SHA-256 thumbprints (43-char base64url) of the
  keys you trust, computed with `ed25519_jwk_thumbprint(jwk)` from a JWKS you verified out of
  band. Every JWK whose thumbprint is not listed is ignored (the filter runs before the
  `kid` lookup, so a duplicate `kid` cannot shadow the real key); a token whose `kid` points
  only at an unlisted key fails with `jwks_key_not_pinned`, with no fall-back to another key.
  After a signing-key rotation, add the new thumbprint (keep the old one while old tokens
  live). An empty list, a non-list value or a malformed entry raises
  `PhoenixKeyError(code="invalid_pinned_thumbprints")` at construction.
* Without pinning the verifier still trusts the JWKS it downloads, and the first
  verification emits a one-time `UserWarning` (once per verifier). Route it with
  `on_warning=callable`, or acknowledge the risk with `on_warning=lambda message: None`.

## Behaviour you should know

* **No key cache by default** (`cache_ttl_ms=0`). A cached key keeps verifying after its
  owner revoked it. Raise it only if you accept that window: `PhoenixKeyVerifier(cache_ttl_ms=30_000)`.
  The JWKS is cached one hour (`jwks_cache_ttl_ms`).
* **`reason` strings are the TypeScript ones**: `timestamp_skew` (more than 60 s from your
  clock), `resolve_failed: <detail>`, `key_revoked[: <time>]`, `key_role_not_owner`,
  `key_mismatch`, `signature_invalid`, `verify_failed: <detail>`.
* The API base must include the `/api/v1` context path (that is the default).

## Own HTTP stack, own clock

HTTP uses `urllib` (http and https only, 10 s timeout, bodies capped at 1 MiB). To use
your own client, or to test, pass a function `(url, headers) -> HttpResponse`:

```python
from phoenixkey_sdk import HttpResponse, PhoenixKeyVerifier

def fetch(url: str, headers: dict[str, str]) -> HttpResponse:
    r = my_session.get(url, headers=headers, timeout=5)
    return HttpResponse(r.status_code, r.content)

verifier = PhoenixKeyVerifier(fetch=fetch, clock=time.time)
```

Return the HTTP status as it is (including 404 and 5xx); raise only when there was no
response at all.

## Differences from the TypeScript package

Every case in `tests/vectors/vectors.json` gives the same result as the TypeScript code.
Outside those vectors the two differ in the places below. Most are on input the TypeScript
types forbid, where this package fails closed with `valid=False` and a `reason`; the exceptions
(valid input that behaves differently) are the stricter Ed25519 and the integer limit on intents.
For the kinds of bad input named below, the verify methods return a failed result instead
of raising.

* `verify_auth_proof` with a `user_did`, `domain` or `challenge` that is not a `str` returns
  `verify_failed: <field> must be a string, ...` before any lookup. TypeScript coerces the
  value to text and ends in `signature_invalid`.
* `verify_intent` returns `verify_failed: ...` for an intent that holds a non-finite float
  (`NaN`, `Infinity`), an integer outside +-2**53, a value JSON cannot carry (`bytes`, `set`,
  a non-string key) or nesting deeper than the interpreter's recursion limit (a few hundred
  levels). A JSON parser in JavaScript would round the large integer to a double (or to `null`
  past 1.8e308) and verify those bytes; this package refuses to check a signature over bytes
  that may differ from what the signer meant. `canonical_json_bytes` on its own keeps the
  JavaScript rendering unless you pass `strict=True`.
* A `public_key_hex` that is not a `str` makes `verify_intent` return `resolve_failed:
  hex value must be a string, ...` without a request; `resolve_key` and `resolve_pubkey` raise
  `TypeError`. TypeScript throws there too.
* A missing, non-numeric or non-finite `intent["timestamp"]` (`NaN`, `Infinity`, which
  `json.loads` accepts as bare tokens) is `timestamp_skew` here; TypeScript lets it through the
  skew check (`NaN` compares false). A verifier should fail closed.
* `verify_auth_proof` returns `timestamp_skew` for a `timestamp` that is not a finite
  non-negative whole number (`NaN`, a string, `100.5`) instead of raising from the envelope
  encoder. TypeScript's argument is typed `number`; there it would throw `RangeError` or pass
  the skew check.
* Key pinning follows the TypeScript `pinnedJwkThumbprints` / `ed25519JwkThumbprint` /
  `jwks_key_not_pinned` / `invalid_pinned_thumbprints` exactly, with two spellings that do not
  carry over: `None` (the default) means "option omitted", where TypeScript distinguishes
  `undefined` (omitted) from `null` (error); and the one-time warning goes to
  `warnings.warn` (`UserWarning`) instead of `console.warn`. `on_warning` is the same hook as
  `onWarning`.
* The detail text of `resolve_failed: ...` (network errors, unparseable JSON) and of an
  undecodable `app_token` signature segment differs by runtime. The prefix and the error
  `code` are the same.
* Ed25519 uses OpenSSL (RFC 8032). The TypeScript library accepts a few non-canonical
  encodings (ZIP-215) that OpenSSL refuses; Python is the stricter of the two.
* `canonical_json_bytes` raises `TypeError` for types JSON cannot represent (and for non-string
  keys) instead of printing `null`.

## Cross-language vectors

`tests/vectors/generate.cjs` compiles the TypeScript sources of this repository, runs the
real `PhoenixKeyVerifier` and `AppTokenVerifier` against a scripted `fetch` and a frozen
clock, and writes `tests/vectors/vectors.json`: key material derived from fixed labels
(P-256 and Ed25519), canonical bytes, signatures, the HTTP exchanges, and the result the
TypeScript code produced. The canonical bytes are read from the buffer the TypeScript
verifier hashes, not recomputed. Negative cases include revoked and viewer keys,
`key_mismatch`, 404 with a key hint, unknown `kid`, wrong audience, expired tokens and
single-bit signature corruption. Key pinning has its own cases (an extra `kid` injected into the
JWKS, a duplicate `kid` placed ahead of the real key, rotation, invalid pin lists) and the
RFC 8037 Appendix A.3 thumbprint vector.

```bash
npm install                                  # once, repository root
node python/tests/vectors/generate.cjs       # regenerate; review the diff
cd python && python -m pytest                # replay
```

When the TypeScript rules change, regenerate the vectors in the same change; a failing
Python test then shows exactly which behaviour moved.
