"""Verification of the ``app_token`` a PhoenixKey server mints for a ServiceDID.

``PhoenixKeyVerifier`` checks a *user's* own signature. This module checks the
*server's* Ed25519 signature on an ``app_token`` (JWT, ``alg=EdDSA``) obtained from
``POST /auth/token/exchange``, using the server's published JWKS. Different key,
different signer, different question -- so it is a separate class.

Invariant: **claims are never read before the signature has verified.** The
``key_role`` claim gates owner-only actions in your backend; a token that skipped
verification would be a privilege escalation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
import warnings
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ._crypto import ed25519_verify
from ._http import Fetch, make_urllib_fetch
from .errors import PhoenixKeyError
from .verifier import DEFAULT_PHOENIXKEY_API_URL

JWKS_PATH = "/.well-known/jwks.json"
DEFAULT_JWKS_CACHE_TTL_MS = 60 * 60 * 1000

# SHA-256 digest, base64url without padding = always 43 characters.
_THUMBPRINT_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")

KeyRole = str  # "viewer" | "manager" | "owner"
_ROLE_RANK = {"viewer": 0, "manager": 1, "owner": 2}


def key_role_from_claim(raw: object) -> KeyRole:
    """Read a role from a raw claim, **failing safe**: anything not exactly one of
    the three known roles (case-insensitive, trimmed) is ``"viewer"``, the lowest.
    Never raises, never returns ``"owner"`` for unknown input."""
    if not isinstance(raw, str):
        return "viewer"
    v = raw.strip().lower()
    return v if v in _ROLE_RANK else "viewer"


def key_role_at_least(role: KeyRole, minimum: KeyRole) -> bool:
    """``viewer < manager < owner``."""
    return _ROLE_RANK[role] >= _ROLE_RANK[minimum]


@dataclass(frozen=True)
class AppTokenClaims:
    iss: str
    sub: str
    #: The ServiceDID the token was minted for (a 1-element ``aud`` array is normalised to a string).
    aud: str
    iat: float
    exp: float
    nonce: str | None
    #: ``authorized_keys.id`` of the device key that opened the session, if present.
    key_id: str | None
    #: Already normalised by :func:`key_role_from_claim` (unknown/absent -> ``"viewer"``).
    key_role: KeyRole


def _is_number(x: object) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _b64url_decode(segment: str) -> bytes:
    b64 = segment.replace("-", "+").replace("_", "/")
    padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("invalid base64url") from e


def ed25519_jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url, 43 chars) of an OKP/Ed25519 public JWK.

    Hashes the UTF-8 bytes of ``{"crv":"Ed25519","kty":"OKP","x":"<x>"}`` -- the
    required members only, in lexicographic order, no whitespace. ``kid``, ``use``
    and ``alg`` do NOT enter the hash, so the thumbprint identifies the key
    material and cannot be reassigned by relabelling.

    Raises :class:`PhoenixKeyError` (``code="invalid_jwk"``) if the input is not an
    Ed25519 OKP JWK with a base64url ``x``. RFC 8037 Appendix A.3::

        ed25519_jwk_thumbprint({"kty": "OKP", "crv": "Ed25519",
                                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
        # -> "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    """
    x = jwk.get("x") if isinstance(jwk, Mapping) else None
    if (
        not isinstance(jwk, Mapping)
        or jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
        or not isinstance(x, str)
        or _BASE64URL_PATTERN.fullmatch(x) is None
    ):
        raise PhoenixKeyError(
            status=0,
            code="invalid_jwk",
            message="ed25519_jwk_thumbprint expects an OKP/Ed25519 JWK with a base64url 'x'",
        )
    # Built by hand, not json.dumps(jwk): the member order and the absence of
    # other members are exactly what RFC 7638 section 3.2 pins down.
    canonical = f'{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}'
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _is_pinned(key: object, pinned: frozenset[str]) -> bool:
    try:
        return ed25519_jwk_thumbprint(key) in pinned  # type: ignore[arg-type]
    except PhoenixKeyError:
        # Not an Ed25519 OKP JWK (or malformed): it can never match a pin.
        return False


def _warn_unpinned(message: str) -> None:
    warnings.warn(message, UserWarning, stacklevel=5)


def _reject_json_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant: {name}")


def _strict_json(text: str) -> Any:
    # json.loads accepts bare NaN / Infinity / -Infinity; JSON.parse in the
    # TypeScript SDK rejects them. Without this, a signed token whose exp is NaN
    # passes the expiry gate (every comparison with NaN is False).
    return json.loads(text, parse_constant=_reject_json_constant)


def _malformed(message: str) -> PhoenixKeyError:
    return PhoenixKeyError(status=0, code="malformed_token", message=message)


def _split_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise _malformed("app_token must have exactly 3 JWT segments")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = _strict_json(_b64url_decode(header_b64).decode("utf-8"))
        payload = _strict_json(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise _malformed("app_token header/payload is not valid JSON") from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise _malformed("app_token header/payload must be JSON objects")
    try:
        signature = _b64url_decode(sig_b64)
    except ValueError:
        raise _malformed("app_token signature segment is not valid base64url") from None
    # The JWS signing input is the exact ASCII text `header.payload` as sent,
    # not a re-serialisation of the parsed JSON.
    return header, payload, f"{header_b64}.{payload_b64}".encode("ascii", "replace"), signature


class AppTokenVerifier:
    """Verify ``app_token`` JWTs against the server's JWKS.

    ``phoenixkey_api_url`` must include the ``/api/v1`` context path (default
    ``https://api.phoenixkey.me/api/v1``). The JWKS is cached for
    ``jwks_cache_ttl_ms`` (default one hour). A token is checked against the key
    whose ``kid`` equals the token's ``kid`` -- there is no fall-back to "the first
    key", because that would make the outcome depend on the server's array order.

    **Key pinning.** ``pinned_jwk_thumbprints`` is a non-empty list of RFC 7638
    SHA-256 thumbprints (base64url, 43 chars; compute them with
    :func:`ed25519_jwk_thumbprint` from a JWKS you checked OUT OF BAND, not from the
    fetch this verifier makes). When set, every JWK in the downloaded JWKS whose
    thumbprint is not listed is ignored, and a token whose ``kid`` points only at
    such a key is rejected with ``jwks_key_not_pinned`` -- no fall-back to another
    key. TLS ends at the CDN edge: without pinning, a CDN that serves an extra
    ``kid`` lets an attacker mint ``app_token``s for any DID. An empty list, a
    non-list value or a malformed entry raises ``invalid_pinned_thumbprints`` at
    construction, so a bad pin list can never degrade into "no pinning" while
    looking pinned. Omit the option (``None``) to keep the legacy trust-the-JWKS
    behaviour; the first verification then emits a one-time warning through
    ``on_warning`` (default: :func:`warnings.warn`, category ``UserWarning``). Pass
    ``on_warning=lambda message: None`` to acknowledge the risk and silence it.
    """

    def __init__(
        self,
        phoenixkey_api_url: str | None = None,
        *,
        jwks_cache_ttl_ms: int = DEFAULT_JWKS_CACHE_TTL_MS,
        fetch: Fetch | None = None,
        timeout: float = 10.0,
        clock: Callable[[], float] = time.time,
        pinned_jwk_thumbprints: list[str] | tuple[str, ...] | set[str] | frozenset[str] | None = None,
        on_warning: Callable[[str], None] | None = None,
    ) -> None:
        url = phoenixkey_api_url if phoenixkey_api_url is not None else DEFAULT_PHOENIXKEY_API_URL
        self._api_url = url.rstrip("/")
        self._ttl_ms = jwks_cache_ttl_ms
        self._fetch: Fetch = fetch if fetch is not None else make_urllib_fetch(timeout)
        self._clock = clock
        self._cached: tuple[list[Any], float] | None = None
        self._on_warning: Callable[[str], None] = on_warning if on_warning is not None else _warn_unpinned
        self._warned_unpinned = False

        # `None` = not pinning (legacy). ANY other value must be a valid, non-empty
        # list -- an empty or malformed one raises here rather than degrading to
        # "no pinning" while looking pinned.
        self._pinned: frozenset[str] | None
        if pinned_jwk_thumbprints is None:
            self._pinned = None
        else:
            if not isinstance(pinned_jwk_thumbprints, (list, tuple, set, frozenset)) or len(pinned_jwk_thumbprints) == 0:
                raise PhoenixKeyError(
                    status=0,
                    code="invalid_pinned_thumbprints",
                    message=(
                        "pinned_jwk_thumbprints must be a non-empty list of RFC 7638 thumbprints. "
                        "An empty list would accept nothing (or, worse, be mistaken for 'pinned'); "
                        "omit the option to run without pinning."
                    ),
                )
            for t in pinned_jwk_thumbprints:
                if not isinstance(t, str) or _THUMBPRINT_PATTERN.fullmatch(t) is None:
                    raise PhoenixKeyError(
                        status=0,
                        code="invalid_pinned_thumbprints",
                        message=(
                            "pinned_jwk_thumbprints entries must be 43-char base64url SHA-256 thumbprints "
                            "(see ed25519_jwk_thumbprint)"
                        ),
                    )
            self._pinned = frozenset(pinned_jwk_thumbprints)

    def verify(self, token: str, expected_aud: str) -> AppTokenClaims:
        """Verify signature, expiry **and** ``aud``; return the claims.

        Raises :class:`PhoenixKeyError` (``code`` is one of ``malformed_token``,
        ``unsupported_alg``, ``jwks_fetch_failed``, ``jwks_key_not_found``,
        ``jwks_key_not_pinned``, ``signature_invalid``, ``token_expired``,
        ``aud_mismatch``, ``expected_aud_required``). ``expected_aud`` is your own ServiceDID and is
        required: without it, a token minted for another service would be accepted.
        """
        if not isinstance(expected_aud, str) or expected_aud == "":
            raise PhoenixKeyError(
                status=0,
                code="expected_aud_required",
                message=(
                    "verify() requires expected_aud (your ServiceDID). To skip the audience "
                    "check deliberately, call verify_without_audience()."
                ),
            )
        return self._verify_internal(token, expected_aud)

    def verify_without_audience(self, token: str) -> AppTokenClaims:
        """Verify signature and expiry but **not** ``aud``. Only correct if you bind
        the token to yourself some other way."""
        return self._verify_internal(token, None)

    # ── internals ─────────────────────────────────────────────────────────────

    def _verify_internal(self, token: str, expected_aud: str | None) -> AppTokenClaims:
        header, payload, signing_input, signature = _split_token(token)

        if header.get("alg") != "EdDSA":
            raise PhoenixKeyError(
                status=0, code="unsupported_alg", message=f"Unsupported app_token alg: {header.get('alg')}"
            )

        pubkey = self._resolve_pubkey(header.get("kid"))

        # Gate 1: no claim below is reachable unless the signature verified.
        if not ed25519_verify(signature, signing_input, pubkey):
            raise PhoenixKeyError(
                status=0, code="signature_invalid", message="app_token signature verification failed"
            )

        # Gate 2: a verified-but-stale token is still unusable.
        exp = payload.get("exp")
        if not _is_number(exp) or int(self._clock()) >= exp:
            raise PhoenixKeyError(status=0, code="token_expired", message="app_token has expired")

        aud_claim = payload.get("aud")
        aud_values = aud_claim if isinstance(aud_claim, list) else ([aud_claim] if aud_claim is not None else [])
        if expected_aud and expected_aud not in aud_values:
            raise PhoenixKeyError(
                status=0,
                code="aud_mismatch",
                message="app_token was not minted for the expected aud (ServiceDID)",
            )

        def s(name: str) -> str:
            v = payload.get(name)
            return v if isinstance(v, str) else ""

        def opt_s(name: str) -> str | None:
            v = payload.get(name)
            return v if isinstance(v, str) else None

        iat = payload.get("iat")
        return AppTokenClaims(
            iss=s("iss"),
            sub=s("sub"),
            aud=aud_values[0] if aud_values and isinstance(aud_values[0], str) else "",
            iat=iat if _is_number(iat) else 0,
            exp=exp,
            nonce=opt_s("nonce"),
            key_id=opt_s("key_id"),
            key_role=key_role_from_claim(payload.get("key_role")),
        )

    def _resolve_pubkey(self, kid: object) -> bytes:
        keys = self._get_jwks()
        if self._pinned is None and not self._warned_unpinned:
            self._warned_unpinned = True
            self._on_warning(
                "[PhoenixKey AppTokenVerifier] No key pinning: signing keys are trusted from the JWKS "
                "fetched over HTTPS. A CDN or network path that serves an extra kid lets an attacker "
                "mint app_tokens. Set pinned_jwk_thumbprints (see ed25519_jwk_thumbprint)."
            )
        # `kid` is required: with no fall-back to keys[0], the outcome depends on
        # the token, not on the order of a JSON array served by the API.
        if not isinstance(kid, str) or kid == "":
            raise PhoenixKeyError(
                status=0,
                code="jwks_key_not_found",
                message="app_token header is missing kid -- cannot select a JWKS key",
            )
        candidates = keys
        if self._pinned is not None:
            pinned = self._pinned
            # Filter BEFORE selecting by kid, so a duplicate kid planted ahead of the
            # real key cannot shadow it, and a key that is not pinned is never a
            # candidate at all.
            candidates = [k for k in keys if _is_pinned(k, pinned)]
            if not any(isinstance(k, dict) and k.get("kid") == kid for k in candidates) and any(
                isinstance(k, dict) and k.get("kid") == kid for k in keys
            ):
                raise PhoenixKeyError(
                    status=0,
                    code="jwks_key_not_pinned",
                    message=(
                        f"JWKS key kid={kid} is not in pinned_jwk_thumbprints -- refusing to use it. "
                        "If PhoenixKey rotated its signing key, verify the new JWKS out of band and "
                        "add its thumbprint; otherwise the JWKS you were served may be forged."
                    ),
                )
        key = next((k for k in candidates if isinstance(k, dict) and k.get("kid") == kid), None)
        if key is None:
            raise PhoenixKeyError(
                status=0, code="jwks_key_not_found", message=f"No JWKS key found for kid={kid}"
            )
        if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
            raise PhoenixKeyError(
                status=0,
                code="jwks_key_not_found",
                message=f"Unsupported JWK kty/crv: {key.get('kty')}/{key.get('crv')}",
            )
        x = key.get("x")
        try:
            if not isinstance(x, str):
                raise ValueError("missing x")
            return _b64url_decode(x)
        except ValueError:
            raise PhoenixKeyError(
                status=0, code="jwks_key_not_found", message="JWK has no valid 'x' coordinate"
            ) from None

    def _get_jwks(self) -> list[Any]:
        if self._cached is not None and self._cached[1] > self._clock() * 1000:
            return self._cached[0]
        url = f"{self._api_url}{JWKS_PATH}"
        res = self._fetch(url, {"Accept": "application/json"})
        if not res.ok:
            hint = (
                " -- check that 'phoenixkey_api_url' includes the context path. The server serves "
                f"every route under '/api/v1'; the bare origin returns 404. Default: '{DEFAULT_PHOENIXKEY_API_URL}'."
                if res.status == 404
                else ""
            )
            raise PhoenixKeyError(
                status=res.status,
                code="jwks_fetch_failed",
                message=f"JWKS fetch failed: HTTP {res.status} at {url}{hint}",
            )
        try:
            body = _strict_json(res.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise PhoenixKeyError(
                status=res.status, code="jwks_fetch_failed", message=f"JWKS at {url} returned 200 with a body that is not JSON"
            ) from None
        keys = body.get("keys") if isinstance(body, dict) else None
        # Fail closed: a 200 without a `keys` array (error page from a proxy,
        # different server version) must not be cached as if it were a JWKS.
        if not isinstance(keys, list):
            raise PhoenixKeyError(
                status=res.status,
                code="jwks_fetch_failed",
                message=f"JWKS at {url} returned 200 but the body has no 'keys' array",
            )
        self._cached = (keys, self._clock() * 1000 + self._ttl_ms)
        return keys
