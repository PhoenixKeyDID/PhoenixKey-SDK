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
import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from ._crypto import ed25519_verify
from ._http import Fetch, make_urllib_fetch
from .errors import PhoenixKeyError
from .verifier import DEFAULT_PHOENIXKEY_API_URL

JWKS_PATH = "/.well-known/jwks.json"
DEFAULT_JWKS_CACHE_TTL_MS = 60 * 60 * 1000

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


def _malformed(message: str) -> PhoenixKeyError:
    return PhoenixKeyError(status=0, code="malformed_token", message=message)


def _split_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise _malformed("app_token must have exactly 3 JWT segments")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
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
    """

    def __init__(
        self,
        phoenixkey_api_url: str | None = None,
        *,
        jwks_cache_ttl_ms: int = DEFAULT_JWKS_CACHE_TTL_MS,
        fetch: Fetch | None = None,
        timeout: float = 10.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        url = phoenixkey_api_url if phoenixkey_api_url is not None else DEFAULT_PHOENIXKEY_API_URL
        self._api_url = url.rstrip("/")
        self._ttl_ms = jwks_cache_ttl_ms
        self._fetch: Fetch = fetch if fetch is not None else make_urllib_fetch(timeout)
        self._clock = clock
        self._cached: tuple[list[Any], float] | None = None

    def verify(self, token: str, expected_aud: str) -> AppTokenClaims:
        """Verify signature, expiry **and** ``aud``; return the claims.

        Raises :class:`PhoenixKeyError` (``code`` is one of ``malformed_token``,
        ``unsupported_alg``, ``jwks_fetch_failed``, ``jwks_key_not_found``,
        ``signature_invalid``, ``token_expired``, ``aud_mismatch``,
        ``expected_aud_required``). ``expected_aud`` is your own ServiceDID and is
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
        # `kid` is required: with no fall-back to keys[0], the outcome depends on
        # the token, not on the order of a JSON array served by the API.
        if not isinstance(kid, str) or kid == "":
            raise PhoenixKeyError(
                status=0,
                code="jwks_key_not_found",
                message="app_token header is missing kid -- cannot select a JWKS key",
            )
        key = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
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
            body = json.loads(res.body.decode("utf-8"))
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
