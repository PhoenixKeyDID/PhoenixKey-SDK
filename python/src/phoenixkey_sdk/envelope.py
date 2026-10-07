"""PHOENIXKEY_RP_AUTH envelope -- the bytes a relying-party login signature covers.

Same layout as the TypeScript SDK's ``envelope.ts``: a domain-separation prefix,
then each string field as a u32 big-endian byte length followed by its UTF-8
bytes, then the timestamp as a u64 big-endian integer. Field order is part of the
format.
"""

from __future__ import annotations

import struct

RP_AUTH_PREFIX_V1 = "PHOENIXKEY_RP_AUTH:v1\u0000"

_MAX_SAFE_INTEGER = 2**53 - 1


def _length_prefixed(s: str) -> bytes:
    body = s.encode("utf-8")
    return struct.pack(">I", len(body)) + body


def _u64be(v: int) -> bytes:
    if isinstance(v, bool) or not isinstance(v, int):
        if isinstance(v, float) and v.is_integer():
            v = int(v)
        else:
            raise ValueError(f"timestamp must be a non-negative integer, got: {v!r}")
    if v < 0:
        raise ValueError(f"timestamp must be a non-negative integer, got: {v}")
    if v > _MAX_SAFE_INTEGER:
        raise ValueError(f"timestamp exceeds the safe integer range: {v}")
    return struct.pack(">Q", v)


def encode_rp_auth_v1(*, user_did: str, domain: str, challenge: str, timestamp: int) -> bytes:
    """Signed bytes under the v1 envelope (injective: no two field sets collide)."""
    return (
        RP_AUTH_PREFIX_V1.encode("utf-8")
        + _length_prefixed(user_did)
        + _length_prefixed(domain)
        + _length_prefixed(challenge)
        + _u64be(timestamp)
    )


def encode_legacy_concat(*, domain: str, challenge: str, timestamp: int) -> bytes:
    """The old ``challenge:domain:timestamp`` form. NOT injective -- migration only."""
    return f"{challenge}:{domain}:{_js_integer_text(timestamp)}".encode("utf-8")


def _js_integer_text(ts: int | float) -> str:
    # `${timestamp}` in JavaScript: integers print without a decimal point.
    if isinstance(ts, float) and ts.is_integer() and abs(ts) < 1e21:
        return str(int(ts))
    return str(ts)
