"""Signature primitives (via ``cryptography``) with the TypeScript SDK's decoding rules."""

from __future__ import annotations

import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

# Order of the P-256 group.
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class HexLengthError(ValueError):
    """Odd-length hex. The message matches the TypeScript SDK's, which surfaces it in ``reason``."""


def hex_to_bytes(h: str) -> bytes:
    """Decode hex, accepting an optional ``0x``/``0X`` prefix.

    Odd length raises :class:`HexLengthError`. Any other malformed input raises
    ``ValueError``; callers treat that as "this does not verify".
    """
    s = h[2:] if h[:2] in ("0x", "0X") else h
    if len(s) % 2 != 0:
        raise HexLengthError("Hex length must be even")
    if not _HEX_RE.match(s):
        raise ValueError("Invalid hex digit")
    return bytes.fromhex(s)


def p256_verify_sha256(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """ECDSA P-256 over SHA-256(message).

    Mirrors ``p256.verify(sig, sha256(msg), pub)`` from ``@noble/curves``:
    the public key is a SEC1 point (33-byte compressed or 65-byte uncompressed),
    the signature is DER (tried first) or 64-byte compact ``r || s``. High-S
    signatures are accepted. Never raises for malformed input -- it returns False.
    """
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
    except ValueError:
        return False

    rs: tuple[int, int] | None = None
    try:
        rs = decode_dss_signature(signature)
    except ValueError:
        if len(signature) == 64:
            rs = (int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    if rs is None:
        return False
    r, s = rs
    if not (0 < r < _P256_N and 0 < s < _P256_N):
        return False
    try:
        pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """Ed25519 (RFC 8032). Returns False for any malformed input."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
