"""phoenixkey_sdk -- verify-only Python client for PhoenixKey identity."""

from ._http import Fetch, HttpResponse
from .canonical import canonical_json_bytes, canonical_json_string
from .envelope import RP_AUTH_PREFIX_V1, encode_legacy_concat, encode_rp_auth_v1
from .errors import PhoenixKeyError
from .verifier import (
    DEFAULT_PHOENIXKEY_API_URL,
    IdentityPubkey,
    PhoenixKeyVerifier,
    VerifyResult,
)

__all__ = [
    "DEFAULT_PHOENIXKEY_API_URL",
    "Fetch",
    "HttpResponse",
    "IdentityPubkey",
    "PhoenixKeyError",
    "PhoenixKeyVerifier",
    "RP_AUTH_PREFIX_V1",
    "VerifyResult",
    "canonical_json_bytes",
    "canonical_json_string",
    "encode_legacy_concat",
    "encode_rp_auth_v1",
]
__version__ = "0.1.0"
