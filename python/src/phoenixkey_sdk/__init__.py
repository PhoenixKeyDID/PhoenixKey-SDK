"""phoenixkey_sdk -- verify-only Python client for PhoenixKey identity."""

from .canonical import canonical_json_bytes, canonical_json_string
from .envelope import RP_AUTH_PREFIX_V1, encode_legacy_concat, encode_rp_auth_v1
from .errors import PhoenixKeyError

__all__ = [
    "PhoenixKeyError",
    "RP_AUTH_PREFIX_V1",
    "canonical_json_bytes",
    "canonical_json_string",
    "encode_legacy_concat",
    "encode_rp_auth_v1",
]
__version__ = "0.1.0"
