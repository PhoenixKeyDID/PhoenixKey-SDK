"""phoenixkey_sdk -- verify-only Python client for PhoenixKey identity."""

from ._http import Fetch, HttpResponse
from .app_token import (
    AppTokenClaims,
    AppTokenVerifier,
    ed25519_jwk_thumbprint,
    key_role_at_least,
    key_role_from_claim,
)
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
    "AppTokenClaims",
    "AppTokenVerifier",
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
    "ed25519_jwk_thumbprint",
    "encode_legacy_concat",
    "encode_rp_auth_v1",
    "key_role_at_least",
    "key_role_from_claim",
]
__version__ = "0.1.0"
