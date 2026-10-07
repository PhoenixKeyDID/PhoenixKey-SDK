"""AppTokenVerifier against vectors produced by the TypeScript SDK."""

from __future__ import annotations

import json

import pytest

from phoenixkey_sdk import HttpResponse, PhoenixKeyError
from phoenixkey_sdk.app_token import (
    AppTokenVerifier,
    key_role_at_least,
    key_role_from_claim,
)

with open(__file__.replace("test_app_token.py", "vectors/vectors.json"), encoding="utf-8") as _f:
    _V = json.load(_f)


def jwks_fetch(response, calls):
    def fetch(url, headers):
        calls.append(url)
        return HttpResponse(response["status"], response["body"].encode("utf-8"))

    return fetch


@pytest.mark.parametrize("case", _V["app_token"], ids=lambda c: c["name"])
def test_app_token_matches_typescript(case):
    calls: list[str] = []
    v = AppTokenVerifier(
        _V["meta"]["api_url"], fetch=jwks_fetch(case["jwks_response"], calls), clock=lambda: case["now"]
    )

    def run():
        if case["mode"] == "verify":
            return v.verify(case["token"], case["expected_aud"])
        return v.verify_without_audience(case["token"])

    exp = case["expected"]
    if exp["ok"]:
        claims = run()
        want = exp["claims"]
        assert claims.iss == want["iss"] and claims.sub == want["sub"] and claims.aud == want["aud"]
        assert claims.iat == want["iat"] and claims.exp == want["exp"]
        assert claims.nonce == want.get("nonce")
        assert claims.key_id == want.get("key_id")
        assert claims.key_role == want["key_role"]
    else:
        with pytest.raises(PhoenixKeyError) as ei:
            run()
        if exp["error"]["name"] == "PhoenixKeyError":
            assert ei.value.code == exp["error"]["code"]
            assert ei.value.status == exp["error"]["status"]
        else:
            # TypeScript lets a DOMException from atob() escape on an undecodable
            # signature segment; Python reports it as a malformed token instead.
            assert case["name"] == "signature_segment_not_base64"
            assert ei.value.code == "malformed_token"
    assert calls == [e["url"] for e in case["exchanges"]]


def test_vector_set_is_not_vacuous():
    codes = {c["expected"]["error"]["code"] for c in _V["app_token"] if not c["expected"]["ok"]}
    for needed in (
        "aud_mismatch",
        "token_expired",
        "signature_invalid",
        "jwks_key_not_found",
        "unsupported_alg",
        "malformed_token",
        "jwks_fetch_failed",
        "expected_aud_required",
    ):
        assert needed in codes, needed
    assert sum(1 for c in _V["app_token"] if c["expected"]["ok"]) >= 8


def _valid_case():
    return next(c for c in _V["app_token"] if c["name"] == "valid_owner")


def test_jwks_is_cached_then_refetched_after_ttl():
    case = _valid_case()
    calls: list[str] = []
    now = {"t": float(case["now"])}
    v = AppTokenVerifier(
        _V["meta"]["api_url"],
        jwks_cache_ttl_ms=10_000,
        fetch=jwks_fetch(case["jwks_response"], calls),
        clock=lambda: now["t"],
    )
    v.verify(case["token"], case["expected_aud"])
    v.verify(case["token"], case["expected_aud"])
    assert len(calls) == 1
    now["t"] += 11
    v.verify(case["token"], case["expected_aud"])
    assert len(calls) == 2


def test_failed_jwks_fetch_is_not_cached():
    case = _valid_case()
    answers = iter([HttpResponse(200, b'{"nope":1}'), HttpResponse(200, case["jwks_response"]["body"].encode())])
    calls: list[str] = []

    def fetch(url, headers):
        calls.append(url)
        return next(answers)

    v = AppTokenVerifier(_V["meta"]["api_url"], fetch=fetch, clock=lambda: case["now"])
    with pytest.raises(PhoenixKeyError) as ei:
        v.verify(case["token"], case["expected_aud"])
    assert ei.value.code == "jwks_fetch_failed"
    assert v.verify(case["token"], case["expected_aud"]).key_role == "owner"
    assert len(calls) == 2


def test_jwks_404_message_points_at_the_context_path():
    calls: list[str] = []
    v = AppTokenVerifier(
        "https://api.example.test",
        fetch=jwks_fetch({"status": 404, "body": "{}"}, calls),
        clock=lambda: _valid_case()["now"],
    )
    with pytest.raises(PhoenixKeyError) as ei:
        v.verify(_valid_case()["token"], _valid_case()["expected_aud"])
    assert ei.value.status == 404 and "/api/v1" in str(ei.value)
    assert calls == ["https://api.example.test/.well-known/jwks.json"]


def test_default_url_includes_context_path():
    calls: list[str] = []
    v = AppTokenVerifier(fetch=jwks_fetch({"status": 404, "body": "{}"}, calls), clock=lambda: 1)
    with pytest.raises(PhoenixKeyError):
        v.verify(_valid_case()["token"], _valid_case()["expected_aud"])
    assert calls == ["https://api.phoenixkey.me/api/v1/.well-known/jwks.json"]


def test_non_string_expected_aud_is_refused_at_runtime():
    v = AppTokenVerifier(fetch=lambda u, h: pytest.fail("must not fetch"))
    for bad in (None, "", 7):
        with pytest.raises(PhoenixKeyError) as ei:
            v.verify(_valid_case()["token"], bad)  # type: ignore[arg-type]
        assert ei.value.code == "expected_aud_required"


def test_key_role_helpers_fail_safe():
    assert key_role_from_claim(None) == "viewer"
    assert key_role_from_claim(" Owner ") == "owner"
    assert key_role_from_claim("root") == "viewer"
    assert key_role_from_claim(1) == "viewer"
    assert key_role_at_least("owner", "manager") and not key_role_at_least("viewer", "manager")
