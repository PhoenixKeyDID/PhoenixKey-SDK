"""Canonical JSON and envelope bytes must equal the TypeScript SDK's, byte for byte."""

from __future__ import annotations

import json

import pytest

from phoenixkey_sdk import canonical_json_bytes, encode_legacy_concat, encode_rp_auth_v1
from phoenixkey_sdk.canonical import canonical_json_string

with open(__file__.replace("test_canonical.py", "vectors/vectors.json"), encoding="utf-8") as _f:
    _V = json.load(_f)


@pytest.mark.parametrize("case", _V["canonical"], ids=lambda c: c["name"])
def test_canonical_bytes_match_typescript(case):
    got = canonical_json_bytes(json.loads(case["intent_json"]))
    assert got.hex() == case["expected_hex"]


@pytest.mark.parametrize("case", _V["envelope"], ids=lambda c: c["name"])
def test_envelope_bytes_match_typescript(case):
    f = case["fields"]
    assert encode_rp_auth_v1(**f).hex() == case["v1_hex"]
    legacy_fields = {k: f[k] for k in ("domain", "challenge", "timestamp")}
    assert encode_legacy_concat(**legacy_fields).hex() == case["legacy_hex"]


def test_vector_set_is_not_vacuous():
    assert len(_V["canonical"]) >= 20
    assert len(_V["envelope"]) >= 8


def test_utf16_key_order_differs_from_code_point_order():
    # U+1F600 is the surrogate pair D83D DE00, which sorts BEFORE U+FF5E in
    # JavaScript, while by code point U+1F600 sorts after. This is the case that
    # Python's own sorted() gets wrong.
    obj = {"～": 1, "\U0001f600": 2}
    assert sorted(obj) == ["～", "\U0001f600"]
    assert canonical_json_string(obj).index("\U0001f600") < canonical_json_string(obj).index("～")


@pytest.mark.parametrize(
    "value, expected",
    [
        (1.0, "1"),
        (-0.0, "0"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-7, "1e-7"),
        (0.000001, "0.000001"),
        (1.5e-10, "1.5e-10"),
        (float("nan"), "null"),
        (float("inf"), "null"),
        (2**53 + 1, "9007199254740992"),
        (True, "true"),
        (None, "null"),
    ],
)
def test_number_formatting_follows_javascript(value, expected):
    assert canonical_json_string(value) == expected


def test_unsupported_types_raise_instead_of_guessing():
    with pytest.raises(TypeError):
        canonical_json_bytes({"a": object()})
    with pytest.raises(TypeError):
        canonical_json_bytes({1: "non-string key"})


def test_envelope_rejects_bad_timestamp():
    with pytest.raises(ValueError):
        encode_rp_auth_v1(user_did="d", domain="x", challenge="c", timestamp=-1)
    with pytest.raises(ValueError):
        encode_rp_auth_v1(user_did="d", domain="x", challenge="c", timestamp=1.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        encode_rp_auth_v1(user_did="d", domain="x", challenge="c", timestamp=2**53)


# ── numbers JavaScript degrades, and the strict mode a verifier uses ─────────


@pytest.mark.parametrize(
    "value, expected",
    [
        (10**308, "1e+308"),  # the largest power of ten a double holds
        (10**309, "null"),  # Number("1" + "0" * 309) is Infinity -> JSON.stringify gives null
        (10**400, "null"),  # float(10**400) raises OverflowError in Python
        (-(10**400), "null"),
    ],
)
def test_huge_integers_follow_javascript_not_overflowerror(value, expected):
    assert canonical_json_string(value) == expected
    assert canonical_json_bytes({"n": value}) == b'{"n":' + expected.encode() + b"}"


@pytest.mark.parametrize(
    "value",
    [2**53 + 1, -(2**53) - 1, 10**400, -(10**400), float("nan"), float("inf"), float("-inf")],
)
def test_strict_refuses_numbers_javascript_would_degrade(value):
    with pytest.raises(ValueError):
        canonical_json_string(value, strict=True)
    # ... also when nested at any depth, in a list or a mapping.
    with pytest.raises(ValueError):
        canonical_json_bytes({"a": [{"b": [value]}]}, strict=True)


@pytest.mark.parametrize("value", [0, 2**53, -(2**53), 1.5, 1e300, -1e-7, True, None])
def test_strict_leaves_ordinary_numbers_alone(value):
    assert canonical_json_string(value, strict=True) == canonical_json_string(value)
