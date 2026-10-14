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


# ── integers: a JSON number is a double, JavaScript prints every double below
# 1e21 in plain digits. An integer is safe exactly when those digits are its own.


@pytest.mark.parametrize(
    "value",
    [
        10**18,
        -(10**18),
        1152921504606847000,  # 2**60 rounded to the 17 digits JavaScript prints
        9007199254740994,  # 2**53 + 2: even, so a double holds it exactly
    ],
)
def test_strict_accepts_integers_a_double_holds_exactly(value):
    assert canonical_json_string(value, strict=True) == str(value)
    # ... and that is also what the lenient (JavaScript-like) rendering prints.
    assert canonical_json_string(value) == str(value)
    assert canonical_json_bytes({"amount": value}, strict=True) == b'{"amount":' + str(value).encode() + b"}"


@pytest.mark.parametrize(
    "value",
    [
        1152921504606846976,  # 2**60: JavaScript prints 1152921504606847000
        9007199254740993,  # 2**53 + 1: rounds to ...992
        -9007199254740993,
        10**21,  # JavaScript switches to 1e+21
        -(10**21),
    ],
)
def test_strict_refuses_integers_a_double_would_change(value):
    with pytest.raises(ValueError):
        canonical_json_string(value, strict=True)


# ── a surrogate pair held as two characters is ONE character in JavaScript ──

_PAIR = chr(0xD83D) + chr(0xDE00)  # two lone halves side by side: len 2, not one character


def test_split_surrogate_pair_is_joined_like_javascript():
    assert canonical_json_bytes(_PAIR) == b'"\xf0\x9f\x98\x80"'  # the bytes TypeScript produces
    assert canonical_json_bytes(_PAIR) == canonical_json_bytes("\U0001f600")
    assert canonical_json_bytes({_PAIR: [_PAIR]}) == canonical_json_bytes({"\U0001f600": ["\U0001f600"]})
    assert len(_PAIR) == 2


@pytest.mark.parametrize(
    "value, expected",
    [
        (chr(0xD83D), b'"\\ud83d"'),
        (chr(0xDE00), b'"\\ude00"'),
        (chr(0xDE00) + chr(0xD83D), b'"\\ude00\\ud83d"'),  # low before high is not a pair
        ("a" + _PAIR + chr(0xD800) + "b", b'"a\xf0\x9f\x98\x80\\ud800b"'),
        (_PAIR + chr(0xDE00), b'"\xf0\x9f\x98\x80\\ude00"'),
    ],
)
def test_lone_surrogate_halves_are_still_escaped(value, expected):
    assert canonical_json_bytes(value) == expected


@pytest.mark.parametrize(
    "obj",
    [
        {_PAIR: 1, "\U0001f600": 2},
        {"\U0001f600": 2, _PAIR: 1},
        {"k": {"a" + _PAIR: 1, "a\U0001f600": 2}},
    ],
    ids=["split-first", "joined-first", "nested"],
)
def test_keys_that_join_to_the_same_javascript_key_are_refused(obj):
    # Two distinct Python keys, one key once JavaScript joins the pair: a JS object
    # cannot hold both, so emitting both would sign bytes TypeScript never produces.
    with pytest.raises(ValueError, match="same key in JavaScript"):
        canonical_json_bytes(obj)


def test_lone_halves_as_keys_stay_distinct_from_the_pair():
    # UTF-16 order, as JavaScript sorts: D83D < D83D DE00 x < DE00.
    obj = {chr(0xD83D): 1, chr(0xDE00): 2, _PAIR + "x": 3}
    assert canonical_json_bytes(obj) == b'{"\\ud83d":1,"\xf0\x9f\x98\x80x":3,"\\ude00":2}'
