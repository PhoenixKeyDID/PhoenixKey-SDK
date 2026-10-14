"""PhoenixKeyVerifier against the vectors produced by the TypeScript SDK."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from phoenixkey_sdk import HttpResponse, PhoenixKeyError, PhoenixKeyVerifier
from phoenixkey_sdk.verifier import DEFAULT_PHOENIXKEY_API_URL

with open(__file__.replace("test_verifier.py", "vectors/vectors.json"), encoding="utf-8") as _f:
    _V = json.load(_f)


def replay_fetch(exchanges):
    """A fetch that answers exactly what the TypeScript run saw, and logs requests."""
    by_url = {e["url"]: e for e in exchanges}
    calls: list[str] = []

    def fetch(url, headers):
        calls.append(url)
        assert headers.get("Accept") == "application/json"
        if url not in by_url:
            raise AssertionError(f"unexpected request: {url}")
        e = by_url[url]
        return HttpResponse(e["status"], e["body"].encode("utf-8"))

    return fetch, calls


def check_result(res, expected, reason_match=None):
    assert res.valid is expected["valid"]
    assert res.envelope == expected.get("envelope")
    if reason_match == "prefix":
        assert res.reason is not None and res.reason.startswith(expected["reason"].split(":")[0] + ":")
    else:
        assert res.reason == expected.get("reason")


@pytest.mark.parametrize("case", _V["intent"], ids=lambda c: c["name"])
def test_verify_intent_matches_typescript(case):
    fetch, calls = replay_fetch(case["exchanges"])
    v = PhoenixKeyVerifier(case["api_url"], fetch=fetch, clock=lambda: case["now"])
    res = v.verify_intent(
        user_did=case["user_did"],
        intent=json.loads(case["intent_json"]),
        signature=case["signature"],
        public_key_hex=case.get("public_key_hex"),
    )
    check_result(res, case["expected"], case.get("reason_match"))
    assert res.user_did == case["user_did"]
    # Same requests, same order, same URLs (including the ?key= hint).
    assert calls == [e["url"] for e in case["exchanges"]]


@pytest.mark.parametrize("case", _V["auth_proof"], ids=lambda c: c["name"])
def test_verify_auth_proof_matches_typescript(case):
    fetch, calls = replay_fetch(case["exchanges"])
    kwargs = {}
    if "accept_legacy_envelope" in case:
        kwargs["accept_legacy_envelope"] = case["accept_legacy_envelope"]
    v = PhoenixKeyVerifier(_V["meta"]["api_url"], fetch=fetch, clock=lambda: case["now"], **kwargs)
    res = v.verify_auth_proof(**case["request"])
    check_result(res, case["expected"])
    assert calls == [e["url"] for e in case["exchanges"]]


def test_vector_set_covers_the_negative_cases():
    reasons = {c["expected"].get("reason", "").split(":")[0] for c in _V["intent"]}
    for needed in (
        "key_revoked",
        "key_role_not_owner",
        "key_mismatch",
        "resolve_failed",
        "signature_invalid",
        "timestamp_skew",
        "verify_failed",
    ):
        assert needed in reasons, needed
    assert any(c["expected"]["valid"] for c in _V["intent"])
    assert len(_V["intent"]) >= 50 and len(_V["auth_proof"]) >= 15


# ── behaviour that is not a TypeScript vector ────────────────────────────────


def _record_body(pub, status="active"):
    return json.dumps(
        {"code": 1000, "result": {"public_key_hex": pub, "key_role": "owner", "status": status}}
    ).encode()


def test_default_api_url_has_context_path():
    assert DEFAULT_PHOENIXKEY_API_URL == "https://api.phoenixkey.me/api/v1"
    urls = []

    def fetch(url, headers):
        urls.append(url)
        return HttpResponse(404, b"{}")

    PhoenixKeyVerifier(fetch=fetch).verify_auth_proof(
        user_did="did:x", signature="00", challenge="c", domain="d", timestamp=1
    )
    # timestamp 1 is skewed -> no request at all
    assert urls == []
    v = PhoenixKeyVerifier(fetch=fetch, clock=lambda: 1)
    v.verify_auth_proof(user_did="did:x", signature="00", challenge="c", domain="d", timestamp=1)
    assert urls == ["https://api.phoenixkey.me/api/v1/identity/did%3Ax/pubkey"]


def test_no_cache_by_default_means_every_verify_hits_the_server():
    n = {"calls": 0}

    def fetch(url, headers):
        n["calls"] += 1
        return HttpResponse(200, _record_body("02" + "11" * 32))

    v = PhoenixKeyVerifier("https://x/api/v1", fetch=fetch)
    v.resolve_key("did:a")
    v.resolve_key("did:a")
    assert n["calls"] == 2


def test_cache_is_keyed_by_did_and_key_and_expires():
    now = {"t": 1000.0}
    urls: list[str] = []

    def fetch(url, headers):
        urls.append(url)
        return HttpResponse(200, _record_body("02" + "11" * 32))

    v = PhoenixKeyVerifier("https://x/api/v1", cache_ttl_ms=30_000, fetch=fetch, clock=lambda: now["t"])
    v.resolve_key("did:a")
    v.resolve_key("did:a")  # cached
    v.resolve_key("did:a", "0xAB")  # different key -> its own entry
    v.resolve_key("did:a", "ab")  # same normalised key -> cached
    v.resolve_key("did:b")  # different DID
    assert len(urls) == 3
    now["t"] += 29.9
    v.resolve_key("did:a")
    assert len(urls) == 3
    now["t"] += 0.2  # past 30 s
    v.resolve_key("did:a")
    assert len(urls) == 4


def test_missing_timestamp_fails_closed():
    v = PhoenixKeyVerifier("https://x/api/v1", fetch=lambda u, h: pytest.fail("must not fetch"))
    res = v.verify_intent(user_did="did:a", intent={"type": "T"}, signature="00")
    assert not res.valid and res.reason == "timestamp_skew"
    res = v.verify_intent(user_did="did:a", intent={"timestamp": True}, signature="00")
    assert not res.valid and res.reason == "timestamp_skew"


def test_transport_failure_becomes_resolve_failed_not_an_exception():
    def fetch(url, headers):
        raise PhoenixKeyError(status=0, code="network_error", message="Request failed: boom")

    v = PhoenixKeyVerifier("https://x/api/v1", fetch=fetch, clock=lambda: 5)
    res = v.verify_intent(user_did="did:a", intent={"timestamp": 5}, signature="00")
    assert not res.valid and res.reason == "resolve_failed: Request failed: boom"


def test_resolve_key_raises_phoenixkey_error_on_404_with_key_hint():
    def fetch(url, headers):
        return HttpResponse(404, b"{}")

    v = PhoenixKeyVerifier("https://x/api/v1", fetch=fetch)
    with pytest.raises(PhoenixKeyError) as ei:
        v.resolve_key("did:a", "ab")
    assert ei.value.status == 404 and ei.value.code == "resolve_failed"
    assert ei.value.user_message_key == "errors.not_found"


def test_resolve_pubkey_gates():
    pub = "02" + "22" * 32

    def serve(status, role="owner"):
        body = json.dumps({"result": {"public_key_hex": pub, "key_role": role, "status": status}}).encode()
        return lambda url, headers: HttpResponse(200, body)

    assert PhoenixKeyVerifier("https://x", fetch=serve("active")).resolve_pubkey("did:a") == pub
    with pytest.raises(PhoenixKeyError) as ei:
        PhoenixKeyVerifier("https://x", fetch=serve("revoked")).resolve_pubkey("did:a")
    assert ei.value.code == "key_revoked"
    with pytest.raises(PhoenixKeyError) as ei:
        PhoenixKeyVerifier("https://x", fetch=serve("active", "viewer")).resolve_pubkey("did:a", "ab")
    assert ei.value.code == "key_role_not_owner"
    # role is only enforced when a specific key was asked for (same as the TS SDK)
    assert PhoenixKeyVerifier("https://x", fetch=serve("active", "viewer")).resolve_pubkey("did:a") == pub


_NONFINITE = [float("nan"), float("inf"), float("-inf")]


@pytest.mark.parametrize("bad", [*_NONFINITE, "100", "NaN", None, True, [100], 100.5, -5, 2**60, 10**400])
def test_auth_proof_unusable_timestamp_is_a_failed_result_not_an_exception(bad):
    v = PhoenixKeyVerifier(
        "https://x", fetch=lambda u, h: pytest.fail("must not fetch"), clock=lambda: 100
    )
    res = v.verify_auth_proof(user_did="d", signature="00", challenge="c", domain="x", timestamp=bad)  # type: ignore[arg-type]
    assert res.valid is False and res.reason == "timestamp_skew" and res.user_did == "d"


def test_auth_proof_whole_number_float_timestamp_still_goes_through():
    pub = "02" + "33" * 32
    urls: list[str] = []

    def fetch(url, headers):
        urls.append(url)
        return HttpResponse(200, _record_body(pub))

    v = PhoenixKeyVerifier("https://x", fetch=fetch, clock=lambda: 100)
    res = v.verify_auth_proof(user_did="d", signature="00", challenge="c", domain="x", timestamp=100.0)  # type: ignore[arg-type]
    assert res.reason != "timestamp_skew" and len(urls) == 1


@pytest.mark.parametrize("bad", _NONFINITE)
def test_intent_nonfinite_timestamp_is_timestamp_skew(bad):
    # abs(now - nan) > 60 is False: without an isfinite check NaN passes the gate.
    v = PhoenixKeyVerifier("https://x", fetch=lambda u, h: pytest.fail("must not fetch"), clock=lambda: 100)
    res = v.verify_intent(user_did="did:a", intent={"type": "T", "timestamp": bad}, signature="00")
    assert res.valid is False and res.reason == "timestamp_skew"


def test_intent_nan_timestamp_parsed_from_json_text_is_timestamp_skew():
    # json.loads accepts the bare tokens NaN / Infinity / -Infinity.
    for token in ("NaN", "Infinity", "-Infinity"):
        intent = json.loads('{"type": "T", "timestamp": ' + token + "}")
        v = PhoenixKeyVerifier("https://x", fetch=lambda u, h: pytest.fail("must not fetch"), clock=lambda: 100)
        res = v.verify_intent(user_did="did:a", intent=intent, signature="00")
        assert res.valid is False and res.reason == "timestamp_skew", token


def test_intent_fractional_timestamp_inside_skew_still_goes_through():
    # Unlike the auth-proof envelope, an intent timestamp is only signed as JSON.
    urls: list[str] = []

    def fetch(url, headers):
        urls.append(url)
        return HttpResponse(404, b"{}")

    v = PhoenixKeyVerifier("https://x", fetch=fetch, clock=lambda: 100)
    res = v.verify_intent(user_did="did:a", intent={"timestamp": 100.5}, signature="00")
    assert res.reason != "timestamp_skew" and len(urls) == 1


# ── the default urllib transport, against a real local socket ─────────────────


class _Handler(BaseHTTPRequestHandler):
    seen: list[tuple[str, str]] = []

    def do_GET(self):  # noqa: N802
        _Handler.seen.append((self.path, self.headers.get("Accept", "")))
        if "missing" in self.path:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"code":1304}')
            return
        body = _record_body("02" + "44" * 32)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


def test_default_transport_over_real_http():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}/api/v1"
        v = PhoenixKeyVerifier(base, timeout=5)
        key = v.resolve_key("did:phoenix:abc", "0xAB")
        assert key.public_key_hex == "02" + "44" * 32 and key.status == "active"
        assert _Handler.seen[0] == ("/api/v1/identity/did%3Aphoenix%3Aabc/pubkey?key=ab", "application/json")
        with pytest.raises(PhoenixKeyError) as ei:
            v.resolve_key("did:missing")
        assert ei.value.status == 404
    finally:
        srv.shutdown()
        srv.server_close()


def test_default_transport_refuses_non_http_schemes():
    v = PhoenixKeyVerifier("file:///etc", timeout=1)
    res = v.verify_auth_proof(user_did="d", signature="00", challenge="c", domain="x", timestamp=int(__import__("time").time()))
    assert not res.valid and res.reason.startswith("resolve_failed:")


def test_default_transport_reports_connection_refused_as_status_zero():
    v = PhoenixKeyVerifier("http://127.0.0.1:9", timeout=1)  # discard port: nothing listens
    with pytest.raises(PhoenixKeyError) as ei:
        v.resolve_key("did:a")
    assert ei.value.status == 0 and ei.value.code == "network_error"


# A Python str can carry a lone surrogate (json.loads of a JSON string holding
# "\\ud800" returns one). TextEncoder in the TypeScript SDK maps it to U+FFFD, so
# both SDKs sign/verify the same bytes and a bad login is a failed result.


def test_envelope_encodes_surrogates_like_text_encoder():
    from phoenixkey_sdk.envelope import encode_legacy_concat, encode_rp_auth_v1

    lone = json.loads('"\\ud800x\\ud83d\\ude00\\udc00"')  # lone, x, pair (joined), lone
    split_pair = "\ud83d\ude00"  # two code points in one str; TextEncoder joins them
    want = bytes.fromhex("efbfbd78f09f9880efbfbd")  # TextEncoder output for `lone`
    v1 = encode_rp_auth_v1(user_did="d", domain=lone, challenge=split_pair, timestamp=1)
    assert want in v1 and bytes.fromhex("00000004f09f9880") in v1
    assert encode_legacy_concat(domain="x", challenge=lone, timestamp=1) == want + b":x:1"


@pytest.mark.parametrize("legacy", [True, False])
@pytest.mark.parametrize("field", ["challenge", "domain"])
def test_auth_proof_lone_surrogate_is_a_failed_result_not_an_exception(field, legacy):
    pub = "02" + "33" * 32
    v = PhoenixKeyVerifier(
        "https://x",
        fetch=lambda u, h: HttpResponse(200, _record_body(pub)),
        clock=lambda: 100,
        accept_legacy_envelope=legacy,
    )
    args = {"challenge": "c", "domain": "x", field: json.loads('"a\\ud800b"')}
    res = v.verify_auth_proof(user_did="d", signature="00" * 64, timestamp=100, **args)
    assert res.valid is False and res.reason == "signature_invalid" and res.user_did == "d"


@pytest.mark.parametrize("sig", [None, 123, b"00" * 64, ["00"]])
def test_auth_proof_non_string_signature_is_verify_failed_not_an_exception(sig):
    pub = "02" + "33" * 32
    v = PhoenixKeyVerifier("https://x", fetch=lambda u, h: HttpResponse(200, _record_body(pub)), clock=lambda: 100)
    res = v.verify_auth_proof(user_did="d", signature=sig, challenge="c", domain="x", timestamp=100)  # type: ignore[arg-type]
    assert res.valid is False and res.reason is not None and res.reason.startswith("verify_failed:")


# The pubkey lookup body goes through the same strict parser as app tokens.


@pytest.mark.parametrize(
    "body",
    [
        _record_body("02" + "33" * 32)[:-1] + b', "n": NaN}',
        b"[" * 200_000 + b"]" * 200_000,
    ],
    ids=["nan", "deep"],
)
def test_pubkey_lookup_body_parsed_strictly(body):
    v = PhoenixKeyVerifier("https://x", fetch=lambda u, h: HttpResponse(200, body), clock=lambda: 100)
    res = v.verify_auth_proof(user_did="d", signature="00" * 64, challenge="c", domain="x", timestamp=100)
    assert res.valid is False and res.reason is not None and res.reason.startswith("resolve_failed:")
