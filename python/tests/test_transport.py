"""A server (or proxy) that answers with garbage, and an injected fetch that raises,
must come out as PhoenixKeyError / a failed result -- never as a raw stdlib exception."""

from __future__ import annotations

import base64
import contextlib
import json
import socket
import threading

import pytest

from phoenixkey_sdk import AppTokenVerifier, PhoenixKeyError, PhoenixKeyVerifier

_BAD_RESPONSES = {
    # http.client.BadStatusLine
    "bad_status_line": b"GARBAGE\r\n\r\n",
    # http.client.LineTooLong (a header line over 65536 bytes)
    "header_line_too_long": b"HTTP/1.1 200 OK\r\nX: " + b"a" * 70000 + b"\r\n\r\n",
    # body shorter than Content-Length: urllib hands back what arrived, so the
    # failure is the unparsable body (or IncompleteRead on other interpreters)
    "truncated_body": b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"keys"',
}


@contextlib.contextmanager
def _serve(payload: bytes):
    """A one-shot-per-connection TCP server on 127.0.0.1 that sends ``payload`` as is."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return  # listener closed
            try:
                conn.recv(65536)
                conn.sendall(payload)
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=loop, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.getsockname()[1]}/api/v1"
    finally:
        srv.close()


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


_TOKEN = _b64({"alg": "EdDSA", "kid": "k"}) + "." + _b64({"exp": 10**10, "aud": "did:svc"}) + ".AA"


_CODES = {"network_error", "resolve_failed", "jwks_fetch_failed"}


@pytest.mark.parametrize("payload", _BAD_RESPONSES.values(), ids=list(_BAD_RESPONSES))
def test_app_token_verify_garbage_http_answer_is_a_phoenixkey_error(payload):
    with _serve(payload) as url:
        v = AppTokenVerifier(url, on_warning=lambda m: None, timeout=3, clock=lambda: 100)
        with pytest.raises(PhoenixKeyError) as ei:
            v.verify(_TOKEN, "did:svc")
    assert ei.value.code in _CODES
    if payload is not _BAD_RESPONSES["truncated_body"]:
        assert ei.value.status == 0 and ei.value.code == "network_error"


@pytest.mark.parametrize("payload", _BAD_RESPONSES.values(), ids=list(_BAD_RESPONSES))
def test_resolve_key_garbage_http_answer_is_a_phoenixkey_error(payload):
    with _serve(payload) as url:
        with pytest.raises(PhoenixKeyError) as ei:
            PhoenixKeyVerifier(url, timeout=3).resolve_key("did:a")
    assert ei.value.code in _CODES
    if payload is not _BAD_RESPONSES["truncated_body"]:
        assert ei.value.status == 0 and ei.value.code == "network_error"


@pytest.mark.parametrize("payload", _BAD_RESPONSES.values(), ids=list(_BAD_RESPONSES))
def test_verify_intent_garbage_http_answer_is_resolve_failed(payload):
    with _serve(payload) as url:
        v = PhoenixKeyVerifier(url, timeout=3, clock=lambda: 100)
        res = v.verify_intent(user_did="did:a", intent={"timestamp": 100}, signature="00")
    assert res.valid is False and res.reason is not None and res.reason.startswith("resolve_failed:")


def test_injected_fetch_that_raises_anything_is_jwks_fetch_failed():
    def fetch(url, headers):
        raise ConnectionError("connection reset by peer")

    v = AppTokenVerifier("https://x", fetch=fetch, on_warning=lambda m: None, clock=lambda: 100)
    with pytest.raises(PhoenixKeyError) as ei:
        v.verify(_TOKEN, "did:svc")
    assert ei.value.code == "jwks_fetch_failed" and ei.value.status == 0
    assert isinstance(ei.value.__cause__, ConnectionError)
    assert "ConnectionError" in str(ei.value)


def test_injected_fetch_failure_is_not_cached_as_a_jwks():
    answers = iter([ConnectionError("down"), None])
    calls: list[str] = []

    def fetch(url, headers):
        calls.append(url)
        a = next(answers)
        if a is not None:
            raise a
        raise ValueError("second call")

    v = AppTokenVerifier("https://x", fetch=fetch, on_warning=lambda m: None, clock=lambda: 100)
    for _ in range(2):
        with pytest.raises(PhoenixKeyError) as ei:
            v.verify(_TOKEN, "did:svc")
        assert ei.value.code == "jwks_fetch_failed"
    assert len(calls) == 2


def test_injected_fetch_raising_phoenixkey_error_keeps_its_own_code():
    def fetch(url, headers):
        raise PhoenixKeyError(status=0, code="network_error", message="Request failed: boom")

    v = AppTokenVerifier("https://x", fetch=fetch, on_warning=lambda m: None, clock=lambda: 100)
    with pytest.raises(PhoenixKeyError) as ei:
        v.verify(_TOKEN, "did:svc")
    assert ei.value.code == "network_error"


def test_injected_fetch_that_raises_anything_is_resolve_failed_from_resolve_key():
    def fetch(url, headers):
        raise ConnectionError("net down")

    v = PhoenixKeyVerifier("https://x", fetch=fetch, clock=lambda: 100)
    with pytest.raises(PhoenixKeyError) as ei:
        v.resolve_key("did:a")
    assert ei.value.code == "resolve_failed" and ei.value.status == 0
    assert isinstance(ei.value.__cause__, ConnectionError)
    res = v.verify_intent(user_did="did:a", intent={"timestamp": 100}, signature="00")
    assert res.valid is False and res.reason is not None and res.reason.startswith("resolve_failed:")


_PUBKEY = json.dumps(
    {"result": {"public_key_hex": "04" + "11" * 64, "status": "active", "key_role": "owner"}}
).encode()


def _http_200(body: bytes) -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def test_body_over_the_cap_is_refused_not_cut():
    # The first MAX_BODY_BYTES are a valid record plus padding; what follows is a
    # proxy error page. Cutting would accept the record; the whole body is not JSON.
    from phoenixkey_sdk._http import MAX_BODY_BYTES

    body = _PUBKEY + b" " * (MAX_BODY_BYTES - len(_PUBKEY)) + b"<html>proxy error</html>"
    with _serve(_http_200(body)) as url:
        with pytest.raises(PhoenixKeyError) as ei:
            PhoenixKeyVerifier(url, timeout=5).resolve_key("did:a")
    assert ei.value.status == 0 and ei.value.code == "network_error"
    assert "exceeds" in str(ei.value)


def test_body_at_the_cap_is_accepted():
    from phoenixkey_sdk._http import MAX_BODY_BYTES

    body = _PUBKEY + b" " * (MAX_BODY_BYTES - len(_PUBKEY))
    with _serve(_http_200(body)) as url:
        key = PhoenixKeyVerifier(url, timeout=5).resolve_key("did:a")
    assert key.status == "active"


def test_redirect_to_ftp_is_refused_before_following():
    payload = b"HTTP/1.1 302 Found\r\nLocation: ftp://127.0.0.1:1/keys\r\nContent-Length: 0\r\n\r\n"
    with _serve(payload) as url:
        with pytest.raises(PhoenixKeyError) as ei:
            PhoenixKeyVerifier(url, timeout=3).resolve_key("did:a")
        v = AppTokenVerifier(url, on_warning=lambda m: None, timeout=3, clock=lambda: 100)
        with pytest.raises(PhoenixKeyError) as ej:
            v.verify(_TOKEN, "did:svc")
    for e in (ei.value, ej.value):
        assert e.status == 0 and e.code == "network_error"
        assert "non-http(s)" in str(e)


def test_jwks_body_over_the_cap_is_refused_not_cut():
    from phoenixkey_sdk._http import MAX_BODY_BYTES

    jwks = json.dumps({"keys": []}).encode()
    body = jwks + b" " * (MAX_BODY_BYTES - len(jwks)) + b"<html>proxy error</html>"
    with _serve(_http_200(body)) as url:
        v = AppTokenVerifier(url, on_warning=lambda m: None, timeout=5, clock=lambda: 100)
        with pytest.raises(PhoenixKeyError) as ei:
            v.verify(_TOKEN, "did:svc")
    assert ei.value.status == 0 and ei.value.code == "network_error"
    assert "exceeds" in str(ei.value)
