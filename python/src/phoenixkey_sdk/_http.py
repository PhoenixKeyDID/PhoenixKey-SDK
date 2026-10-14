"""Minimal HTTP transport on the standard library.

Everything that talks to the network goes through a ``Fetch`` callable, so tests
(and callers with their own HTTP stack) can inject one -- the same way the
TypeScript SDK lets you inject ``fetch``.
"""

from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping

from .errors import PhoenixKeyError

# A pubkey record or a JWKS is a few hundred bytes. Refuse to buffer more than
# this from a server (or a proxy that went wrong).
MAX_BODY_BYTES = 1 << 20

USER_AGENT = "phoenixkey-sdk-python/0.1.0"


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


Fetch = Callable[[str, Mapping[str, str]], HttpResponse]


def _is_http_url(url: str) -> bool:
    return url.lower().startswith(("https://", "http://"))


class _HttpOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to http(s).

    urllib's default handler also follows a redirect to ``ftp://``; the answer then
    has no HTTP status, and a verifier must not read keys from a non-HTTP source.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if not _is_http_url(newurl):
            raise PhoenixKeyError(
                status=0,
                code="network_error",
                message="Redirect to a non-http(s) URL refused",
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def make_urllib_fetch(timeout: float = 10.0) -> Fetch:
    """Build the default ``Fetch`` on top of ``urllib.request``.

    A non-2xx answer is returned as an ``HttpResponse`` (not raised) so callers
    decide what it means. A failure to get any answer raises ``PhoenixKeyError``
    with ``status == 0``.
    """

    opener = urllib.request.build_opener(_HttpOnlyRedirect)

    def fetch(url: str, headers: Mapping[str, str]) -> HttpResponse:
        if not _is_http_url(url):
            raise PhoenixKeyError(
                status=0,
                code="network_error",
                message="Only http(s) URLs are supported",
            )
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers}, method="GET")
        try:
            with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked above and on redirect
                status = resp.status
                body = resp.read(MAX_BODY_BYTES + 1)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
            except Exception:  # pragma: no cover - body unreadable
                body = b""
            return HttpResponse(e.code, body)
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as e:
            # HTTPException (BadStatusLine, LineTooLong, IncompleteRead, ...) is not
            # an OSError: a server that answers with garbage must not escape raw.
            raise PhoenixKeyError(status=0, code="network_error", message=f"Request failed: {e}") from e
        if not isinstance(status, int):
            raise PhoenixKeyError(status=0, code="network_error", message="Response has no HTTP status")
        if len(body) > MAX_BODY_BYTES:
            # Refuse, do not cut: a prefix of an oversized body can itself be valid JSON
            # (a record followed by padding and a proxy error page), and the TS SDK
            # rejects the whole body.
            raise PhoenixKeyError(
                status=0,
                code="network_error",
                message=f"Response body exceeds {MAX_BODY_BYTES} bytes",
            )
        return HttpResponse(status, body)

    return fetch
