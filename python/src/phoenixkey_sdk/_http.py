"""Minimal HTTP transport on the standard library.

Everything that talks to the network goes through a ``Fetch`` callable, so tests
(and callers with their own HTTP stack) can inject one -- the same way the
TypeScript SDK lets you inject ``fetch``.
"""

from __future__ import annotations

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


def make_urllib_fetch(timeout: float = 10.0) -> Fetch:
    """Build the default ``Fetch`` on top of ``urllib.request``.

    A non-2xx answer is returned as an ``HttpResponse`` (not raised) so callers
    decide what it means. A failure to get any answer raises ``PhoenixKeyError``
    with ``status == 0``.
    """

    def fetch(url: str, headers: Mapping[str, str]) -> HttpResponse:
        if not url.lower().startswith(("https://", "http://")):
            raise PhoenixKeyError(
                status=0,
                code="network_error",
                message="Only http(s) URLs are supported",
            )
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked above
                return HttpResponse(resp.status, resp.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES])
        except urllib.error.HTTPError as e:
            try:
                body = e.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
            except Exception:  # pragma: no cover - body unreadable
                body = b""
            return HttpResponse(e.code, body)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise PhoenixKeyError(status=0, code="network_error", message=f"Request failed: {e}") from e

    return fetch
