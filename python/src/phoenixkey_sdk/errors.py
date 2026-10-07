"""Error type shared by every verifier in this package."""

from __future__ import annotations

from typing import Any


def _default_user_message_key(status: int) -> str:
    if status == 0:
        return "errors.network"
    if status in (401, 403):
        return "errors.unauthorized"
    if status == 404:
        return "errors.not_found"
    if status in (408, 504):
        return "errors.timeout"
    if status == 429:
        return "errors.rate_limited"
    if status >= 500:
        return "errors.server"
    return "errors.generic"


class PhoenixKeyError(Exception):
    """Failure raised by this package.

    ``status`` is the HTTP status, or ``0`` when there was no HTTP response at
    all (network failure, or a token rejected before any request was made).
    ``code`` is a stable machine-readable string (``"resolve_failed"``,
    ``"signature_invalid"``, ``"aud_mismatch"``, ...) identical to the code the
    TypeScript SDK uses for the same failure.
    """

    def __init__(
        self,
        *,
        status: int,
        message: str,
        code: str | None = None,
        raw_code: int | None = None,
        user_message_key: str | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code if code is not None else "unknown"
        self.raw_code = raw_code
        self.user_message_key = (
            user_message_key if user_message_key is not None else _default_user_message_key(status)
        )
        self.details = details

    @property
    def message(self) -> str:
        return str(self)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"PhoenixKeyError(status={self.status!r}, code={self.code!r}, message={str(self)!r})"
