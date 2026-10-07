"""Canonical JSON, byte-for-byte identical to the TypeScript SDK.

The signed bytes of an intent are the UTF-8 encoding of its canonical JSON:
keys sorted at every level, no whitespace. A signature only verifies if this
produces exactly the bytes the signer produced, so the places where Python's own
``json`` module and JavaScript's ``JSON.stringify`` disagree are all handled
here by hand:

* **Key order.** JavaScript sorts keys by UTF-16 code unit; Python's ``sorted``
  sorts by code point. They differ for keys containing characters outside the
  Basic Multilingual Plane (emoji) next to characters in U+E000-U+FFFF.
* **Numbers.** JavaScript prints ``1.0`` as ``1``, ``1e21`` as ``1e+21`` and
  ``1e-7`` as ``1e-7``; Python prints ``1.0``, ``1e+21``, ``1e-07``. NaN and
  infinities become ``null``.
* **Strings.** ``JSON.stringify`` escapes ``"``, ``\\``, control characters
  below U+0020 (short forms for ``\\b \\f \\n \\r \\t``, ``\\u00xx`` otherwise) and
  lone surrogates; it leaves U+007F, U+2028 and U+2029 alone. Python's encoder
  would emit lone surrogates raw, which then cannot be UTF-8 encoded.
* **Absent vs null.** A ``None`` value is the JSON ``null`` and keeps its key; a
  key that is not in the mapping is simply absent -- same as a missing or
  ``undefined`` property in the TypeScript object.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any, Mapping

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _js_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        short = _SHORT_ESCAPES.get(cp)
        if short is not None:
            out.append(short)
        elif cp < 0x20 or 0xD800 <= cp <= 0xDFFF:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _js_number(x: int | float) -> str:
    """``JSON.stringify(Number)`` -- ECMA-262 Number::toString plus the null rule."""
    if isinstance(x, int):
        # A JSON parser in JavaScript would have turned this into a double.
        # Reproduce that so the same document gives the same bytes everywhere.
        if -(2**53) <= x <= 2**53:
            return str(x)
        x = float(x)
    if math.isnan(x) or math.isinf(x):
        return "null"
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    dec = Decimal(repr(abs(x)))
    _, digit_tuple, exponent = dec.as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    # value = 0.DIGITS * 10**n
    n = len(digit_tuple) + int(exponent)
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        exp = ("+" if e >= 0 else "-") + str(abs(e))
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + exp
    return sign + body


def _utf16_key(k: str) -> bytes:
    # Big-endian UTF-16 bytes compare exactly like JavaScript's default
    # string sort (UTF-16 code unit order). "surrogatepass" keeps lone
    # surrogates sortable instead of raising.
    return k.encode("utf-16-be", "surrogatepass")


def canonical_json_string(obj: Any) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return _js_number(obj)
    if isinstance(obj, str):
        return _js_string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json_string(v) for v in obj) + "]"
    if isinstance(obj, Mapping):
        for k in obj:
            if not isinstance(k, str):
                raise TypeError(f"canonical JSON object keys must be str, got {type(k).__name__}")
        return (
            "{"
            + ",".join(
                f"{_js_string(k)}:{canonical_json_string(obj[k])}" for k in sorted(obj, key=_utf16_key)
            )
            + "}"
        )
    raise TypeError(f"Cannot canonicalize value of type {type(obj).__name__}")


def canonical_json_bytes(obj: Any) -> bytes:
    """UTF-8 bytes of the canonical JSON of ``obj`` (what an intent signature covers)."""
    return canonical_json_string(obj).encode("utf-8")
