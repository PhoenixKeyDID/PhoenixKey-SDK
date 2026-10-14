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


def _join_surrogate_pairs(s: str) -> str:
    """Join a surrogate pair held as two characters into one code point.

    A str can hold a pair as two characters (a Python literal with the two escapes,
    or two lone halves joined by the caller). JavaScript sees one astral character
    there; join the pair as envelope._utf8 does and leave lone halves as they are.
    """
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")
    return s


def _js_string(s: str) -> str:
    out = ['"']
    s = _join_surrogate_pairs(s)
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


def _js_number(x: int | float, strict: bool = False) -> str:
    """``JSON.stringify(Number)`` -- ECMA-262 Number::toString plus the null rule.

    ``strict`` refuses what JavaScript silently degrades: a non-finite float
    (``null``) and an integer that a double cannot hold exactly. JavaScript
    prints every double below 1e21 in plain digits, so an integer survives the
    round trip when the digits JavaScript prints for ``float(x)`` are the digits
    of ``x`` itself (``10**18`` does, ``2**60`` does not: it prints as
    ``1152921504606847000``). A verifier must not check a signature over bytes
    that differ from what the signer meant, so it passes ``strict=True``.
    """
    if isinstance(x, int):
        # A JSON parser in JavaScript would have turned this into a double.
        # Reproduce that so the same document gives the same bytes everywhere.
        if -(2**53) <= x <= 2**53:
            return str(x)
        if strict:
            if abs(x) < 10**21 and _js_number(float(x)) == str(x):
                return str(x)
            raise ValueError("integer that a JSON number (an IEEE double) cannot hold exactly")
        try:
            x = float(x)
        except OverflowError:
            # Number("1" + "0" * 400) is Infinity in JavaScript and
            # JSON.stringify(Infinity) is "null".
            return "null"
    if math.isnan(x) or math.isinf(x):
        if strict:
            raise ValueError("non-finite number")
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


def canonical_json_string(obj: Any, *, strict: bool = False) -> str:
    """Canonical JSON text of ``obj``.

    ``strict=True`` raises ``ValueError`` for a non-finite float or an integer
    a double cannot hold exactly, instead of mapping it the way ``JSON.stringify``
    does. Deep nesting still ends in ``RecursionError``; the caller on an untrusted path
    (``PhoenixKeyVerifier.verify_intent``) catches exactly that.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return _js_number(obj, strict)
    if isinstance(obj, str):
        return _js_string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json_string(v, strict=strict) for v in obj) + "]"
    if isinstance(obj, Mapping):
        joined: dict[str, str] = {}
        for k in obj:
            if not isinstance(k, str):
                raise TypeError(f"canonical JSON object keys must be str, got {type(k).__name__}")
            j = _join_surrogate_pairs(k)
            if j in joined:
                # Two Python keys, one JavaScript key: a JS object cannot hold both,
                # so there is no canonical form both sides agree on.
                raise ValueError(
                    f"canonical JSON object keys {joined[j]!r} and {k!r} are the same key in JavaScript"
                )
            joined[j] = k
        return (
            "{"
            + ",".join(
                f"{_js_string(k)}:{canonical_json_string(obj[k], strict=strict)}"
                for k in sorted(obj, key=_utf16_key)
            )
            + "}"
        )
    raise TypeError(f"Cannot canonicalize value of type {type(obj).__name__}")


def canonical_json_bytes(obj: Any, *, strict: bool = False) -> bytes:
    """UTF-8 bytes of the canonical JSON of ``obj`` (what an intent signature covers)."""
    return canonical_json_string(obj, strict=strict).encode("utf-8")
