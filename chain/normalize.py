"""Normalization: undo the cheap evasions before any matcher runs.

Produces a "view" of the text that contains the original plus every decoded
layer, so a rule written against plain text still fires on base64, hex,
URL-encoded, PowerShell -EncodedCommand, homoglyph or zero-width variants.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from functools import lru_cache
from urllib.parse import unquote

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# Small confusables table; extend from Unicode confusables.txt in production.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",  # Cyrillic
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",  # Greek
    "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "ο": "o", "ν": "v", "ι": "i",
    "０": "0", "１": "1", "＠": "@",
})

B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
PS_ENC_RE = re.compile(r"-(?:e|ec|en|enc|enco|encod|encode|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", re.I)
CARET_RE = re.compile(r"\^(.)", re.S)  # cmd.exe escape: ^x -> x (p^o^w^e^r^s^h^e^l^l)

MAX_DEPTH = 3


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in s) / len(s)


def _try_b64(token: str) -> str | None:
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-8", "utf-16-le"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if _printable_ratio(text) > 0.9 and len(text.strip()) >= 4:
            return text
    return None


def _try_hex(token: str) -> str | None:
    token = token.replace("\\x", "")
    try:
        text = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _printable_ratio(text) > 0.9 else None


def canonical(text: str) -> str:
    """Single-layer canonical form: NFKC, zero-width stripped, homoglyphs folded, carets removed."""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(ZERO_WIDTH).translate(HOMOGLYPHS)
    text = CARET_RE.sub(r"\1", text)
    return text


def decode_layers(text: str, depth: int = 0) -> list[str]:
    """Return decoded payloads found inside text (recursive up to MAX_DEPTH)."""
    if depth >= MAX_DEPTH:
        return []
    found: list[str] = []

    for m in PS_ENC_RE.finditer(text):
        dec = _try_b64(m.group(1))
        if dec:
            found.append(dec)
    for m in B64_RE.finditer(text):
        dec = _try_b64(m.group(0))
        if dec and dec not in found:
            found.append(dec)
    for m in HEX_RE.finditer(text):
        dec = _try_hex(m.group(0))
        if dec:
            found.append(dec)
    if "%" in text:
        dec = unquote(text)
        if dec != text:
            found.append(dec)

    nested: list[str] = []
    for item in found:
        nested.extend(decode_layers(canonical(item), depth + 1))
    return [canonical(f) for f in found] + nested


@lru_cache(maxsize=4096)
def normalize(text: str) -> str:
    """Original canonical text plus all decoded layers, newline-joined."""
    base = canonical(text)
    layers = decode_layers(base)
    if not layers:
        return base
    return "\n".join([base, *layers])
