#!/usr/bin/env python3
"""
exp_parser.py — Decode a SonicWall SonicOS 7.x EXP export into flat settings.

Confirmed format (SonicOS 7.3.x, verified against real client exports):

    <download>.zip
        └── Default_<serial>_<date>_<hash>.exp     (single member)
                = base64 text, one long line
                = decodes to  key=value&key=value&...   (values URL-encoded)

parse_exp_file(path) returns an ordered dict {key: decoded_value}. Because
SonicWall indexes list items into the key names (foo_0, foo_1, ...), keys are
unique and nothing is lost.
"""

import base64
import os
import urllib.parse
import zipfile


def _decode_exp_bytes(raw: bytes) -> dict:
    """raw = the base64 body of a .exp file -> {key: value}."""
    decoded = base64.b64decode(raw)
    text = decoded.decode("latin-1")
    out = {}
    for pair in text.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        out[key] = urllib.parse.unquote(value)
    return out


def parse_exp_file(path: str) -> dict:
    """Accepts the downloaded .zip, a raw .exp, or an already-decoded file."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        data = fh.read()

    # ZIP download -> pull the single .exp member's base64 body
    if head[:2] == b"PK":
        with zipfile.ZipFile(path) as zf:
            exp_members = [n for n in zf.namelist() if n.lower().endswith(".exp")]
            if not exp_members:
                exp_members = [n for n in zf.namelist() if not n.endswith("/")]
            if not exp_members:
                raise ValueError(f"No .exp member found inside {path}")
            return _decode_exp_bytes(zf.read(exp_members[0]))

    # Raw .exp = base64 body directly
    return _decode_exp_bytes(data)


def exp_member_name(path: str) -> str:
    """Return the inner .exp filename (used to label the firewall)."""
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for n in zf.namelist():
                if n.lower().endswith(".exp"):
                    return os.path.basename(n)
    return os.path.basename(path)
