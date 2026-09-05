#!/usr/bin/env python3
"""
inspect_exp.py — Figure out what format the SonicWall EXP files actually are.

Drop one (or more) of your real EXP downloads into ./input/ and run:

    python3 inspect_exp.py

This does NOT parse anything yet. It just reports what each file *is* (zip,
gzip, plaintext key=value, obfuscated blob, etc.) so we can build the correct
parser. Nothing is modified; extracted samples go to ./data/_inspect/.
"""

import gzip
import io
import os
import string
import zipfile

INPUT_DIR = "input"
INSPECT_DIR = os.path.join("data", "_inspect")

PRINTABLE = set(bytes(string.printable, "ascii"))


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data[:4096] if b in PRINTABLE)
    return good / len(data[:4096])


def hexdump(data: bytes, n: int = 64) -> str:
    chunk = data[:n]
    hx = " ".join(f"{b:02x}" for b in chunk)
    txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"  hex : {hx}\n  ascii: {txt}"


def sniff(name: str, data: bytes, depth: int = 0) -> None:
    pad = "  " * depth
    print(f"{pad}• {name}  ({len(data)} bytes)")
    print(f"{pad}{hexdump(data)}")

    # ZIP?
    if data[:2] == b"PK":
        print(f"{pad}  => looks like a ZIP archive")
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            for info in zf.infolist():
                print(f"{pad}    - {info.filename} ({info.file_size} bytes)")
                sniff(info.filename, zf.read(info), depth + 2)
        except Exception as e:
            print(f"{pad}  (could not read zip: {e})")
        return

    # GZIP?
    if data[:2] == b"\x1f\x8b":
        print(f"{pad}  => looks like GZIP")
        try:
            inner = gzip.decompress(data)
            sniff(name + " [gunzipped]", inner, depth + 1)
        except Exception as e:
            print(f"{pad}  (could not gunzip: {e})")
        return

    ratio = printable_ratio(data)
    print(f"{pad}  printable ratio (first 4KB): {ratio:.0%}")

    if ratio > 0.85:
        text = data.decode("latin-1", errors="replace")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        has_kv = sum(1 for ln in lines[:50] if "=" in ln)
        print(f"{pad}  => looks like TEXT ({len(lines)} non-empty lines, "
              f"{has_kv}/{min(50, len(lines))} contain '=')")
        print(f"{pad}  first lines:")
        for ln in lines[:8]:
            print(f"{pad}    | {ln[:120]}")
    else:
        print(f"{pad}  => looks like BINARY / obfuscated (not plain text)")


def main() -> None:
    os.makedirs(INSPECT_DIR, exist_ok=True)
    files = [f for f in sorted(os.listdir(INPUT_DIR))
             if not f.startswith(".")]
    if not files:
        print(f"No files found in ./{INPUT_DIR}/ — drop a sample EXP there first.")
        return
    for f in files:
        path = os.path.join(INPUT_DIR, f)
        if not os.path.isfile(path):
            continue
        print("=" * 70)
        with open(path, "rb") as fh:
            data = fh.read()
        sniff(f, data)
        print()


if __name__ == "__main__":
    main()
