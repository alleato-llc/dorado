"""The gyotaku CLI: Skein-512 file hashing, like sha256sum but Skein. Streams in
constant memory. Named for the Japanese art of fish-printing: a file's fingerprint."""

from __future__ import annotations

import argparse
import sys

from .. import skein


def _out_len(bits: int) -> int:
    if bits <= 0 or bits % 8 != 0:
        raise ValueError("--bits must be a positive multiple of 8")
    return bits // 8


def _digest_file(path: str, out_len: int) -> str:
    with open(path, "rb") as f:
        return skein.hash_stream(out_len, f).hex()


def _format_line(tag: bool, digest: str, name: str) -> str:
    return f"SKEIN-512 ({name}) = {digest}" if tag else f"{digest}  {name}"


def _run_check(files: list[str]) -> int:
    checked = failed = 0
    for lst in files:
        with open(lst, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = _parse_check_line(line)
                if parsed is None:
                    print(f"error: {lst}: malformed line: {line}", file=sys.stderr)
                    return 1
                expected, name = parsed
                checked += 1
                try:
                    got = _digest_file(name, len(expected) // 2)
                except OSError:
                    print(f"{name}: FAILED open or read")
                    failed += 1
                    continue
                if got.lower() == expected.lower():
                    print(f"{name}: OK")
                else:
                    print(f"{name}: FAILED")
                    failed += 1
    if checked == 0:
        print("error: no digests found to verify", file=sys.stderr)
        return 1
    if failed:
        print(f"error: {failed} of {checked} digests did NOT match", file=sys.stderr)
        return 1
    return 0


def _parse_check_line(line: str):
    if line.startswith("SKEIN-512 (") and ") = " in line:
        name = line[len("SKEIN-512 (") : line.rindex(") = ")]
        digest = line[line.rindex(") = ") + 4 :].strip()
        return digest, name
    parts = line.split(None, 1)
    if len(parts) == 2:
        return parts[0], parts[1].lstrip("*").strip()
    return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="gyotaku", description="Skein-512 file hashing (educational, unaudited).")
    p.add_argument("--bits", type=int, default=256, help="output length in bits (a multiple of 8)")
    p.add_argument("-c", "--check", action="store_true", help="verify checksum lists")
    p.add_argument("--tag", action="store_true", help='BSD-style output: "SKEIN-512 (file) = digest"')
    p.add_argument("files", nargs="*")
    a = p.parse_args(argv)

    try:
        if a.check:
            if a.tag:
                raise ValueError("--tag cannot be combined with --check")
            if not a.files:
                raise ValueError("--check needs at least one checksum file")
            return _run_check(a.files)

        out_len = _out_len(a.bits)
        if not a.files:
            digest = skein.hash_stream(out_len, sys.stdin.buffer).hex()
            print(_format_line(a.tag, digest, "-") if a.tag else digest)
        else:
            for path in a.files:
                print(_format_line(a.tag, _digest_file(path, out_len), path))
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
