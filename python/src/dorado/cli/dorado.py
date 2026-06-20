"""The dorado CLI: encrypt/decrypt/inspect, raw-key and password modes, streaming.
A port of the Rust/Go/TypeScript CLIs (no GUI)."""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import BinaryIO

from .. import engine
from .. import format as fmt
from ..errors import DoradoError

_VARIANTS = {"256": fmt.T256, "512": fmt.T512, "1024": fmt.T1024}
_MACS = {"skein": fmt.MAC_SKEIN, "hmac-sha256": fmt.MAC_HMAC, "blake3": fmt.MAC_BLAKE3}


def _dehex(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dorado", description="Threefish encryption (educational, unaudited).")
    p.add_argument("command", choices=["encrypt", "decrypt", "inspect"])
    p.add_argument("--key")
    p.add_argument("--key-file")
    p.add_argument("--iv")
    p.add_argument("--tweak", default="00" * 16)
    p.add_argument("--password", action="store_true")
    p.add_argument("--password-stdin", action="store_true")
    p.add_argument("--variant", default="256", choices=list(_VARIANTS))
    p.add_argument("--kdf", default="argon2id", choices=["argon2id", "scrypt", "pbkdf2"])
    p.add_argument("--mac", default="skein", choices=list(_MACS))
    p.add_argument("--argon2-mem-mib", type=int, default=64)
    p.add_argument("--argon2-time", type=int, default=3)
    p.add_argument("--argon2-par", type=int, default=1)
    p.add_argument("--scrypt-logn", type=int, default=15)
    p.add_argument("--scrypt-r", type=int, default=8)
    p.add_argument("--scrypt-p", type=int, default=1)
    p.add_argument("--pbkdf2-rounds", type=int, default=600_000)
    p.add_argument("--chunk-kib", type=int, default=64)
    p.add_argument("--label")
    p.add_argument("--expect-label")
    p.add_argument("--in", dest="in_path")
    p.add_argument("--out", dest="out_path")
    return p


def _kdf_params(a: argparse.Namespace) -> fmt.KdfParams:
    if a.kdf == "argon2id":
        return fmt.KdfParams.argon2id(a.argon2_mem_mib * 1024, a.argon2_time, a.argon2_par)
    if a.kdf == "scrypt":
        return fmt.KdfParams.scrypt(a.scrypt_logn, a.scrypt_r, a.scrypt_p)
    return fmt.KdfParams.pbkdf2(a.pbkdf2_rounds)


def _read_password(a: argparse.Namespace, confirm: bool) -> bytes:
    if a.password_stdin:
        line = sys.stdin.buffer.readline()
        return line.rstrip(b"\r\n")
    pw = getpass.getpass("Password: ").encode()
    if confirm and getpass.getpass("Confirm password: ").encode() != pw:
        raise DoradoError("passwords do not match")
    if not pw:
        raise DoradoError("password must not be empty")
    return pw


def _open_in(a: argparse.Namespace) -> BinaryIO:
    return open(a.in_path, "rb") if a.in_path else sys.stdin.buffer


def _open_out(a: argparse.Namespace) -> BinaryIO:
    return open(a.out_path, "wb") if a.out_path else sys.stdout.buffer


def _password_mode(a: argparse.Namespace) -> bool:
    return a.password or a.password_stdin


def _crypt(a: argparse.Namespace, encrypt: bool) -> None:
    creds = sum(bool(x) for x in (a.key, a.key_file, a.password, a.password_stdin))
    if creds != 1:
        raise DoradoError("provide exactly one of --key, --key-file, --password, --password-stdin")

    if not _password_mode(a):
        key_hex = a.key if a.key else open(a.key_file, "r").read()
        key = _dehex(key_hex)
        variant = {32: fmt.T256, 64: fmt.T512, 128: fmt.T1024}.get(len(key))
        if variant is None:
            raise DoradoError(f"key must be 32, 64, or 128 bytes, got {len(key)}")
        if not a.iv:
            raise DoradoError("--iv is required with --key/--key-file")
        with _open_in(a) as r, _open_out(a) as w:
            engine.raw_ctr_stream(variant, key, _dehex(a.tweak), _dehex(a.iv), r, w)
        return

    if a.iv:
        raise DoradoError("--iv is not used in password mode; the IV is generated and stored")
    if a.password_stdin and not a.in_path:
        raise DoradoError("with --password-stdin, pass the data via --in")

    password = _read_password(a, encrypt)
    if encrypt:
        opts = engine.PasswordOptions(
            variant=_VARIANTS[a.variant],
            kdf=_kdf_params(a),
            mac=_MACS[a.mac],
            tweak=_dehex(a.tweak),
            chunk_size=a.chunk_kib * 1024,
            label=a.label.encode() if a.label else b"",
        )
        with _open_in(a) as r, _open_out(a) as w:
            engine.encrypt_password_stream(password, opts, r, w)
    else:
        expect = a.expect_label.encode() if a.expect_label else None
        with _open_in(a) as r, _open_out(a) as w:
            engine.decrypt_password_stream(password, r, w, expect)


def _inspect(a: argparse.Namespace) -> None:
    with _open_in(a) as r:
        info = engine.inspect_stream(r)
    variant = {fmt.T256: "Threefish-256", fmt.T512: "Threefish-512", fmt.T1024: "Threefish-1024"}[info.variant]
    if info.kdf.kind == fmt.KDF_ARGON2ID:
        kdf = f"Argon2id (memory {info.kdf.m_cost} KiB, iterations {info.kdf.t_cost}, lanes {info.kdf.p_cost})"
    elif info.kdf.kind == fmt.KDF_SCRYPT:
        kdf = f"scrypt (log2(N) {info.kdf.log_n}, r {info.kdf.r}, p {info.kdf.p})"
    else:
        kdf = f"PBKDF2-HMAC-SHA256 (rounds {info.kdf.rounds})"
    mac = {fmt.MAC_SKEIN: "Skein-512", fmt.MAC_HMAC: "HMAC-SHA256", fmt.MAC_BLAKE3: "BLAKE3 (keyed)"}[info.mac]
    label = info.label.decode("utf-8", "replace") if info.label else "(none)"
    sys.stdout.write(
        f"format:   dorado password container (DRDO v{info.version})\n"
        f"variant:  {variant}\nkdf:      {kdf}\nmac:      {mac}\n"
        f"chunk:    {info.chunk_size} bytes\nsalt:     {info.salt_len} bytes\n"
        f"tweak:    {info.tweak.hex()}\nlabel:    {label}\n"
    )


def main(argv: list[str] | None = None) -> int:
    a = _build_parser().parse_args(argv)
    try:
        if a.command == "encrypt":
            _crypt(a, True)
        elif a.command == "decrypt":
            _crypt(a, False)
        else:
            _inspect(a)
    except (DoradoError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
