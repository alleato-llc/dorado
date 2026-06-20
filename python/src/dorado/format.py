"""The on-disk container format (magic "DRDO", version 4; version 3 still read):
header marshalling and streaming parse. Matches the Rust reference and the other
ports byte-for-byte. All multi-byte integers are big-endian.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO

from .errors import DoradoError

MAGIC = b"DRDO"
VERSION = 4
DEFAULT_CHUNK_BYTES = 64 * 1024
MAX_CHUNK_BYTES = 1 << 30
MAX_LABEL_LEN = 4096
MAC_KEY_LEN = 32
TAG_LEN = 32

# Variant codes.
T256 = 0
T512 = 1
T1024 = 2

# MAC ids.
MAC_HMAC = 1
MAC_SKEIN = 2
MAC_BLAKE3 = 3

# KDF ids.
KDF_ARGON2ID = 1
KDF_SCRYPT = 2
KDF_PBKDF2 = 3
PRF_HMAC_SHA256 = 1


def key_len(variant: int) -> int:
    """The variant's key/block/IV length in bytes."""
    if variant == T256:
        return 32
    if variant == T512:
        return 64
    if variant == T1024:
        return 128
    raise ValueError(f"unknown variant code {variant}")


def block_len(variant: int) -> int:
    return key_len(variant)


@dataclass
class KdfParams:
    kind: int
    m_cost: int = 0  # argon2id: memory in KiB
    t_cost: int = 0  # argon2id: iterations
    p_cost: int = 0  # argon2id: lanes
    log_n: int = 0   # scrypt: log2(N)
    r: int = 0       # scrypt: block factor
    p: int = 0       # scrypt: parallelism
    rounds: int = 0  # pbkdf2: iterations
    prf: int = 0     # pbkdf2: PRF id

    @staticmethod
    def argon2id(m_cost_kib: int, t_cost: int, p_cost: int) -> "KdfParams":
        return KdfParams(KDF_ARGON2ID, m_cost=m_cost_kib, t_cost=t_cost, p_cost=p_cost)

    @staticmethod
    def scrypt(log_n: int, r: int, p: int) -> "KdfParams":
        return KdfParams(KDF_SCRYPT, log_n=log_n, r=r, p=p)

    @staticmethod
    def pbkdf2(rounds: int) -> "KdfParams":
        return KdfParams(KDF_PBKDF2, rounds=rounds, prf=PRF_HMAC_SHA256)


@dataclass
class Header:
    version: int
    variant: int
    kdf: KdfParams
    mac: int
    chunk_size: int
    salt: bytes
    tweak: bytes
    iv: bytes
    label: bytes


def marshal(h: Header) -> bytes:
    """Serialize a header to its on-disk bytes."""
    out = bytearray(MAGIC)
    out += bytes([h.version, h.variant])
    if h.kdf.kind == KDF_ARGON2ID:
        out += bytes([1]) + struct.pack(">III", h.kdf.m_cost, h.kdf.t_cost, h.kdf.p_cost)
    elif h.kdf.kind == KDF_SCRYPT:
        out += bytes([2, h.kdf.log_n]) + struct.pack(">II", h.kdf.r, h.kdf.p)
    elif h.kdf.kind == KDF_PBKDF2:
        out += bytes([3]) + struct.pack(">I", h.kdf.rounds) + bytes([h.kdf.prf])
    else:
        raise ValueError(f"unknown kdf kind {h.kdf.kind}")
    out += bytes([h.mac]) + struct.pack(">I", h.chunk_size)
    out += bytes([len(h.salt)]) + h.salt + h.tweak + h.iv
    if h.version >= 4:
        out += struct.pack(">H", len(h.label)) + h.label
    return bytes(out)


def read_full(reader: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes (looping over partial reads), or fewer at end of input."""
    parts = []
    remaining = n
    while remaining > 0:
        chunk = reader.read(remaining)
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def _exact(reader: BinaryIO, n: int, what: str) -> bytes:
    b = read_full(reader, n)
    if len(b) != n:
        raise DoradoError(f"header truncated reading {what}")
    return b


def _u8(reader: BinaryIO, what: str) -> int:
    return _exact(reader, 1, what)[0]


def _u16(reader: BinaryIO, what: str) -> int:
    return struct.unpack(">H", _exact(reader, 2, what))[0]


def _u32(reader: BinaryIO, what: str) -> int:
    return struct.unpack(">I", _exact(reader, 4, what))[0]


def read(reader: BinaryIO) -> Header:
    """Read a header from reader, leaving it positioned at the first frame."""
    if _exact(reader, 4, "magic") != MAGIC:
        raise DoradoError("not a dorado password file (bad magic)")
    version = _u8(reader, "version")
    if version not in (3, VERSION):
        raise DoradoError(f"unsupported format version {version}")
    variant = _u8(reader, "variant")
    if variant > 2:
        raise DoradoError(f"unknown variant code {variant}")

    kdf_id = _u8(reader, "kdf id")
    if kdf_id == KDF_ARGON2ID:
        kdf = KdfParams(KDF_ARGON2ID, m_cost=_u32(reader, "m_cost"), t_cost=_u32(reader, "t_cost"), p_cost=_u32(reader, "p_cost"))
    elif kdf_id == KDF_SCRYPT:
        kdf = KdfParams(KDF_SCRYPT, log_n=_u8(reader, "log_n"), r=_u32(reader, "r"), p=_u32(reader, "p"))
    elif kdf_id == KDF_PBKDF2:
        rounds = _u32(reader, "rounds")
        prf = _u8(reader, "prf")
        if prf != PRF_HMAC_SHA256:
            raise DoradoError(f"unknown prf id {prf}")
        kdf = KdfParams(KDF_PBKDF2, rounds=rounds, prf=prf)
    else:
        raise DoradoError(f"unknown kdf id {kdf_id}")

    mac = _u8(reader, "mac id")
    if not 1 <= mac <= 3:
        raise DoradoError(f"unknown mac id {mac}")
    chunk_size = _u32(reader, "chunk size")
    salt_len = _u8(reader, "salt len")
    salt = _exact(reader, salt_len, "salt")
    tweak = _exact(reader, 16, "tweak")
    iv = _exact(reader, block_len(variant), "iv")
    if version >= 4:
        label_len = _u16(reader, "label len")
        if label_len > MAX_LABEL_LEN:
            raise DoradoError(f"label too long ({label_len} bytes)")
        label = _exact(reader, label_len, "label")
    else:
        label = b""
    return Header(version, variant, kdf, mac, chunk_size, salt, tweak, iv, label)
