"""The three key-derivation functions. Argon2id comes from argon2-cffi; scrypt and
PBKDF2-HMAC-SHA256 from the standard library's hashlib (matching the other ports'
use of a KDF library). The raw password bytes are fed directly, so the derived keys
match the Rust reference byte-for-byte.
"""

from __future__ import annotations

import hashlib

from argon2.low_level import Type, hash_secret_raw

from . import format as fmt
from .errors import InvalidParams, MalformedContainer


def derive(p: fmt.KdfParams, password: bytes, salt: bytes, out_len: int) -> bytes:
    """Stretch password (with salt) into out_len key bytes using params."""
    if p.kind == fmt.KDF_ARGON2ID:
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=p.t_cost,
            memory_cost=p.m_cost,
            parallelism=p.p_cost,
            hash_len=out_len,
            type=Type.ID,
            version=19,
        )
    if p.kind == fmt.KDF_SCRYPT:
        n = 1 << p.log_n
        # OpenSSL's scrypt refuses to allocate more than maxmem; size it to the
        # parameters (this only gates the computation, not the output).
        maxmem = min(0x7FFFFFFF, 128 * p.r * (n + p.p + 2) + (1 << 20))
        return hashlib.scrypt(password, salt=salt, n=n, r=p.r, p=p.p, dklen=out_len, maxmem=maxmem)
    if p.kind == fmt.KDF_PBKDF2:
        return hashlib.pbkdf2_hmac("sha256", password, salt, p.rounds, dklen=out_len)
    raise InvalidParams(f"unknown kdf kind {p.kind}")


def validate(p: fmt.KdfParams) -> None:
    """Reject KDF parameters whose cost is unreasonably large. The cost comes from an
    untrusted header. Bounds match the other ports."""
    if p.kind == fmt.KDF_ARGON2ID:
        if p.m_cost > (1 << 21):
            raise MalformedContainer("argon2 memory cost too large")
        if p.t_cost > 64:
            raise MalformedContainer("argon2 time cost too large")
        if p.p_cost > 16:
            raise MalformedContainer("argon2 parallelism too large")
    elif p.kind == fmt.KDF_SCRYPT:
        if p.log_n > 21:
            raise MalformedContainer("scrypt cost (log2 N) too large")
        if p.r > 32:
            raise MalformedContainer("scrypt block factor r too large")
        if p.p > 16:
            raise MalformedContainer("scrypt parallelism p too large")
    elif p.kind == fmt.KDF_PBKDF2:
        if p.rounds > 50_000_000:
            raise MalformedContainer("pbkdf2 rounds too large")
    else:
        raise MalformedContainer(f"unknown kdf kind {p.kind}")
