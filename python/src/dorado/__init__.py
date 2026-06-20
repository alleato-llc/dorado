"""dorado: a from-scratch Threefish cipher and authenticated container (Python port).

Educational and unaudited; for real data prefer a vetted library. The on-disk format
is byte-for-byte cross-compatible with the Rust reference and the Go, Java, and
TypeScript ports.
"""

from __future__ import annotations

from . import blake3, skein, threefish
from .engine import (
    ContainerInfo,
    PasswordOptions,
    decrypt_password,
    decrypt_password_stream,
    default_options,
    encrypt_password,
    encrypt_password_stream,
    inspect,
    inspect_stream,
    raw_ctr,
    raw_ctr_stream,
)
from .errors import DoradoError
from .format import (
    KDF_ARGON2ID,
    KDF_PBKDF2,
    KDF_SCRYPT,
    MAC_BLAKE3,
    MAC_HMAC,
    MAC_SKEIN,
    T256,
    T512,
    T1024,
    KdfParams,
)

__all__ = [
    "threefish",
    "skein",
    "blake3",
    "PasswordOptions",
    "ContainerInfo",
    "KdfParams",
    "DoradoError",
    "default_options",
    "encrypt_password",
    "decrypt_password",
    "inspect",
    "raw_ctr",
    "encrypt_password_stream",
    "decrypt_password_stream",
    "raw_ctr_stream",
    "inspect_stream",
    "T256",
    "T512",
    "T1024",
    "MAC_SKEIN",
    "MAC_HMAC",
    "MAC_BLAKE3",
    "KDF_ARGON2ID",
    "KDF_SCRYPT",
    "KDF_PBKDF2",
]
