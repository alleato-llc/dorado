"""Key derivation, in its two standard forms.

derive_from_password is password-based derivation (a PBKDF): it stretches a weak,
guessable secret into a raw key, deliberately slowly, under caller-tunable cost
parameters (validate bounds untrusted ones). Argon2id comes from argon2-cffi;
scrypt and PBKDF2-HMAC-SHA256 from the standard library's hashlib (matching the
other ports' use of a KDF library). The raw password bytes are fed directly, so
the derived keys match the Rust reference byte-for-byte.

derive_from_key is key-based derivation (a KBKDF): it splits an already
high-entropy key into independent, domain-separated children, fast (one keyed
hash of the port's own from-scratch primitives, not the KDF libraries above),
with no salt and no cost parameters because there is nothing to stretch. The
keyed hash defaults to Skein-512 (Threefish's native companion);
derive_from_key_with lets a caller pick the PRF (KdfPrf) instead, e.g. BLAKE3 to
keep a ChaCha-family construction single-family top to bottom. The names are the
guardrail: a password must never take the fast path, and a key never needs the
slow one.
"""

from __future__ import annotations

import enum
import hashlib

from argon2.low_level import Type, hash_secret_raw

from . import blake3
from . import format as fmt
from . import skein
from .errors import InvalidParams, MalformedContainer


def derive_from_password(p: fmt.KdfParams, password: bytes, salt: bytes, out_len: int) -> bytes:
    """Stretch password (with salt) into out_len key bytes using params -- deliberately
    slow (the cost is what an attacker pays per guess). For deriving from an
    already-strong key, use derive_from_key instead."""
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


class KdfPrf(enum.Enum):
    """The keyed hash derive_from_key_with fans a master key out with. Both are
    secure PRFs and produce identically strong children; the choice exists only to
    let a construction stay within one cryptographic family (Skein for Threefish,
    BLAKE3 for a ChaCha-family cipher) rather than mixing lineages."""

    SKEIN512 = "skein512"
    """Skein-512 keyed hash (Threefish's native companion). The default, and what
    derive_from_key uses. Accepts a key of any length."""

    BLAKE3 = "blake3"
    """BLAKE3 keyed hash. Requires a 32-byte key (BLAKE3's keyed mode is defined
    only for a 256-bit key); other lengths raise ValueError."""


# Fixed prefix domain-separating derive_from_key's keyed hashing from every other
# keyed use in the engine (DRDOrawE/DRDOrawM in the raw-key split,
# DRDOchnk/DRDOrwFr in the frame MACs).
_DERIVE_FROM_KEY_DOMAIN = b"DRDOkdrv"


def derive_from_key(key: bytes, domain: str, out_len: int) -> bytes:
    """Derive out_len key bytes from an already high-entropy key, separated by
    domain -- key-based derivation (the fast form): one domain-separated Skein-512
    keyed hash, no salt, no cost parameters, because a strong key has nothing to
    stretch. Deterministic: the same key and domain always yield the same bytes,
    and different domains yield computationally unrelated ones, so a caller can
    fan one master key out into independent per-purpose keys
    (derive_from_key(master, "myapp/index", ..), derive_from_key(master,
    "myapp/data", ..)). Never pass a password here: there is no stretching, so a
    guessable input stays guessable -- that is derive_from_password's job. To fan
    out with a different PRF (e.g. BLAKE3), use derive_from_key_with."""
    return derive_from_key_with(KdfPrf.SKEIN512, key, domain, out_len)


def derive_from_key_with(prf: KdfPrf, key: bytes, domain: str, out_len: int) -> bytes:
    """derive_from_key with a caller-chosen PRF (KdfPrf). The domain separation,
    determinism, and "never pass a password" contract are exactly the same; only
    the underlying keyed hash changes. With KdfPrf.SKEIN512 this is byte-for-byte
    identical to derive_from_key. KdfPrf.BLAKE3 requires a 32-byte key."""
    msg = _DERIVE_FROM_KEY_DOMAIN + domain.encode()
    if prf == KdfPrf.SKEIN512:
        return skein.mac(key, out_len, msg)
    if prf == KdfPrf.BLAKE3:
        if len(key) != 32:
            raise ValueError(f"derive_from_key_with(BLAKE3) requires a 32-byte key, got {len(key)}")
        return blake3.keyed_mac(key, out_len, msg)
    raise InvalidParams(f"unknown kdf prf {prf}")


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
        if p.rounds == 0:
            # Zero rounds would "derive" an all-zero key without error.
            raise MalformedContainer("pbkdf2 rounds must be nonzero")
        if p.rounds > 50_000_000:
            raise MalformedContainer("pbkdf2 rounds too large")
    else:
        raise MalformedContainer(f"unknown kdf kind {p.kind}")
