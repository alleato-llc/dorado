"""Property/fuzz tests for the container parsers. These feed thousands of
pseudo-random, truncated, and mutated byte strings to decrypt and inspect and assert
that every call either succeeds or raises a DoradoError (or one of its subclasses),
and never an unexpected exception (IndexError, struct.error, MemoryError, ...) and
never hangs. The randomness is seeded so failures reproduce; no external fuzzing
dependency is used (stdlib random only)."""

import random
import struct

import pytest

from dorado import (
    DoradoError,
    KdfParams,
    MAC_SKEIN,
    PasswordOptions,
    T256,
    decrypt_password,
    encrypt_password,
    inspect,
)

PW = b"correct horse battery staple"


@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch):
    """Keep the fuzz fast and hang-free. A mutated header can carry a large but
    validate-accepted KDF cost, and running the real Argon2/scrypt/PBKDF2 on it would
    be slow. The fuzz targets the parse and validation surface, not the KDF math, so
    we stub derive to a deterministic fast function. The header is still fully parsed
    and validated, and the MAC still runs over real key bytes; the derived key just is
    not the costly one (decryption then fails authentication, which is fine here)."""
    import hashlib

    def _cheap(p, password, salt, out_len):
        return hashlib.shake_256(bytes(password) + bytes(salt)).digest(out_len)

    # engine refers to this module as kdf_mod, so patching the module attribute here
    # covers both the kdf module and the engine's reference to it (same object).
    monkeypatch.setattr("dorado.kdf.derive", _cheap)


# Anything outside this set is a bug: the parsers must categorize every input as a
# success or a DoradoError, not leak a low-level exception.
_FORBIDDEN = (
    IndexError,
    struct.error,
    MemoryError,
    OverflowError,
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    UnicodeDecodeError,
)


def _check(data: bytes) -> None:
    """Run every public parser entry point on data and assert it only ever returns or
    raises a DoradoError."""
    for fn in (
        lambda: decrypt_password(PW, data),
        lambda: decrypt_password(PW, data, b"label"),
        lambda: inspect(data),
    ):
        try:
            fn()
        except DoradoError:
            pass
        except _FORBIDDEN as e:  # pragma: no cover - only on a real bug
            raise AssertionError(f"unexpected {type(e).__name__}: {e!r} for {data[:32]!r}") from e


def _real_container() -> bytes:
    opts = PasswordOptions(variant=T256, kdf=KdfParams.pbkdf2(2_000), mac=MAC_SKEIN)
    opts.chunk_size = 64
    payload = bytes(range(256)) * 4
    return encrypt_password(PW, opts, payload)


def test_fuzz_random_bytes():
    rng = random.Random(0xD0240)
    for _ in range(2000):
        n = rng.randint(0, 512)
        data = bytes(rng.randrange(256) for _ in range(n))
        _check(data)


def test_fuzz_magic_prefixed_random():
    # Bytes that start with the right magic exercise deeper header-parse paths.
    from dorado import format as fmt

    rng = random.Random(0xBEEF)
    for _ in range(2000):
        n = rng.randint(0, 256)
        data = fmt.MAGIC + bytes(rng.randrange(256) for _ in range(n))
        _check(data)


def test_fuzz_truncations_of_real_container():
    base = _real_container()
    for cut in range(len(base) + 1):
        _check(base[:cut])


def test_fuzz_single_byte_mutations_of_real_container():
    base = _real_container()
    rng = random.Random(0x5EED)
    for _ in range(2000):
        buf = bytearray(base)
        pos = rng.randrange(len(buf))
        buf[pos] ^= 1 << rng.randrange(8)
        _check(bytes(buf))


def test_fuzz_multi_byte_mutations_of_real_container():
    base = _real_container()
    rng = random.Random(0x1234)
    for _ in range(1000):
        buf = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        # Also sometimes splice or chop to vary the length.
        if rng.random() < 0.3:
            buf = buf[: rng.randrange(len(buf) + 1)]
        _check(bytes(buf))


def test_real_container_round_trips_under_fuzz_helper():
    # Sanity check: the unmutated container still decrypts, so the fuzz harness is
    # exercising a valid baseline.
    base = _real_container()
    assert decrypt_password(PW, base) == bytes(range(256)) * 4
    with pytest.raises(DoradoError):
        decrypt_password(b"wrong", base)
