"""Construction tests: round-trips, every KDF/MAC/variant, and the security properties."""

import io

import pytest

import dorado
from dorado import (
    KDF_SCRYPT,
    MAC_BLAKE3,
    MAC_HMAC,
    MAC_SKEIN,
    DoradoError,
    KdfParams,
    PasswordOptions,
    T256,
    T512,
    T1024,
    decrypt_password,
    encrypt_password,
    inspect,
    raw_ctr,
)
from dorado import format as fmt

PW = b"correct horse battery staple"
VARIANTS = [T256, T512, T1024]
MACS = [MAC_SKEIN, MAC_HMAC, MAC_BLAKE3]


def kdfs():
    return [KdfParams.argon2id(8 * 1024, 1, 1), KdfParams.scrypt(14, 8, 1), KdfParams.pbkdf2(20_000)]


def opts(variant, kdf, mac):
    return PasswordOptions(variant=variant, kdf=kdf, mac=mac)


def test_round_trip_every_variant_kdf_mac():
    plaintext = b"the quick brown fox jumps over the lazy dog"
    for variant in VARIANTS:
        for kdf in kdfs():
            for mac in MACS:
                ct = encrypt_password(PW, opts(variant, kdf, mac), plaintext)
                assert decrypt_password(PW, ct) == plaintext, (variant, kdf.kind, mac)


def test_empty_plaintext():
    ct = encrypt_password(PW, opts(T256, KdfParams.pbkdf2(20_000), MAC_SKEIN), b"")
    assert decrypt_password(PW, ct) == b""


def test_multi_chunk():
    o = opts(T256, KdfParams.pbkdf2(20_000), MAC_SKEIN)
    o.chunk_size = 128
    plaintext = bytes((i * 7) & 0xFF for i in range(5000))
    ct = encrypt_password(PW, o, plaintext)
    assert decrypt_password(PW, ct) == plaintext


def test_wrong_password():
    ct = encrypt_password(PW, opts(T256, KdfParams.pbkdf2(20_000), MAC_SKEIN), b"secret")
    with pytest.raises(DoradoError):
        decrypt_password(b"wrong", ct)


def test_tampering():
    ct = bytearray(encrypt_password(PW, opts(T256, KdfParams.pbkdf2(20_000), MAC_SKEIN), b"secret"))
    ct[-1] ^= 1
    with pytest.raises(DoradoError):
        decrypt_password(PW, bytes(ct))


def test_truncation():
    ct = encrypt_password(PW, opts(T256, KdfParams.pbkdf2(20_000), MAC_SKEIN), b"secret")
    with pytest.raises(DoradoError):
        decrypt_password(PW, ct[:-8])


def test_bad_magic():
    with pytest.raises(DoradoError):
        inspect(b"XXXX\x00\x00\x00\x00")


def test_label_binding():
    o = opts(T256, KdfParams.pbkdf2(20_000), MAC_SKEIN)
    o.label = b"demo-context"
    ct = encrypt_password(PW, o, b"payload")
    assert decrypt_password(PW, ct, b"demo-context") == b"payload"
    assert decrypt_password(PW, ct) == b"payload"
    with pytest.raises(DoradoError):
        decrypt_password(PW, ct, b"other")
    assert inspect(ct).label == b"demo-context"


def test_inspect():
    ct = encrypt_password(PW, opts(T512, KdfParams.scrypt(14, 8, 1), MAC_BLAKE3), b"hi")
    info = inspect(ct)
    assert info.version == fmt.VERSION
    assert info.variant == T512
    assert info.mac == MAC_BLAKE3
    assert info.kdf.kind == KDF_SCRYPT
    assert info.chunk_size == fmt.DEFAULT_CHUNK_BYTES


def test_hostile_kdf_cost_rejected():
    ct = bytearray(encrypt_password(PW, opts(T256, KdfParams.argon2id(8 * 1024, 1, 1), MAC_SKEIN), b"x"))
    # Patch the header m_cost (offset 7) to 2**31, which validate() must reject.
    ct[7:11] = b"\x80\x00\x00\x00"
    with pytest.raises(DoradoError):
        decrypt_password(PW, bytes(ct))


def test_streaming_api():
    plaintext = b"streamed payload across the input"
    enc = io.BytesIO()
    dorado.encrypt_password_stream(PW, opts(T256, KdfParams.pbkdf2(20_000), MAC_SKEIN), io.BytesIO(plaintext), enc)
    dec = io.BytesIO()
    dorado.decrypt_password_stream(PW, io.BytesIO(enc.getvalue()), dec)
    assert dec.getvalue() == plaintext


def test_raw_ctr():
    key = bytes(range(32))
    iv = bytes(255 - i for i in range(32))
    data = b"raw CTR, any length, no header"
    ct = raw_ctr(T256, key, bytes(16), iv, data)
    assert raw_ctr(T256, key, bytes(16), iv, ct) == data
