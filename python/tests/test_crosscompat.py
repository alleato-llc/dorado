"""Cross-compatibility: decrypt .mahi fixtures produced by the Rust reference (the
baseline), one per KDF/MAC/variant plus a labeled and a multi-frame file. Checked-in
regression guards that the Python port stays byte-compatible with the shared format.
The reverse direction is verified during development."""

import pathlib

import pytest

from dorado import DoradoError, decrypt_password, inspect

PW = b"pw-cross"
FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def fixture(name):
    return (FIXTURES / name).read_bytes()


@pytest.mark.parametrize(
    "name,expected",
    [
        ("argon_skein_256.mahi", b"rust argon+skein+256"),
        ("scrypt_hmac_512.mahi", b"rust scrypt+hmac+512"),
        ("pbkdf2_blake3_1024.mahi", b"rust pbkdf2+blake3+1024"),
    ],
)
def test_decrypts_rust_fixture(name, expected):
    assert decrypt_password(PW, fixture(name)) == expected


def test_labeled_fixture():
    data = fixture("labeled.mahi")
    assert inspect(data).label == b"demo-context"
    assert decrypt_password(PW, data, b"demo-context") == b"rust labeled payload"
    with pytest.raises(DoradoError):
        decrypt_password(PW, data, b"wrong")


def test_multi_frame_fixture():
    assert decrypt_password(PW, fixture("multichunk.mahi")) == b"x" * 5000
