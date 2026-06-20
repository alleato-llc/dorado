"""Skein-512 and BLAKE3 known-answer tests. Empty/"abc" are official vectors; the
longer ones are baked from the Rust reference (dorado)."""

from dorado import blake3, skein


def seq(n):
    return bytes(i & 0xFF for i in range(n))


def test_skein_empty512():
    assert skein.hash(64, b"").hex() == (
        "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4"
        "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
    )


def test_skein_abc256():
    assert skein.hash(32, b"abc").hex() == "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527"


def test_skein_abc512():
    assert skein.hash(64, b"abc").hex() == (
        "8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f938"
        "93ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75"
    )


def test_skein_multiblock():
    assert skein.hash(32, seq(500)).hex() == "15096f2f503dce8eab3ab3ac80d840dafdd8001ca1737fab69b717475b4abdaf"


def test_skein_keyed_mac():
    assert skein.mac(b"\x9c" * 32, 32, b"authenticate me").hex() == (
        "8b0865bcabf2dec950b2178b5127e88914d039a0681339e5d10e06d95bad12b3"
    )


def test_skein_streaming_matches_one_shot():
    msg = seq(700)
    h = skein.Skein512(32)
    for i in range(0, len(msg), 9):
        h.update(msg[i : i + 9])
    assert h.digest() == skein.hash(32, msg)


def test_blake3_empty():
    assert blake3.hash(32, b"").hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"


def test_blake3_multichunk_tree():
    assert blake3.hash(32, seq(3000)).hex() == "6c943946a70794f2e14c785d5ee88d300d5f9b91d1b4ef88302974ac4b069052"


def test_blake3_keyed_mac():
    assert blake3.keyed_mac(b"\x9c" * 32, 32, b"authenticate me").hex() == (
        "e8a84781007d67df2b0de8cf1d0c48b0fee97a0f9744ba5b325c1aac2d670a08"
    )


def test_blake3_streaming_matches_one_shot():
    msg = seq(2500)
    h = blake3.Hasher.new()
    for i in range(0, len(msg), 7):
        h.update(msg[i : i + 7])
    assert h.digest(32) == blake3.hash(32, msg)
