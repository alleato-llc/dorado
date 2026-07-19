"""End-to-end tests of the dorado CLI's raw-key mode, driving main() in-process:
authenticated (encrypt-then-MAC) by default, bare CTR behind the explicit
--unauthenticated opt-out, and --unauthenticated rejected in password mode.
"""

from dorado import MAC_SKEIN, T256, encrypt_raw_authenticated, raw_ctr
from dorado.cli.dorado import main

KEY_HEX = "11" * 32
IV_HEX = "02" * 32
KEY = bytes.fromhex(KEY_HEX)
IV = bytes.fromhex(IV_HEX)
TWEAK = bytes(16)
PLAINTEXT = b"raw-key mode through the CLI, authenticated unless opted out"


def run_raw(command, in_path, out_path, *extra):
    return main([command, "--key", KEY_HEX, "--iv", IV_HEX, "--in", str(in_path), "--out", str(out_path), *extra])


def test_raw_key_is_authenticated_by_default(tmp_path):
    pt = tmp_path / "pt"
    ct = tmp_path / "ct"
    out = tmp_path / "out"
    pt.write_bytes(PLAINTEXT)

    assert run_raw("encrypt", pt, ct) == 0
    # The default is the authenticated construction with the default MAC and
    # chunk size: framing and per-chunk tags, byte-for-byte the engine's output.
    expected = encrypt_raw_authenticated(T256, KEY, TWEAK, IV, MAC_SKEIN, 64 * 1024, PLAINTEXT)
    assert ct.read_bytes() == expected
    assert len(ct.read_bytes()) > len(PLAINTEXT), "framing + tag overhead, not bare CTR"

    assert run_raw("decrypt", ct, out) == 0
    assert out.read_bytes() == PLAINTEXT


def test_raw_key_default_rejects_tampering_and_wrong_key(tmp_path, capsys):
    pt = tmp_path / "pt"
    ct = tmp_path / "ct"
    out = tmp_path / "out"
    pt.write_bytes(PLAINTEXT)
    assert run_raw("encrypt", pt, ct) == 0

    tampered = bytearray(ct.read_bytes())
    tampered[-1] ^= 1
    bad = tmp_path / "bad"
    bad.write_bytes(bytes(tampered))
    assert run_raw("decrypt", bad, out) == 1
    assert "error:" in capsys.readouterr().err

    wrong = "99" * 32
    assert main(["decrypt", "--key", wrong, "--iv", IV_HEX, "--in", str(ct), "--out", str(out)]) == 1
    assert "error:" in capsys.readouterr().err


def test_raw_key_mac_and_chunk_options_apply(tmp_path):
    pt = tmp_path / "pt"
    ct = tmp_path / "ct"
    out = tmp_path / "out"
    pt.write_bytes(PLAINTEXT * 40)  # spans multiple 1 KiB chunks

    assert run_raw("encrypt", pt, ct, "--mac", "hmac-sha256", "--chunk-kib", "1") == 0
    # Decrypting needs the same parameters back...
    assert run_raw("decrypt", ct, out, "--mac", "hmac-sha256", "--chunk-kib", "1") == 0
    assert out.read_bytes() == PLAINTEXT * 40
    # ...and the defaults (Skein MAC, 64 KiB chunks) must fail authentication.
    assert run_raw("decrypt", ct, out) == 1


def test_raw_key_unauthenticated_opt_out_is_bare_ctr(tmp_path):
    pt = tmp_path / "pt"
    ct = tmp_path / "ct"
    out = tmp_path / "out"
    pt.write_bytes(PLAINTEXT)

    assert run_raw("encrypt", pt, ct, "--unauthenticated") == 0
    data = ct.read_bytes()
    assert len(data) == len(PLAINTEXT), "bare CTR: output length equals input length"
    assert data == raw_ctr(T256, KEY, TWEAK, IV, PLAINTEXT)

    assert run_raw("decrypt", ct, out, "--unauthenticated") == 0
    assert out.read_bytes() == PLAINTEXT


def test_unauthenticated_rejected_in_password_mode(tmp_path, capsys):
    pt = tmp_path / "pt"
    pt.write_bytes(PLAINTEXT)
    for command in ("encrypt", "decrypt"):
        assert main([command, "--password-stdin", "--unauthenticated", "--in", str(pt)]) == 1
        err = capsys.readouterr().err
        assert "--unauthenticated is not used in password mode, which is always authenticated" in err
