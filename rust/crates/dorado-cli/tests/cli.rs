//! End-to-end tests that drive the built `dorado` binary over real files and
//! stdin, covering the I/O glue that unit tests cannot reach: argument
//! dispatch, file readers/writers, the raw-key path, and the password-stdin
//! path. The interactive (TTY prompt) password path is deliberately not
//! exercised here, as it requires a terminal.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_dorado");

/// A unique temp path, namespaced by process id so parallel test runs do not
/// collide.
fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dorado-clitest-{}-{name}", std::process::id()));
    p
}

/// Run a prepared command, feeding `password` to its stdin, and report success.
fn feed_password(mut cmd: Command, password: &str) -> bool {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(password.as_bytes())
        .unwrap();
    child.wait().unwrap().success()
}

#[test]
fn raw_key_is_authenticated_by_default_round_trip_and_rejects_tampering_and_wrong_key() {
    let key = "11".repeat(32); // 32 bytes selects the 256 variant
    let wrong_key = "22".repeat(32);
    let iv = "00".repeat(32);
    let plain = tmp("rawauth-plain");
    let cipher = tmp("rawauth-cipher");
    let out = tmp("rawauth-out");
    let payload = b"raw-key round trip through the CLI, authenticated by default";
    fs::write(&plain, payload).unwrap();

    // No --authenticated flag needed: this is the default now.
    let enc = Command::new(BIN)
        .args(["encrypt", "--key", &key, "--iv", &iv, "--in"])
        .arg(&plain)
        .arg("--out")
        .arg(&cipher)
        .status()
        .unwrap();
    assert!(enc.success(), "encrypt should succeed");
    let ct = fs::read(&cipher).unwrap();
    assert_ne!(ct, payload, "data is transformed");
    assert!(
        ct.len() > payload.len(),
        "authenticated output carries a tag and frame overhead, so it must be \
         larger than the plaintext, not byte-for-byte the same length"
    );

    let dec = Command::new(BIN)
        .args(["decrypt", "--key", &key, "--iv", &iv, "--in"])
        .arg(&cipher)
        .arg("--out")
        .arg(&out)
        .status()
        .unwrap();
    assert!(dec.success(), "decrypt should succeed");
    assert_eq!(
        fs::read(&out).unwrap(),
        payload,
        "round-trips to the original"
    );

    // A wrong key must fail, not silently produce garbage.
    let bad_key = Command::new(BIN)
        .args(["decrypt", "--key", &wrong_key, "--iv", &iv, "--in"])
        .arg(&cipher)
        .arg("--out")
        .arg(tmp("rawauth-badkey-out"))
        .status()
        .unwrap();
    assert!(!bad_key.success(), "a wrong key must fail");

    // Flipping a ciphertext byte must fail authentication, not decrypt to
    // silently-wrong plaintext.
    let tampered = tmp("rawauth-tampered");
    let mut data = fs::read(&cipher).unwrap();
    *data.last_mut().unwrap() ^= 1;
    fs::write(&tampered, &data).unwrap();
    let tam = Command::new(BIN)
        .args(["decrypt", "--key", &key, "--iv", &iv, "--in"])
        .arg(&tampered)
        .arg("--out")
        .arg(tmp("rawauth-tampered-out"))
        .status()
        .unwrap();
    assert!(!tam.success(), "tampering must fail");

    for f in [plain, cipher, out, tampered] {
        let _ = fs::remove_file(f);
    }
}

#[test]
fn raw_key_unauthenticated_opt_out_round_trips_and_is_bare_ctr() {
    let key = "11".repeat(32);
    let iv = "00".repeat(32);
    let plain = tmp("rawbare-plain");
    let cipher = tmp("rawbare-cipher");
    let out = tmp("rawbare-out");
    let payload = b"raw-key CTR round trip through the CLI, unauthenticated opt-out";
    fs::write(&plain, payload).unwrap();

    let enc = Command::new(BIN)
        .args([
            "encrypt",
            "--key",
            &key,
            "--iv",
            &iv,
            "--unauthenticated",
            "--in",
        ])
        .arg(&plain)
        .arg("--out")
        .arg(&cipher)
        .status()
        .unwrap();
    assert!(enc.success(), "encrypt should succeed");
    let ct = fs::read(&cipher).unwrap();
    assert_ne!(ct, payload, "data is transformed");
    assert_eq!(
        ct.len(),
        payload.len(),
        "bare CTR has no framing or tag, so output length equals input length exactly"
    );

    // CTR is symmetric, so decrypting is the same command shape as encrypting.
    let dec = Command::new(BIN)
        .args([
            "decrypt",
            "--key",
            &key,
            "--iv",
            &iv,
            "--unauthenticated",
            "--in",
        ])
        .arg(&cipher)
        .arg("--out")
        .arg(&out)
        .status()
        .unwrap();
    assert!(dec.success(), "decrypt should succeed");
    assert_eq!(
        fs::read(&out).unwrap(),
        payload,
        "round-trips to the original"
    );

    for f in [plain, cipher, out] {
        let _ = fs::remove_file(f);
    }
}

#[test]
fn raw_key_rejects_mismatched_iv_length() {
    let plain = tmp("raw-badiv-plain");
    fs::write(&plain, b"x").unwrap();
    let bad = Command::new(BIN)
        .args(["encrypt", "--key", &"11".repeat(32), "--iv", "0000", "--in"])
        .arg(&plain)
        .arg("--out")
        .arg(tmp("raw-badiv-out"))
        .status()
        .unwrap();
    assert!(!bad.success(), "an IV shorter than the key must fail");
    let _ = fs::remove_file(plain);
}

#[test]
fn password_round_trip_and_rejects_wrong_password_and_tampering() {
    let plain = tmp("pw-plain");
    let cipher = tmp("pw-cipher");
    let out = tmp("pw-out");
    let payload = b"password container round trip through the CLI";
    fs::write(&plain, payload).unwrap();

    // PBKDF2 with a low round count keeps the test fast.
    let mut enc = Command::new(BIN);
    enc.args([
        "encrypt",
        "--password-stdin",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-rounds",
        "1000",
        "--in",
    ])
    .arg(&plain)
    .arg("--out")
    .arg(&cipher);
    assert!(feed_password(enc, "hunter2"), "encrypt should succeed");

    let mut dec = Command::new(BIN);
    dec.args(["decrypt", "--password-stdin", "--in"])
        .arg(&cipher)
        .arg("--out")
        .arg(&out);
    assert!(feed_password(dec, "hunter2"), "decrypt should succeed");
    assert_eq!(fs::read(&out).unwrap(), payload);

    // Wrong password must fail.
    let mut bad = Command::new(BIN);
    bad.args(["decrypt", "--password-stdin", "--in"])
        .arg(&cipher)
        .arg("--out")
        .arg(tmp("pw-badpw-out"));
    assert!(!feed_password(bad, "wrong"), "a wrong password must fail");

    // Flipping a ciphertext byte must fail authentication.
    let tampered = tmp("pw-tampered");
    let mut data = fs::read(&cipher).unwrap();
    *data.last_mut().unwrap() ^= 1;
    fs::write(&tampered, &data).unwrap();
    let mut tam = Command::new(BIN);
    tam.args(["decrypt", "--password-stdin", "--in"])
        .arg(&tampered)
        .arg("--out")
        .arg(tmp("pw-tampered-out"));
    assert!(!feed_password(tam, "hunter2"), "tampering must fail");

    for f in [plain, cipher, out, tampered] {
        let _ = fs::remove_file(f);
    }
}

#[test]
fn decrypts_containers_encrypted_by_every_other_port() {
    // The reverse direction of the cross-compat suites: every other port's
    // tests decrypt Rust-generated fixtures, and this test decrypts a
    // container generated by each port's own encrypt path, so the
    // byte-for-byte compatibility claim is verified both ways.
    //
    // Each file in tests/fixtures/ports/ was generated by that port's CLI (or,
    // for the CLI-less ports, a throwaway script over its engine API) with the
    // password "cross-port", the plaintext "the reverse direction: <port>
    // encrypted this", the default 64 KiB chunk size, and the KDF/MAC/variant
    // listed below, so the reverse direction also spans the parameter space:
    //
    //   go       pbkdf2 (10000 rounds)          skein        256
    //   ts       pbkdf2 (10000 rounds)          hmac-sha256  512
    //   java     pbkdf2 (10000 rounds)          blake3       1024
    //   python   scrypt (log_n 12, r 8, p 1)    skein        512
    //   c        argon2id (8 MiB, t 1, p 1)     hmac-sha256  256
    //   zig      scrypt (log_n 12, r 8, p 1)    blake3       1024
    //   haskell  argon2id (8 MiB, t 1, p 1)     skein        256
    //   cpp      scrypt (log_n 12, r 8, p 1)    hmac-sha256  512
    //
    // e.g. for the CLI ports, from inside <port>/:
    //   printf 'cross-port' | ./dorado encrypt --password-stdin \
    //     --kdf <kdf> <cost flags> --mac <mac> --variant <v> \
    //     --in plaintext.bin --out <port>.mahi
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ports");
    for port in ["go", "ts", "java", "python", "c", "zig", "haskell", "cpp"] {
        let container = fixtures.join(format!("{port}.mahi"));
        assert!(
            container.exists(),
            "missing fixture {}",
            container.display()
        );
        let out = tmp(&format!("port-{port}-out"));

        let mut dec = Command::new(BIN);
        dec.args(["decrypt", "--password-stdin", "--in"])
            .arg(&container)
            .arg("--out")
            .arg(&out);
        assert!(
            feed_password(dec, "cross-port"),
            "decrypting the {port} port's container must succeed"
        );
        let want = format!("the reverse direction: {port} encrypted this");
        assert_eq!(
            fs::read(&out).unwrap(),
            want.as_bytes(),
            "the {port} port's container must decrypt to its plaintext"
        );
        let _ = fs::remove_file(out);
    }
}

#[test]
fn password_stdin_requires_an_input_file() {
    // With --password-stdin the data must come from --in, since stdin carries
    // the password.
    let mut cmd = Command::new(BIN);
    cmd.args(["encrypt", "--password-stdin"]);
    assert!(!feed_password(cmd, "pw"), "missing --in must be an error");
}

#[test]
fn inspect_reports_parameters_without_a_password() {
    let plain = tmp("insp-plain");
    let cipher = tmp("insp-cipher");
    fs::write(&plain, b"inspect me").unwrap();

    let mut enc = Command::new(BIN);
    enc.args([
        "encrypt",
        "--password-stdin",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-rounds",
        "1000",
        "--variant",
        "512",
        "--in",
    ])
    .arg(&plain)
    .arg("--out")
    .arg(&cipher);
    assert!(feed_password(enc, "pw"), "encrypt should succeed");

    // No password is needed to inspect.
    let out = Command::new(BIN)
        .args(["inspect", "--in"])
        .arg(&cipher)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Threefish-512"), "{stdout}");
    assert!(stdout.contains("PBKDF2-HMAC-SHA256"), "{stdout}");

    // A non-container is rejected.
    let bad = Command::new(BIN)
        .args(["inspect", "--in"])
        .arg(&plain)
        .status()
        .unwrap();
    assert!(!bad.success(), "inspecting a non-container must fail");

    for f in [plain, cipher] {
        let _ = fs::remove_file(f);
    }
}

#[test]
fn label_is_stored_shown_and_enforced() {
    let plain = tmp("label-plain");
    let cipher = tmp("label-cipher");
    let out = tmp("label-out");
    fs::write(&plain, b"labeled payload").unwrap();

    let mut enc = Command::new(BIN);
    enc.args([
        "encrypt",
        "--password-stdin",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-rounds",
        "1000",
        "--label",
        "backup-2026",
        "--in",
    ])
    .arg(&plain)
    .arg("--out")
    .arg(&cipher);
    assert!(feed_password(enc, "pw"), "encrypt should succeed");

    // inspect shows the label without a password.
    let shown = Command::new(BIN)
        .args(["inspect", "--in"])
        .arg(&cipher)
        .output()
        .unwrap();
    assert!(String::from_utf8(shown.stdout)
        .unwrap()
        .contains("backup-2026"));

    // The matching expected label decrypts.
    let mut ok = Command::new(BIN);
    ok.args([
        "decrypt",
        "--password-stdin",
        "--expect-label",
        "backup-2026",
        "--in",
    ])
    .arg(&cipher)
    .arg("--out")
    .arg(&out);
    assert!(feed_password(ok, "pw"), "matching label should decrypt");
    assert_eq!(fs::read(&out).unwrap(), b"labeled payload");

    // A wrong expected label fails.
    let mut bad = Command::new(BIN);
    bad.args([
        "decrypt",
        "--password-stdin",
        "--expect-label",
        "wrong",
        "--in",
    ])
    .arg(&cipher)
    .arg("--out")
    .arg(tmp("label-badout"));
    assert!(!feed_password(bad, "pw"), "label mismatch must fail");

    for f in [plain, cipher, out] {
        let _ = fs::remove_file(f);
    }
}
