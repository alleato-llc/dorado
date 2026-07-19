//! End-to-end tests for the built `gyotaku` binary: stdin and file hashing, the
//! output-length flag, and rejection of a bad length.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_gyotaku");

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("gyotaku-clitest-{}-{name}", std::process::id()));
    p
}

fn run_stdin(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A child that rejects its arguments (the bad --bits test) may exit
    // before reading stdin, surfacing the race as BrokenPipe here; that is
    // not a failure, the caller asserts on status and output.
    if let Err(e) = child.stdin.take().unwrap().write_all(input) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    child.wait_with_output().unwrap()
}

#[test]
fn hashes_stdin_with_the_default_length() {
    // The Skein-512-256 digest of "abc".
    let out = run_stdin(&[], b"abc");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527"
    );
}

#[test]
fn bits_flag_selects_the_output_length() {
    // The official Skein-512-512 digest of the empty message.
    let out = run_stdin(&["--bits", "512"], b"");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4\
         1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
    );
}

#[test]
fn hashes_a_file_and_prints_its_name() {
    let path = tmp("input.txt");
    fs::write(&path, b"abc").unwrap();
    let out = Command::new(BIN).arg(&path).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527"),
        "digest present: {stdout}"
    );
    assert!(
        stdout.contains(path.to_str().unwrap()),
        "filename present: {stdout}"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn rejects_a_non_byte_aligned_length() {
    let out = run_stdin(&["--bits", "7"], b"abc");
    assert!(
        !out.status.success(),
        "7 bits is not a whole number of bytes"
    );
}

#[test]
fn tag_output_is_bsd_style() {
    let path = tmp("tag-input");
    fs::write(&path, b"abc").unwrap();
    let out = Command::new(BIN).arg("--tag").arg(&path).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("SKEIN-512 ("), "{s}");
    assert!(
        s.contains("= 0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527"),
        "{s}"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn check_mode_verifies_and_detects_mismatch() {
    let data = tmp("check-data");
    fs::write(&data, b"abc").unwrap();

    // Produce a checksum line for the file, then store it as a checklist.
    let produced = Command::new(BIN).arg(&data).output().unwrap();
    assert!(produced.status.success());
    let list = tmp("check-list");
    fs::write(&list, &produced.stdout).unwrap();

    // Verification passes against the unmodified file.
    let ok = Command::new(BIN).arg("-c").arg(&list).output().unwrap();
    assert!(
        ok.status.success(),
        "stdout={}",
        String::from_utf8_lossy(&ok.stdout)
    );
    assert!(String::from_utf8(ok.stdout).unwrap().contains("OK"));

    // Changing the file makes the stored digest no longer match.
    fs::write(&data, b"abcd").unwrap();
    let bad = Command::new(BIN).arg("-c").arg(&list).output().unwrap();
    assert!(!bad.status.success(), "a mismatch must fail");
    assert!(String::from_utf8(bad.stdout).unwrap().contains("FAILED"));

    for f in [data, list] {
        let _ = fs::remove_file(f);
    }
}
