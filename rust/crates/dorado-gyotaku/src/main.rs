//! `gyotaku`: a standalone Skein-512 hashing tool, the Skein equivalent of
//! `sha256sum`. The name is the Japanese art of printing a fish in ink, an
//! impression that fingerprints the fish, which is what this makes of a file.
//! Skein is the hash function Threefish was designed to power; this exposes it
//! in its primary, unkeyed role (file/stream fingerprinting), as opposed to the
//! keyed MAC the encryption tool uses internally.
//!
//! Educational and unaudited; for real-world hashing prefer BLAKE3 or SHA-256
//! from a vetted library.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "gyotaku",
    version,
    about = "Skein-512 file hashing, a fish-print fingerprint. Educational, unaudited."
)]
struct Cli {
    /// Output length in bits (a multiple of 8). Skein supports any length.
    #[arg(long, default_value_t = 256)]
    bits: usize,

    /// Read digests from the FILES and verify them (like `sha256sum -c`).
    #[arg(short = 'c', long)]
    check: bool,

    /// Print BSD-style tagged output: "SKEIN-512 (file) = digest".
    #[arg(long)]
    tag: bool,

    /// Files to hash, or checksum lists to verify with --check. Reads stdin when
    /// none are given (not allowed with --check).
    files: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if cli.check {
        if cli.tag {
            return Err("--tag cannot be combined with --check".into());
        }
        if cli.files.is_empty() {
            return Err("--check needs at least one checksum file".into());
        }
        return run_check(&cli.files);
    }

    let out_len = out_len_from_bits(cli.bits)?;
    if cli.files.is_empty() {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        let digest = hex(&dorado::skein::hash(out_len, &buf));
        // Keep stdin output bare (just the digest) unless tagged.
        if cli.tag {
            println!("{}", tag_line(&digest, "-"));
        } else {
            println!("{digest}");
        }
    } else {
        for path in &cli.files {
            let data = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let digest = hex(&dorado::skein::hash(out_len, &data));
            println!("{}", format_line(cli.tag, &digest, path));
        }
    }
    Ok(())
}

/// Verify the digests listed in each checksum file. Prints "name: OK" or
/// "name: FAILED" per entry and errors if any entry fails or none were found.
fn run_check(files: &[String]) -> Result<(), String> {
    let mut checked = 0u64;
    let mut failed = 0u64;
    for list in files {
        let content = fs::read_to_string(list).map_err(|e| format!("{list}: {e}"))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (expected, name) =
                parse_check_line(line).ok_or_else(|| format!("{list}: malformed line: {line}"))?;
            // The digest length in the file fixes the output length to recompute.
            let out_len = expected.len() / 2;
            checked += 1;
            match fs::read(&name) {
                Ok(data) => {
                    let got = hex(&dorado::skein::hash(out_len, &data));
                    if got.eq_ignore_ascii_case(&expected) {
                        println!("{name}: OK");
                    } else {
                        println!("{name}: FAILED");
                        failed += 1;
                    }
                }
                Err(_) => {
                    println!("{name}: FAILED open or read");
                    failed += 1;
                }
            }
        }
    }
    if checked == 0 {
        return Err("no digests found to verify".into());
    }
    if failed > 0 {
        return Err(format!("{failed} of {checked} digests did NOT match"));
    }
    Ok(())
}

/// Format one output line in either the default or BSD-tagged style.
fn format_line(tag: bool, digest: &str, name: &str) -> String {
    if tag {
        tag_line(digest, name)
    } else {
        // Two spaces, matching the sha256sum convention.
        format!("{digest}  {name}")
    }
}

fn tag_line(digest: &str, name: &str) -> String {
    format!("SKEIN-512 ({name}) = {digest}")
}

/// Parse one line of a checksum file into (expected hex digest, filename),
/// accepting both the default "digest  name" form and the BSD-tagged
/// "SKEIN-512 (name) = digest" form. Returns None if the line is not a valid
/// digest entry.
fn parse_check_line(line: &str) -> Option<(String, String)> {
    // BSD-tagged: "<algo> (<name>) = <hex>".
    if let Some((_, rest)) = line.split_once(" (") {
        if let Some((name, digest)) = rest.split_once(") = ") {
            let digest = digest.trim();
            if is_even_hex(digest) {
                return Some((digest.to_string(), name.to_string()));
            }
        }
    }
    // Default: "<hex>  <name>" (the name may carry a leading '*' binary marker).
    let (digest, rest) = line.split_once(char::is_whitespace)?;
    if !is_even_hex(digest) {
        return None;
    }
    let name = rest
        .trim_start()
        .strip_prefix('*')
        .unwrap_or(rest.trim_start());
    Some((digest.to_string(), name.to_string()))
}

/// A non-empty string of an even number of hex digits (a whole-byte digest).
fn is_even_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Convert a requested output length in bits to whole bytes, rejecting zero or a
/// length that is not a whole number of bytes.
fn out_len_from_bits(bits: usize) -> Result<usize, String> {
    if bits == 0 || !bits.is_multiple_of(8) {
        return Err("--bits must be a positive multiple of 8".into());
    }
    Ok(bits / 8)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
