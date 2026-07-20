# Security

## Status

Dorado is an educational, from-scratch implementation and is **unaudited**. It has
not had a professional cryptographic review. Do not use it to protect data you cannot
afford to lose or expose; prefer an audited tool (age, libsodium, GnuPG, OpenSSL) for
real secrets. The cryptography here exists to be read and understood, not to be relied
on.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's "Report a
vulnerability" (Security advisories) on the repository, rather than opening a public
issue. Because the project is educational and unaudited, findings are most useful as
learning material; there is no guarantee of a fix or a timeline.

## What it is designed to do

The password container is authenticated encryption built encrypt-then-MAC over the
from-scratch Threefish cipher in CTR mode, chunked so it streams in constant memory.
Within that scope it aims to provide:

- **Confidentiality** of file contents at rest, under a password (stretched by
  Argon2id, scrypt, or PBKDF2) or a raw key.
- **Integrity and authenticity.** Each chunk carries a MAC over a domain separator,
  the chunk index, a final-chunk flag, and the ciphertext, with the whole header
  bound into the first chunk's tag. This detects tampering, a wrong password, and
  chunk reordering, dropping, or truncation. The tag is checked before a chunk is
  decrypted, and the comparison is constant time.
- **Bounded handling of untrusted input.** A container header is parsed before any
  secret is derived: the chunk-size field is range-checked and block-aligned before
  any allocation, and the KDF cost parameters are validated against caps before the
  KDF runs, so a hostile file cannot force a huge allocation or a memory-hard bomb.
  The `decrypt` path has coverage-guided fuzz harnesses in the Rust, C, and C++
  implementations (cargo-fuzz / libFuzzer), and CI runs each of those three as a
  short smoke pass (60 seconds, a crash fails the job) on every relevant change;
  longer runs are manual. The Go, TypeScript, Java, and Python suites include
  deterministic randomized fuzz-style tests of it; the Zig and Haskell ports
  have neither yet.
- **No nonce reuse by construction.** Every encryption draws a fresh random salt and
  a full-block random IV from a CSPRNG, so the CTR keystream is never reused across
  files under the same password.
- **Best-effort secret hygiene**, whose strength varies by implementation. In Rust,
  derived keys, the KDF output, and the cipher's expanded key schedule are zeroized
  on drop, and the CLI `mlock`s the password buffer out of swap (best effort, and
  the bytes are still wiped if the lock fails); the Rust GUIs best-effort wipe their
  app-owned password copies but do not `mlock`. The Go, C, C++, and Zig CLIs also
  `mlock` the password and wipe derived keys. The TypeScript Node CLI holds
  passwords and raw keys in locked off-heap `sodium-native` buffers and fails
  closed if that library is unavailable (`--insecure-memory` opts out). Java,
  Python, and Haskell leave secret lifetimes to the caller (Java's engine
  best-effort wipes its internal key material).

## What it does not defend against (non-goals)

- **A compromised host.** Malware, a keylogger, a malicious OS, or memory inspection
  by another process on the same machine defeat it. The `mlock` and zeroization are
  best-effort hardening, not a defense against an attacker who already controls the
  machine.
- **Side channels beyond the basics.** The cipher avoids secret-dependent branching
  and indexing, and tag comparison is constant time, but there is no protection or
  formal analysis for power, electromagnetic, or microarchitectural side channels.
  The constant-time comparison is hand-written and relies on the compiler not
  defeating it (it does not use a barrier crate such as `subtle`).
- **Metadata.** Ciphertext length reveals plaintext length (no padding). The header is
  cleartext by design: format version, cipher variant, KDF and its cost parameters,
  MAC choice, chunk size, salt, tweak, and any label are all visible without the
  password (this is what `dorado inspect` reads). A label binds a file to a context
  but is not secret.
- **A weak password or a bad RNG.** Security rests on password entropy and the KDF
  cost, and on the operating system's CSPRNG. `DORADO_RNG` (a Rust-only knob) only
  selects between two CSPRNGs (`os` and `thread`); it cannot and should not be used
  to supply a deterministic or weak source.
- **Forward secrecy, key management, or multi-recipient use.** This is symmetric,
  password-based, single-file encryption. There is no forward secrecy, no key
  rotation, no asymmetric recipients, and no protection against coercion.

## Cryptographic choices

The primitives are written from scratch (Threefish, Skein-512, BLAKE3; the Haskell
and C++ ports also build SHA-256 and HMAC-SHA256 from scratch, while the other
implementations take HMAC-SHA256 from their standard libraries) and verified
against official test vectors or differentially against audited implementations;
the KDFs (Argon2id, scrypt, PBKDF2) come from established libraries. The default
MAC is Skein-512, keeping the default construction within the Threefish family.
None of this substitutes for an audit.
