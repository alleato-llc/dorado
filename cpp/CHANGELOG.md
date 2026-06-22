# Changelog - C++ port

Changes to the **C++ port only** (`cpp/`). Cross-cutting changes (project docs, the
wire format, cross-port decisions) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the C++-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md)
is the master table.

## [Unreleased]

### Added

- Initial C++ port (C++23, CMake), mirroring the Rust reference and the other ports:
  byte-for-byte cross-compatible `.mahi` container, the same SDK surface, and the
  `dorado` + `gyotaku` CLIs.
- From-scratch primitives: Threefish-256/512/1024 and CTR, Skein-512 (UBI) with an
  incremental hasher, BLAKE3 with a keyed-MAC mode and incremental hasher, and
  SHA-256 + HMAC-SHA256. Verified against the same official vectors the other ports
  use (Crypto++ Threefish, RFC 8439/FIPS, RFC 4231, RFC 7914).
- The three password KDFs (Argon2id, scrypt, PBKDF2) are the only delegation, via
  OpenSSL's `EVP_KDF` (OpenSSL >= 3.2 for Argon2). No other external dependency.
- Streaming over `std::istream`/`std::ostream` in constant memory is the core; the
  in-memory byte APIs wrap it via `std::stringstream`. Engine results use
  `std::expected<T, std::string>`.
- Test suite (`dorado_test`, run via `ctest`): primitive KATs, every MAC/variant, the
  incremental hashers, and cross-compat fixtures from the Rust CLI with wrong-password
  and tamper rejection plus round-trips.
- Secret hygiene, matching the C/Zig tier: the engine wipes the derived keys (a scope
  guard) and the `Threefish` expanded key schedule (its destructor) on every exit path,
  using a non-elidable volatile-write `secure_wipe`; the `dorado` CLI holds the password
  in a page-aligned, `mlock`'d buffer wiped on free (best-effort `mlock`). Reflected in
  `docs/implementations.md`.
