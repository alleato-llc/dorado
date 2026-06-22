# Changelog - Haskell port

Changes to the **Haskell port only** (`haskell/`). Cross-cutting changes (project
docs, the chunk-size cap policy, the wire format) live in the
[Core CHANGELOG](../CHANGELOG.md) and [docs/spec.md](../docs/spec.md); this file
records the Haskell-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md)
is the master table.

## [Unreleased]

### Added

- Initial Haskell port (Cabal package `dorado`, built with GHC): an SDK plus the
  `dorado` and `gyotaku` CLIs, byte-for-byte cross-compatible with the other ports.
- From-scratch primitives, each verified against the same vectors as the Rust
  reference: Threefish 256/512/1024 + CTR (official Crypto++ KATs), Skein-512, BLAKE3,
  and SHA-256 + HMAC-SHA256 (FIPS/RFC vectors). Strict throughout: the primitive cores
  run in `ST` over unboxed `STUArray`s behind pure `runST` functions; native `Word64`
  ARX.
- The DRDO v4 container (`Dorado.Format` + `Dorado.Engine`): encrypt-then-MAC over a
  continuous CTR stream, framed into chunks, with the MAC menu (HMAC-SHA256, Skein-512,
  keyed BLAKE3), KDFs delegated to `crypton` (Argon2id, scrypt, PBKDF2), raw-key CTR
  mode, `inspect`, and label binding. Constant-memory streaming over `Handle`s, with
  output byte-identical to whole-file CTR; in-memory `ByteString` forms too. Verified
  by decrypting Rust-produced `.mahi` fixtures (every KDF/MAC/variant, multi-frame,
  labeled) and by the Rust CLI decrypting this port's output.

### Notes

- Secret handling is caller-managed (GC-managed `ByteString`s, no wipe, no `mlock`),
  like the Java and Python ports; weaker than the Rust/C/Zig/Go ports.
- `gyotaku` currently reads each file fully before hashing (the Skein hasher here is
  one-shot, not incremental), so it does not hash inputs larger than memory the way
  the streaming CLIs do for the container.
