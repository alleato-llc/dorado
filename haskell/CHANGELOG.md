# Changelog - Haskell port

Changes to the **Haskell port only** (`haskell/`). Cross-cutting changes (project
docs, the chunk-size cap policy, the wire format) live in the
[Core CHANGELOG](../CHANGELOG.md) and [docs/spec.md](../docs/spec.md); this file
records the Haskell-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md)
is the master table.

## [Unreleased]

### Added

- **Raw-key mode gains an authenticated option**: `Dorado.Engine.encryptRawAuthenticated`
  / `decryptRawAuthenticated` (in-memory) and `encryptRawAuthenticatedStream` /
  `decryptRawAuthenticatedStream` (streaming over `Handle`s), encrypt-then-MAC over the
  caller-supplied key with no password or KDF, reusing the password container's
  chunk/frame machinery. See the [Core CHANGELOG](../CHANGELOG.md) for the cross-port
  rationale and [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for the
  byte-level construction (key-splitting via domain-separated Skein-512, the frame
  AAD). Verified against the cross-language known-answer vectors in
  `docs/fixtures/raw-authenticated.md`. Bare `rawCtr` / `rawCtrStream` are unchanged
  and remain the default.
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
- An incremental Skein-512 hasher (`Dorado.Skein.newHasher`/`update`/`finalize`),
  producing the same digest as the one-shot `hash` at any chunking, so `gyotaku`
  streams files in constant memory (matching the other ports) rather than reading
  them whole.

### Notes

- Secret handling is caller-managed (GC-managed `ByteString`s, no wipe, no `mlock`),
  like the Java and Python ports; weaker than the Rust/C/Zig/Go ports.
