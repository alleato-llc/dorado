# Changelog - Haskell port

Changes to the **Haskell port only** (`haskell/`). Cross-cutting changes (project
docs, the chunk-size cap policy, the wire format) live in the
[Core CHANGELOG](../CHANGELOG.md) and [docs/spec.md](../docs/spec.md); this file
records the Haskell-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md)
is the master table.

## [Unreleased]

### Added

- **Key-based derivation**: `Dorado.Kdf.deriveFromKey` / `deriveFromKeyWith`, with a
  `KdfPrf` PRF choice (`Skein512` | `Blake3`), the fast counterpart to the password
  KDFs: one domain-separated keyed hash (`"DRDOkdrv" || domain`) fanning an already
  high-entropy key out into independent per-purpose subkeys, no salt, no cost
  parameters. Skein-512 keyed hashing is the default (any key length);
  `deriveFromKeyWith Blake3` selects keyed BLAKE3 instead (32-byte key only, `Left`
  otherwise). Both are built on this port's own from-scratch hashes; `crypton` stays
  password-KDF-only. The names are the guardrail: a password must never take this
  path (there is no stretching), and a key never needs the slow one. See the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale; known-answer
  tested against all six vectors in
  [docs/fixtures/derive-from-key.md](../docs/fixtures/derive-from-key.md).
- **KDF cost validation**: `Dorado.Kdf.validate` rejects cost parameters that are
  unreasonably large (Argon2id memory > 2^21 KiB, iterations > 64, lanes > 16;
  scrypt log2(N) > 21, r > 32, p > 16; PBKDF2 rounds of 0 or > 50,000,000), with the
  same bounds as the other ports. Every password decrypt path runs it on the
  untrusted header before deriving keys; the CLI also runs it on encrypt so its cost
  flags cannot produce a file no port would decrypt.
- **Chunk-size cap**: `defaultMaxChunkBytes` (64 MiB), `hardMaxChunkBytes` (1 GiB),
  `maxChunkBytes` (the effective cap, honoring a `DORADO_MAX_CHUNK_BYTES` tightening
  clamped into (0, 1 GiB]), and the pure, env-free resolver `chunkCapFrom`, exported
  from `Dorado.Format` and re-exported by `Dorado.Engine`. Every decrypt path
  (password and raw-authenticated) bounds the header's chunk size and each frame's
  `ct_len` against the cap before allocating and before deriving any key. The pure
  in-memory decrypt forms use the fixed 64 MiB default; only the streaming forms,
  being in `IO`, can honor the environment override.
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

### Changed

- **CLI raw-key mode (`--key`/`--key-file`) is authenticated by default**
  (encrypt-then-MAC via `encryptRawAuthenticatedStream`/`decryptRawAuthenticatedStream`;
  `--mac` and `--chunk-kib` now apply to raw-key mode too), with bare CTR moved behind
  a new `--unauthenticated` opt-out. Passing `--unauthenticated` in password mode is
  an error (password mode is always authenticated). This matches the Rust CLI's
  default change; see the [Core CHANGELOG](../CHANGELOG.md) for the cross-port
  rationale. Raw output produced by the previous default (bare CTR) still decrypts
  with `--unauthenticated`.
- CLI `--chunk-kib` is now validated: a non-numeric value or a size outside
  (0, effective cap] is an error, where before an unparseable value silently fell
  back to the default and any size was accepted.

### Fixed

- **Untrusted-header hardening (catch-up)**: this port previously enforced no bounds
  on the KDF cost parameters or the chunk size read from a container header, both of
  which the other implementations already bound. A crafted `.mahi` file could demand
  gigabytes of Argon2 memory or a multi-minute derivation (denial of service) before
  the inevitable authentication failure. All decrypt paths (in-memory and streaming,
  password and raw-authenticated) now run `Kdf.validate` and the chunk-size cap
  before any key derivation or allocation, matching the Rust reference. Error
  reporting is unchanged: wrong password and tampering both stay
  "authentication failed".

### Notes

- Secret handling is caller-managed (GC-managed `ByteString`s, no wipe, no `mlock`),
  like the Java and Python ports; weaker than the Rust/C/Zig/Go ports.
