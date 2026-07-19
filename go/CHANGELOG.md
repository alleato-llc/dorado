# Changelog - Go port

Changes to the **Go port only** (`go/`). Cross-cutting changes (project docs, the
chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the Go-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

- `go/engine`: raw-key authenticated mode (`EncryptRawAuthenticatedStream` /
  `DecryptRawAuthenticatedStream` / `*Bytes`, in the new `go/engine/raw_authenticated.go`),
  encrypt-then-MAC over a caller-supplied key with no password or KDF, reusing the
  password container's chunk/frame machinery. Ports the Rust reference construction;
  see the [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale and
  [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for the byte-level
  construction. Verified against the six cross-language known-answer vectors in
  [docs/fixtures/raw-authenticated.md](../docs/fixtures/raw-authenticated.md).
  `RawCTRStream` (bare, unauthenticated) is unchanged and remains available
  (the CLI reaches it via `--unauthenticated`; see Changed).
- `go/engine`: both standard forms of key derivation are now public.
  `DeriveFromPassword` (the former unexported `derive`: Argon2id, scrypt,
  PBKDF2-HMAC-SHA256 behind one call) stretches a weak secret, deliberately
  slowly. The new `DeriveFromKey` is the fast, key-based form (one
  domain-separated Skein-512 keyed hash, its own `DRDOkdrv` domain prefix)
  fanning an already high-entropy key out into independent per-purpose
  children, and `DeriveFromKeyWith` takes a `KDFPrf` (`KDFPrfSkein512`,
  `KDFPrfBLAKE3`; the BLAKE3 form requires a 32-byte key) to fan out under
  either PRF. The parallel names are the guardrail: a password must never take
  the fast path, a key never needs the slow one. Ports the Rust reference's
  `derive_from_password`/`derive_from_key`/`derive_from_key_with`; see the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale. Verified
  against the six cross-language known-answer vectors in
  [docs/fixtures/derive-from-key.md](../docs/fixtures/derive-from-key.md).
  API surface only: the wire format is unchanged.
- `go/engine`: exported sentinel errors (`ErrAuthFailed`, `ErrMalformedContainer`,
  `ErrUnsupportedVersion`, `ErrInvalidParams`) wrapped with `%w`, so callers classify
  failures with `errors.Is` instead of matching strings. Wrong password and tampering
  stay merged as `ErrAuthFailed`.
- `go/engine`: a native `FuzzDecryptPasswordBytes` fuzz target over the decrypt path, and
  an exported `MaxChunkBytes()`.

### Changed

- CLI: raw-key mode (`--key`/`--key-file`) is now authenticated by default,
  matching the Rust CLI. `dorado encrypt --key ... --iv ...` produces
  encrypt-then-MAC output (larger than the input by the per-chunk tag and
  framing; `--mac` and `--chunk-kib` apply) unless the new `--unauthenticated`
  flag opts back into bare CTR (output length exactly equals input length).
  This breaks any script that assumed raw-key mode's old bare output shape
  without `--unauthenticated` on both ends. Password mode is always
  authenticated and rejects the flag. See the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale.
- CLI parity: `dorado --help`/`-h` and `gyotaku --help`/`-h` now print usage to stdout
  and exit 0 (were exit 2 via the error path), and `gyotaku` accepts `--check` as well
  as `-c` (`--version` already worked). See [Core](../CHANGELOG.md).
- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling,
  `DORADO_MAX_CHUNK_BYTES`); the Go CLI caps `--chunk-kib` to the effective max so
  encryption matches the default decrypt cap. See [Core](../CHANGELOG.md). (RNG was
  already `crypto/rand` and the tag compare already `subtle.ConstantTimeCompare`, so no
  change was needed there.)
- CI: the Go job runs `go test -race` and `govulncheck`, on Go 1.25 (matching `go.mod`,
  which the previous 1.24 pin did not satisfy).

### Fixed

- `go/engine`: `validate` now rejects PBKDF2 `Rounds: 0` as invalid params
  ("pbkdf2 rounds must be nonzero"), matching the Rust reference. Zero rounds
  would "derive" an all-zero key without error; a crafted or corrupted header
  carrying it now fails cleanly at validation instead. (Decryption already
  failed authentication in that case, so this closes an oddity, not a
  vulnerability.)

### Removed

- The `chacha`, `poly1305`, and `chacha20poly1305` packages (the from-scratch ChaCha20,
  Poly1305, and ChaCha20-Poly1305 AEAD) were removed and moved to the standalone `foxtrot`
  project. They were verified library code only, never used by the engine, so nothing else
  changes. See [Core](../CHANGELOG.md).
