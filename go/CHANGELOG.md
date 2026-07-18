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
  `RawCTRStream` (bare, unauthenticated) is unchanged and remains the default.
- `go/engine`: exported sentinel errors (`ErrAuthFailed`, `ErrMalformedContainer`,
  `ErrUnsupportedVersion`, `ErrInvalidParams`) wrapped with `%w`, so callers classify
  failures with `errors.Is` instead of matching strings. Wrong password and tampering
  stay merged as `ErrAuthFailed`.
- `go/engine`: a native `FuzzDecryptPasswordBytes` fuzz target over the decrypt path, and
  an exported `MaxChunkBytes()`.

### Changed

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

### Removed

- The `chacha`, `poly1305`, and `chacha20poly1305` packages (the from-scratch ChaCha20,
  Poly1305, and ChaCha20-Poly1305 AEAD) were removed and moved to the standalone `foxtrot`
  project. They were verified library code only, never used by the engine, so nothing else
  changes. See [Core](../CHANGELOG.md).
