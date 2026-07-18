# Changelog - C port

Changes to the **C port only** (`c/`). Cross-cutting changes (project docs, the
chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the C-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

- **Raw-key mode gains an authenticated option**: `dorado_encrypt_raw_authenticated_stream`
  / `dorado_decrypt_raw_authenticated_stream` (plus `dorado_encrypt_raw_authenticated` /
  `dorado_decrypt_raw_authenticated` in-memory wrappers), encrypt-then-MAC over the
  caller-supplied key with no password or KDF, reusing the password container's
  chunk/frame/MAC machinery. Decryption verifies each frame before decrypting it and
  returns `dorado_err_auth` (merged with wrong-key) on a corrupted, tampered, or
  wrong-key stream. See the [Core CHANGELOG](../CHANGELOG.md) for the cross-port
  rationale and [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for the
  byte-level construction. `dorado_raw_ctr_stream` is unchanged and remains the default.
- CLI parity: `dorado` and `gyotaku` now support `--help`/`-h` (usage to stdout,
  exit 0) and `--version` (`<name> 0.1.0`); both previously errored on `--help`. See
  [Core](../CHANGELOG.md).
- Pointer-classifiable sentinel error strings (`dorado_err_auth`, `dorado_err_malformed`,
  `dorado_err_params`) returned by identity, so a caller can classify a failure by pointer
  comparison without an API change. Wrong password and tampering both map to
  `dorado_err_auth` (merged).
- A sanitized test build: `make test SAN=1` runs the suite under AddressSanitizer +
  UndefinedBehaviorSanitizer; CI runs it. A 20k-iteration smash test over the decrypt path
  (run under the sanitizers) and a libFuzzer target (`make fuzz`).

### Changed

- Applied the chunk-size cap policy (`DORADO_DEFAULT_MAX_CHUNK_BYTES` 64 MiB, 1 GiB hard
  ceiling, `DORADO_MAX_CHUNK_BYTES`); see [Core](../CHANGELOG.md). (Tag compare already
  used `CRYPTO_memcmp`, salt/IV `getentropy`, and keys are wiped with `OPENSSL_cleanse`,
  so no change there.)

### Fixed

- The docs claimed `make test` ran under ASan/UBSan, but the build used neither. The claim
  is now true via `make test SAN=1` (CI runs it); `c/README.md` and the C section of the
  repo-root `CLAUDE.md` were corrected to describe it accurately (plain `make test` is
  unsanitized).
