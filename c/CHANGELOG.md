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
  byte-level construction. `dorado_raw_ctr_stream` is unchanged (the CLI's raw-key
  default did change; see Changed below).
- **Key-based derivation**: `dorado_kdf_derive_from_key` (and
  `dorado_kdf_derive_from_key_with`, taking a `DORADO_KDF_PRF_SKEIN512` /
  `DORADO_KDF_PRF_BLAKE3` PRF selector), the fast form of key derivation alongside the
  password KDFs, mirroring the Rust reference's `kdf::derive_from_key` /
  `derive_from_key_with` (see [rust/CHANGELOG.md](../rust/CHANGELOG.md) for the
  rationale). One domain-separated keyed hash (`"DRDOkdrv" || domain`) fans an already
  high-entropy key out into independent per-purpose subkeys: Skein-512 keyed by default
  (any key length), BLAKE3 keyed selectable (requires a 32-byte key; other lengths
  return `dorado_err_params`). Built on the port's own from-scratch Skein-512/BLAKE3
  (libargon2/OpenSSL stay password-KDF-only). Library API only; the wire format is
  untouched. Known-answer tests hardcode the six cross-language vectors from
  [docs/fixtures/derive-from-key.md](../docs/fixtures/derive-from-key.md).
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

- **CLI raw-key mode (`--key`/`--key-file`) is now authenticated by default**,
  matching the Rust reference CLI: `dorado encrypt --key ... --iv ...` produces
  encrypt-then-MAC output via `dorado_encrypt_raw_authenticated_stream` (larger than
  the input, by per-frame tag and framing overhead), and `--mac`/`--chunk-kib` now
  apply to raw-key mode too. The new `--unauthenticated` flag opts back into bare CTR
  (`dorado_raw_ctr_stream`, output length exactly equal to input length, no tamper
  detection); passing it in password mode is an error, since password mode is always
  authenticated. This breaks any script that assumed raw-key mode's old bare-CTR
  output shape without also adding `--unauthenticated` on both ends. Library API
  unchanged. See the [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale
  (authenticated-by-default, the libsodium/age precedent).
- Applied the chunk-size cap policy (`DORADO_DEFAULT_MAX_CHUNK_BYTES` 64 MiB, 1 GiB hard
  ceiling, `DORADO_MAX_CHUNK_BYTES`); see [Core](../CHANGELOG.md). (Tag compare already
  used `CRYPTO_memcmp`, salt/IV `getentropy`, and keys are wiped with `OPENSSL_cleanse`,
  so no change there.)

### Fixed

- `dorado_kdf_validate` now rejects PBKDF2 `rounds == 0` (as `dorado_err_params`,
  like the other bounds), matching the Rust reference's `kdf::validate`. Zero rounds
  would "derive" an all-zero key without error; a crafted or corrupted header
  carrying it now fails cleanly at validation. (Decryption already failed
  authentication in that case, so this closes an oddity, not a vulnerability.)
- The docs claimed `make test` ran under ASan/UBSan, but the build used neither. The claim
  is now true via `make test SAN=1` (CI runs it); `c/README.md` and the C section of the
  repo-root `CLAUDE.md` were corrected to describe it accurately (plain `make test` is
  unsanitized).
