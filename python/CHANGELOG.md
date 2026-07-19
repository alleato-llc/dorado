# Changelog - Python port

Changes to the **Python port only** (`python/`). Cross-cutting changes (project docs, the
chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the Python-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

- **The `kdf` module gains key-based derivation, the fast form.**
  `derive_from_key(key, domain, out_len)` fans an already high-entropy key out
  into independent, domain-separated children with one Skein-512 keyed hash (its
  own `DRDOkdrv` domain prefix, built on the port's from-scratch primitives, not
  the KDF libraries); `derive_from_key_with(prf, ...)` selects the PRF via the
  new `KdfPrf` enum (`SKEIN512`, the default; `BLAKE3`, which requires a 32-byte
  key and raises `ValueError` otherwise). The former `kdf.derive` is renamed
  `derive_from_password`, and both forms plus `KdfPrf` are exported from the
  package: the parallel names are the guardrail (a password must never take the
  fast path, a key never needs the slow one). Matches the Rust reference's
  `kdf::derive_from_key`/`derive_from_key_with`; known-answer vectors are
  hardcoded from [docs/fixtures/derive-from-key.md](../docs/fixtures/derive-from-key.md).
  API surface only: the container wire format is unchanged.
- **Raw-key mode gains an authenticated construction** (encrypt-then-MAC):
  `encrypt_raw_authenticated`/`decrypt_raw_authenticated` and their `_stream`
  variants in `dorado.engine`, exported from the package. Caller-supplied key,
  no password, no KDF, reusing the password container's chunk/frame machinery.
  See the [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale and
  [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for the byte-level
  construction (key-splitting via domain-separated Skein-512, the frame AAD).
  Bare `raw_ctr`/`raw_ctr_stream` is unchanged and remains the default.
- CLI parity: `dorado` and `gyotaku` gained `--version` (`<name> 0.1.0`); `--help`
  already worked via argparse. See [Core](../CHANGELOG.md).
- Exception subclasses `AuthError`, `MalformedContainer`, and `InvalidParams` under
  `DoradoError` (unifying the previous stray `ValueError`s), exported from the package, so
  callers can classify failures. Wrong password and tampering stay merged as `AuthError`
  (same type and message).
- A fuzz/property test (stdlib `random`, no new dependency) feeding random, truncated, and
  mutated bytes to the decrypt path, asserting only `DoradoError` (never `IndexError`,
  `struct.error`, `MemoryError`, etc.) and no hang.

### Changed

- **Raw-key mode (`--key`/`--key-file`) is now authenticated by default in the
  CLI.** `dorado encrypt --key ... --iv ...` produces encrypt-then-MAC output
  (per `--mac` and `--chunk-kib`, larger than the input by framing and per-chunk
  tags) unless the new `--unauthenticated` flag opts back into the old bare CTR
  behavior (output length equal to input length, no tamper detection); passing
  `--unauthenticated` in password mode is an error, password mode being always
  authenticated. This breaks scripts that assumed raw-key mode's old output
  shape unless they add `--unauthenticated` on both ends. See the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale (authenticated
  as the default, libsodium/age style; bare CTR as an expert opt-out).
- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling,
  `DORADO_MAX_CHUNK_BYTES`); see [Core](../CHANGELOG.md). (MAC verify already used
  `hmac.compare_digest` and salt/IV already `os.urandom`, so no change there.)

### Fixed

- `kdf.validate` now rejects `rounds == 0` for PBKDF2 (`MalformedContainer`,
  "pbkdf2 rounds must be nonzero"), matching the Rust reference: zero rounds
  would "derive" an all-zero key without error. (Decryption already failed
  authentication in that case, so this closes an oddity, not a vulnerability.)

### Notes

- Key zeroization is fundamentally limited: `bytes`/`str` are immutable and cannot be
  reliably wiped. This is documented in the source rather than papered over.
