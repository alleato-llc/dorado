# Changelog - Python port

Changes to the **Python port only** (`python/`). Cross-cutting changes (project docs, the
chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the Python-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

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

- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling,
  `DORADO_MAX_CHUNK_BYTES`); see [Core](../CHANGELOG.md). (MAC verify already used
  `hmac.compare_digest` and salt/IV already `os.urandom`, so no change there.)

### Notes

- Key zeroization is fundamentally limited: `bytes`/`str` are immutable and cannot be
  reliably wiped. This is documented in the source rather than papered over.
