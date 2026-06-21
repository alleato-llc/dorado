# Changelog - Python port

Changes to the **Python port only** (`python/`). Cross-cutting changes (project docs, the
chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the Python-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

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
