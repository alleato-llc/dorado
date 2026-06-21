# Changelog - Zig port

Changes to the **Zig port only** (`zig/`, Zig 0.16). Cross-cutting changes (project docs,
the chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md)
and [docs/spec.md](../docs/spec.md); this file records the Zig-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

- A seeded smash/fuzz test over the decrypt path (random, truncated, and mutated inputs),
  asserting only the engine's declared errors and no panic or UB under ReleaseSafe. It
  surfaced no bug; the existing parse bounds hold.

### Changed

- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling); the
  `DORADO_MAX_CHUNK_BYTES` override is resolved at the CLI boundary, since the libc-free
  SDK module cannot call `getenv`. See [Core](../CHANGELOG.md). (The error set already
  distinguished failure kinds with wrong-password and tampering merged into
  `error.AuthFailed`, the tag compare already used `std.crypto.timing_safe.eql`, and key
  material is wiped with `secureZero`, so no change there.)
