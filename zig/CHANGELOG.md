# Changelog - Zig port

Changes to the **Zig port only** (`zig/`, Zig 0.16). Cross-cutting changes (project docs,
the chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md)
and [docs/spec.md](../docs/spec.md); this file records the Zig-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

- `zig/src/engine.zig`: raw-key authenticated mode
  (`encryptRawAuthenticatedStream` / `decryptRawAuthenticatedStream` / the
  `encryptRawAuthenticated` / `decryptRawAuthenticated` slice wrappers),
  encrypt-then-MAC over a caller-supplied key with no password or KDF, reusing
  the password container's chunk/frame machinery. Ports the Rust reference
  construction; see the [Core CHANGELOG](../CHANGELOG.md) for the cross-port
  rationale and [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for
  the byte-level construction. Verified against the six cross-language
  known-answer vectors in
  [docs/fixtures/raw-authenticated.md](../docs/fixtures/raw-authenticated.md).
  `rawCtrStream` (bare, unauthenticated) is unchanged and remains the default.
- CLI parity: `dorado` and `gyotaku` now support `--help`/`-h` (usage to stdout,
  exit 0) and `--version` (`<name> 0.1.0`); previously both printed the error-usage and
  `gyotaku --help` tried to open `--help` as a file. See [Core](../CHANGELOG.md).
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
