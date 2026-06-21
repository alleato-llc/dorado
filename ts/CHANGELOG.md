# Changelog - TypeScript port

Changes to the **TypeScript port only** (`ts/`). Cross-cutting changes (project docs, the
chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the TypeScript-specific details.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
[VERSIONS.md](../VERSIONS.md) is the master table.

## [Unreleased]

### Added

- CLI parity: `dorado`/`gyotaku` now support `--help`/`-h` (usage to stdout, exit 0),
  and `gyotaku` accepts `--check` as well as `-c`; `--version` already worked. See
  [Core](../CHANGELOG.md).
- A `DoradoError` base with `AuthError`, `MalformedContainerError`, and
  `InvalidParamsError` subclasses, exported for `instanceof`, so callers can classify
  failures. Wrong password and tampering stay merged as `AuthError` (same class and
  message).
- A seeded fuzz/property test over the decrypt path, asserting only `DoradoError`
  subclasses (never a bare `Error`/`TypeError`/`RangeError`) and no hang.

### Changed

- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling). The
  `DORADO_MAX_CHUNK_BYTES` override is read with a browser-safe `process` guard. See
  [Core](../CHANGELOG.md). (The tag compare already used a length-independent
  XOR-accumulate and salt/IV `crypto.getRandomValues`, so no change there.)

### Removed

- `src/chacha.ts`, `src/poly1305.ts`, `src/chacha20poly1305.ts`, and `src/aead.test.ts`
  (the from-scratch ChaCha20, Poly1305, and ChaCha20-Poly1305 AEAD) were removed and moved
  to the standalone `foxtrot` project. They were verified library code only, never used by
  the engine, so nothing else changes. See [Core](../CHANGELOG.md).

### Notes

- Key zeroization is fundamentally limited in JS (GC-managed, immutable strings); the Node
  CLI does the best available (libsodium `sodium_malloc`/`sodium_memzero` for the
  password), documented rather than papered over.
- `npm audit` reports five advisories, all confined to the `vitest` dev-tooling chain
  (dev-only, not in the published library or browser bundle). The only fix is a breaking
  `vitest` major bump, deferred for maintainer triage.
