# Changelog - TypeScript port

Changes to the **TypeScript port only** (`ts/`). Cross-cutting changes (project docs, the
chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the TypeScript-specific details.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
[VERSIONS.md](../VERSIONS.md) is the master table.

## [Unreleased]

### Added

- **Both standard forms of key derivation are now public** (`src/engine/kdf.ts`,
  re-exported from `src/engine/engine.ts`). The password entry point is renamed
  `derive` → `deriveFromPassword` (same signature and output; it was only used
  internally by the engine, so nothing external breaks), and the new
  `deriveFromKey(key, domain, outLen)` is the fast, key-based form: one
  domain-separated keyed hash (its own `DRDOkdrv` prefix) fanning an already
  high-entropy key out into independent per-purpose children, over the port's
  own from-scratch primitives via the swappable `CipherBackend` (no `hash-wasm`).
  `deriveFromKeyWith(prf, ...)` selects the PRF (`KdfPrf`, `"skein512"` default —
  any key length — or `"blake3"`, which requires a 32-byte key and throws
  `InvalidParamsError` otherwise). The parallel names are the guardrail: a
  password must never take the fast path, a key never needs the slow one. API
  surface only; the container wire format is untouched. Mirrors the Rust
  reference (`dorado-engine::kdf`); verified against all six known-answer
  vectors in [docs/fixtures/derive-from-key.md](../docs/fixtures/derive-from-key.md).
- **Raw-key mode gains an authenticated construction** (encrypt-then-MAC):
  `encryptRawAuthenticatedBytes` / `decryptRawAuthenticatedBytes` in
  `src/engine/engine.ts`, keyed directly by a caller-supplied key with no
  password or KDF, reusing the password container's frame/MAC machinery
  (`splitRawKey`, `rawFrameAAD`). A wrong key, corruption, or tampering throws
  `AuthError`, matching the password container's error taxonomy. `rawCTR` is
  unchanged and remains the default. See the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale and
  [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for the byte-level
  construction; verified against the six known-answer vectors in
  [docs/fixtures/raw-authenticated.md](../docs/fixtures/raw-authenticated.md).
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

- **The Node CLI's raw-key mode (`--key`/`--key-file`) is now authenticated by
  default.** `dorado encrypt --key ... --iv ...` produces encrypt-then-MAC
  output (`encryptRawAuthenticatedBytes`; `--mac` and `--chunk-kib` apply)
  instead of bare CTR, and decrypt rejects a tampered, corrupted, or wrong-key
  stream; the new `--unauthenticated` flag opts back into bare CTR (output
  length equal to input length), and is an error in password mode, which is
  always authenticated. This breaks any script that assumed raw-key mode's old
  output shape unless it adds `--unauthenticated` on both ends. Matches the
  Rust CLI; see the [Core CHANGELOG](../CHANGELOG.md) for the cross-port
  rationale (authenticated as the default, reach-for behavior, per libsodium
  and age precedent).
- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling). The
  `DORADO_MAX_CHUNK_BYTES` override is read with a browser-safe `process` guard. See
  [Core](../CHANGELOG.md). (The tag compare already used a length-independent
  XOR-accumulate and salt/IV `crypto.getRandomValues`, so no change there.)

### Fixed

- `validate` (`src/engine/kdf.ts`) now rejects PBKDF2 `rounds: 0`
  ("pbkdf2 rounds must be nonzero") in addition to the too-large bound. Zero
  rounds would "derive" an all-zero key without error; a crafted or corrupted
  header carrying it now fails cleanly at validation instead. Matches the Rust
  reference fix. (Decryption already failed authentication in that case, so
  this closes an oddity, not a vulnerability.)

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
