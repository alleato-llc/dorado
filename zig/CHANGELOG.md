# Changelog - Zig port

Changes to the **Zig port only** (`zig/`, Zig 0.16). Cross-cutting changes (project docs,
the chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md)
and [docs/spec.md](../docs/spec.md); this file records the Zig-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

- The `dorado` CLI suppresses core dumps at startup
  (`std.posix.setrlimit(.CORE, ...)` in `cli_dorado.zig`), so a crash cannot
  leave the password or derived keys in a core file. `mlock` keeps those pages
  out of swap but not out of a core dump, so this complements it. Best-effort,
  POSIX-only, a no-op on `.windows`/`.wasi`. See the
  [Core changelog](../CHANGELOG.md) for the cross-port rationale.
- `zig/src/kdf.zig`: key-based derivation (`deriveFromKey` / `deriveFromKeyWith`
  with a `KdfPrf` enum: `.skein512`, the default, or `.blake3`), the fast
  domain-separated fan-out of an already high-entropy key into independent
  per-purpose children, alongside the existing password KDFs. One keyed hash
  (`out = PRF(key, "DRDOkdrv" ++ domain)`), no salt, no cost parameters; built
  on the port's own from-scratch Skein-512/BLAKE3, not `std.crypto`. The BLAKE3
  PRF requires a 32-byte key (`error.BadKeyLength` otherwise). The names are
  the guardrail: a password must never take the fast path, a key never needs
  the slow one. Ports the Rust reference construction; see the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale. Verified
  against the six cross-language known-answer vectors in
  [docs/fixtures/derive-from-key.md](../docs/fixtures/derive-from-key.md).
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
  `rawCtrStream` (bare, unauthenticated) is unchanged and remains available.
- CLI parity: `dorado` and `gyotaku` now support `--help`/`-h` (usage to stdout,
  exit 0) and `--version` (`<name> 0.1.0`); previously both printed the error-usage and
  `gyotaku --help` tried to open `--help` as a file. See [Core](../CHANGELOG.md).
- A seeded smash/fuzz test over the decrypt path (random, truncated, and mutated inputs),
  asserting only the engine's declared errors and no panic or UB under ReleaseSafe. It
  surfaced no bug; the existing parse bounds hold.

### Changed

- `dorado` CLI: raw-key mode (`--key`/`--key-file`) is now authenticated by
  default, streaming encrypt-then-MAC via the raw authenticated construction
  (`--mac` and `--chunk-kib` apply to it), with a new `--unauthenticated` flag
  opting back into bare CTR (confidentiality only, no tamper detection; a
  deliberate, expert opt-out). `--unauthenticated` with a password is an error
  (password mode is always authenticated). Mirrors the Rust CLI; see
  [Core](../CHANGELOG.md).
- `kdf.validate` also rejects `rounds == 0` for PBKDF2 (zero rounds would
  "derive" an all-zero key without error), reported as `error.HostileCost` like
  the other out-of-bounds header parameters, matching the Rust reference's
  `InvalidParams` bound.
- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling); the
  `DORADO_MAX_CHUNK_BYTES` override is resolved at the CLI boundary, since the libc-free
  SDK module cannot call `getenv`. See [Core](../CHANGELOG.md). (The error set already
  distinguished failure kinds with wrong-password and tampering merged into
  `error.AuthFailed`, the tag compare already used `std.crypto.timing_safe.eql`, and key
  material is wiped with `secureZero`, so no change there.)
