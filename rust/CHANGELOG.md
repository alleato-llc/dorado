# Changelog - Rust port

Changes to the **Rust port only** (`rust/`, the reference implementation). Cross-cutting
changes (project docs, CI, the chunk-size cap policy, the wire format) live in the
[Core CHANGELOG](../CHANGELOG.md) and [docs/spec.md](../docs/spec.md); this file records
the Rust-specific details. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
[VERSIONS.md](../VERSIONS.md) is the master table.

## [Unreleased]

### Added

- `rust/salpa.yaml`: parameterizes the Rust CLI release for
  [salpa](https://github.com/alleato-llc/salpa) (see the Core changelog for the
  workflow-level change). `bins: [dorado, gyotaku]` + `package: archive` bundles both
  CLI binaries and `LICENSE` into one archive per platform.

### Changed

- **Release policy**: the Rust CLI track now auto-releases on every push to `main`
  touching `rust/**`, computing the next `rust-v*` semver from tags + commit
  `#minor`/`#major` annotations (patch by default), instead of requiring a manually
  pushed `rust-v` tag. A one-time `rust-v0.1.0` bootstrap tag keeps the sequence
  consistent with this changelog's existing `0.1.0` version.
- **Release archive naming**: platform archives are now named with salpa's friendly
  os/arch tokens instead of Rust target triples, e.g.
  `dorado-0.1.0-aarch64-apple-darwin.tar.gz` -> `dorado-0.1.0-macos-arm64.tar.gz`,
  `dorado-0.1.0-x86_64-pc-windows-msvc.zip` -> `dorado-0.1.0-windows-x86_64.zip`. The
  archive contents (the `dorado`/`gyotaku` binaries plus `LICENSE`) are unchanged.

- `dorado-engine`: a typed `Error` enum (`AuthFailed`, `MalformedHeader`,
  `UnsupportedVersion`, `InvalidParams`, `Io`) and a `Result<T>` alias, replacing the
  stringly-typed `Result<_, String>`, so callers can match on the failure kind. Wrong
  password and tampering remain a single `AuthFailed` (with a test asserting identical
  messages). Frontends absorb it via `From<Error> for String`.
- `dorado-engine`: env knobs (defaults in code, env only overrides). `DORADO_RNG` selects
  the CSPRNG source (`os` default, or `thread`). `DORADO_MAX_CHUNK_BYTES` overrides the
  accepted chunk-size cap. New `DEFAULT_MAX_CHUNK_BYTES` and `max_chunk_bytes()`.

### Changed

- `dorado-engine`: the default container encryption RNG is now `OsRng` (was
  `rand::thread_rng()`); both are CSPRNGs, so existing and new files are unaffected.
- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling,
  `DORADO_MAX_CHUNK_BYTES` clamped to tighten); see [Core](../CHANGELOG.md). Rust is the
  originating implementation.
- `dorado` / `dorado-engine`: removed the infallible `try_into().unwrap()` byte-to-word
  conversions in the cipher and hashers in favor of explicit array indexing or `expect`
  with an invariant message. Behavior is byte-identical (verified by the known-answer and
  differential tests) and throughput is unchanged.

### Removed

- `dorado`: the `chacha`, `poly1305`, and `chacha20poly1305` modules (the from-scratch
  ChaCha20, Poly1305, and ChaCha20-Poly1305 AEAD) were removed and moved to the standalone
  `foxtrot` project, along with the bench's `chacha20` case. They were verified library
  code only, never used by the engine, so nothing else changes. See [Core](../CHANGELOG.md).
