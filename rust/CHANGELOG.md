# Changelog - Rust port

Changes to the **Rust port only** (`rust/`, the reference implementation). Cross-cutting
changes (project docs, CI, the chunk-size cap policy, the wire format) live in the
[Core CHANGELOG](../CHANGELOG.md) and [docs/spec.md](../docs/spec.md); this file records
the Rust-specific details. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
[VERSIONS.md](../VERSIONS.md) is the master table.

## [Unreleased]

### Added

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
