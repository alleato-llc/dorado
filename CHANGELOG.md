# Changelog

Notable changes to the dorado monorepo. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); when releases are cut they
get a dated version heading below `Unreleased`. This changelog starts in 2026-06; for
earlier history see the git log.

**Rule:** any change worth noting (a feature, a fix, a wire-format or behavior change,
a notable doc change) adds a bullet to the `Unreleased` section **in the same commit or
PR**, grouped under Added / Changed / Fixed / Removed. Wire-format or algorithm changes
must say so explicitly, since they affect cross-compatibility across all ports.

## [Unreleased]

### Fixed

- `bench/report.html` was regenerated empty; rebuilt it from `results.json` with the
  data embedded. Also reworded `report_template.html`'s comment (synced from Gota) so
  the substitution tokens it documented no longer get replaced into the comment.

### Added

- `dorado-engine`: a typed `Error` enum (`AuthFailed`, `MalformedHeader`,
  `UnsupportedVersion`, `InvalidParams`, `Io`) and a `Result<T>` alias, replacing the
  previous stringly-typed `Result<_, String>`, so callers can match on the failure
  kind. Wrong password and tampering remain a single `AuthFailed` so they stay
  indistinguishable. The frontends still render errors via `Display`.
- `dorado-engine`: two standalone env knobs (defaults in code, env only overrides).
  `DORADO_RNG` selects the CSPRNG source (`os` default, or `thread`).
  `DORADO_MAX_CHUNK_BYTES` overrides the accepted chunk-size cap, clamped to the
  `MAX_CHUNK_BYTES` hard ceiling so it can only tighten. New public
  `DEFAULT_MAX_CHUNK_BYTES` and `max_chunk_bytes()`.
- `go/engine`: exported sentinel errors (`ErrAuthFailed`, `ErrMalformedContainer`,
  `ErrUnsupportedVersion`, `ErrInvalidParams`) wrapped with `%w`, so callers classify
  failures with `errors.Is` instead of matching strings. Wrong password and tampering
  stay merged as `ErrAuthFailed`. Mirrors the `dorado-engine` typed errors.
- `go/engine`: a `DORADO_MAX_CHUNK_BYTES` override (clamped to the 1 GiB hard ceiling,
  can only tighten), exported `MaxChunkBytes()`, and a native fuzz target
  `FuzzDecryptPasswordBytes` over the decrypt path.
- `SECURITY.md`: the threat model, non-goals, and reporting process.
- `bench/`: an HTML report (`report.py` + `report_template.html`) that renders
  `results.json` into a self-contained `report.html` (sortable, per-language colors,
  magnitude bars, formatted MB/s, with a file picker).

### Changed

- `dorado-engine`: the default container encryption RNG is now `OsRng` (was
  `rand::thread_rng()`); both are CSPRNGs, so existing and new files are unaffected.
- `dorado-engine`: the default cap on an accepted chunk size dropped from 1 GiB to
  64 MiB (`DEFAULT_MAX_CHUNK_BYTES`); `MAX_CHUNK_BYTES` (1 GiB) is now the hard
  ceiling. This is a decoder acceptance policy, not a wire-format change: normal files
  (64 KiB chunks) are unaffected, and a larger cap can be restored per host via
  `DORADO_MAX_CHUNK_BYTES`.
- `dorado` / `dorado-engine`: removed the infallible `try_into().unwrap()` byte-to-word
  conversions in the cipher and hashers in favor of explicit array indexing or
  `expect` with an invariant message. Behavior is byte-identical (verified by the
  known-answer and differential tests) and throughput is unchanged.
- `go/engine`: the default accepted chunk-size cap dropped from 1 GiB to 64 MiB
  (parity with `dorado-engine`); 1 GiB is now the hard ceiling. The Go CLI caps
  `--chunk-kib` to the effective max so encryption matches the default decrypt cap.
  Decoder policy, not a wire-format change.
- CI: the Go job runs `go test -race` and `govulncheck`, on Go 1.25 (matching
  `go/go.mod`, which the previous 1.24 pin did not satisfy).
- `bench/` is now a consumer of [Gota](https://github.com/alleato-llc/gota), the
  standalone cross-language micro-benchmark reference extracted from this harness.
  `harness.py`, `report.py`, and `report_template.html` are copies from Gota (do not
  edit in place; change them in Gota and re-copy).
- `bench/`: replaced the shell orchestrator (`run.sh`) with the Python `run.py` plus
  the generic `harness.py`; subprocess capture isolates each runner's output, fixing a
  shell append-race that could scramble it.
