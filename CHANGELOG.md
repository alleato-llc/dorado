# Changelog - Core

The **core** changelog for the dorado monorepo: the cross-cutting pieces only - the
project-wide docs (`docs/`, `SECURITY.md`), the repo-wide CI, and cross-port decisions
recorded once here and pointed to from each port. Per-port changes live in each
`<port>/CHANGELOG.md`; the on-disk wire format is versioned in
[`docs/spec.md`](docs/spec.md); [`VERSIONS.md`](VERSIONS.md) is the master table of every
component and its current version.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); when a
release is cut, the `Unreleased` entries get a dated version heading below.

**Rule:** route each change by what it touches. A change to a single port goes in that
port's changelog; a project-wide doc, CI, or a cross-port decision goes here; a
wire-format change is a coordinated bump of `format::VERSION` recorded here and in every
port's changelog. Add the bullet under Added / Changed / Fixed / Removed **in the same
commit or PR**. Wire-format or algorithm changes must say so, since they affect
cross-compatibility across all ports.

This changelog starts in 2026-06; for earlier history see the git log.

## [Unreleased]

### Added

- CLI feature parity across every CLI port (`go`, `python`, `c`, `zig`, `ts`; Rust is
  the reference). Both binaries (`dorado` and `gyotaku`) in every port now accept
  `--help`/`-h` (usage to stdout, exit 0) and `--version` (`<name> 0.1.0`), and
  `gyotaku` accepts both `-c` and `--check`. The flag surface (encrypt/decrypt/inspect
  plus every option) was already consistent; this closes the `--help`/`--version`
  gaps. Per-port specifics are in each port's changelog.
- `SECURITY.md`: the project threat model, explicit non-goals, and the vulnerability
  reporting process.
- Per-component versioning: a [`VERSIONS.md`](VERSIONS.md) master table and a changelog
  per port (plus `bench/` and `web/`), replacing the single global changelog. A change is
  now routed to the changelog of whatever it touches.

### Changed

- **Chunk-size acceptance policy, applied across all eight ports.** The default accepted
  container chunk-size cap is now 64 MiB (was 1 GiB); 1 GiB remains the hard ceiling, and
  a `DORADO_MAX_CHUNK_BYTES` environment override is honored, clamped so it can only
  tighten below the ceiling. This bounds the per-frame allocation from an untrusted
  header. It is decoder/encoder acceptance policy, **not a wire-format change**: normal
  files (64 KiB chunks) round-trip and cross-decrypt unchanged. Per-port implementation
  details are in each port's changelog.
- **Security audit across all eight ports** (Rust and Go first, then Java, Python, C,
  Zig, TypeScript). Cross-cutting outcome: typed/classifiable errors in every port with
  wrong-password and tampering kept indistinguishable, fuzz/smash harnesses over the
  decrypt path, and the chunk-cap policy above. Per-port specifics (error types, RNG,
  zeroization, sanitizers, CI) are in each port's changelog.
- CI: per-port hardening landed (see the Go and C port changelogs for `go test -race` +
  `govulncheck` and the C ASan/UBSan run). The container format is unchanged at `v4`.
