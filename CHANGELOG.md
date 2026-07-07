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

- **Site deploy workflow** (`.github/workflows/deploy-site.yml`) and **release workflow**
  (`.github/workflows/release.yml`), both driven end-to-end by
  [salpa](https://github.com/alleato-llc/salpa) (a private house release tool, pulled from
  ghcr) instead of raw `aws`/packaging commands in the workflow YAML — the house
  convention also used by the sibling `soroban` project. `salpa.yaml` (repo root) and
  `rust/salpa.yaml` parameterize the two stages: `salpa deploy` and `salpa
  build`/`test`/`publish`/`version`.
  - **Deploy**: pushes to `main` that touch `web/**` build the Astro landing page and
    deploy it to `dorado.alleato.dev` (S3 + CloudFront, provisioned separately as IaC)
    over short-lived OIDC credentials, then invalidate the CDN (the distribution is
    resolved at runtime by its alias, no id wired into the workflow). Path-filtered, so
    a commit that does not touch `web/` never deploys. Also redeploys on a new
    `rust-v*` release (`release: published`), so the landing page's download links
    (see [`web/CHANGELOG.md`](web/CHANGELOG.md)) pick up the freshly published
    binaries.
  - **Release**: the Rust CLI track now **auto-releases on every push to `main` that
    touches `rust/**`** (no manual `git tag` step) — `salpa version` computes the next
    semver from `rust-v*` tags plus `#minor`/`#major` in the commit message (patch by
    default), and `salpa build`/`publish` (run once per CLI, via `--config
    salpa-dorado.yaml`/`salpa-gyotaku.yaml`) produce one bare binary per platform per CLI
    (Linux, macOS Intel + Apple Silicon, Windows) — no archive, so each CLI downloads as
    a single file. `LICENSE` is attached to the release once rather than duplicated per
    platform. See [`rust/CHANGELOG.md`](rust/CHANGELOG.md) for the release-policy and
    packaging details. Other ports can add their own `<port>-v*` tracks later.
- **C++ port** (`cpp/`), the tenth implementation: an SDK (`libdorado.a`) plus the
  `dorado`/`gyotaku` CLIs, byte-for-byte cross-compatible with the others (verified by
  decrypting the Rust CLI's `.mahi` fixtures and by Rust decrypting its output, with
  matching `gyotaku` digests). C++23 with CMake; like Haskell it implements
  SHA-256/HMAC-SHA256 from scratch, and its sole dependency is OpenSSL (the three
  password KDFs go through `EVP_KDF`; everything else is from scratch). The docs now say
  "ten implementations" (`README.md`, root `CLAUDE.md`, `docs/implementations.md`,
  `VERSIONS.md`). CI gains a path-filtered `cpp` job, wired into the `changes` filter and
  re-run on `docs/spec.md` changes like the other ports. Per-port details are in
  [`cpp/CHANGELOG.md`](cpp/CHANGELOG.md).

### Changed

- CI (`.github/workflows/ci.yml`) gains soroban-style hardening: a least-privilege
  top-level `permissions: contents: read` (the RustSec audit job widens its own token to
  `issues: write`), workflow-level `concurrency` so a new push supersedes the in-flight
  run for the same ref, and a human-readable `name:` on every job. The path-filtered
  per-component structure is unchanged.
- CI: the `cpp` job gains a sanitized rerun (a second CMake build with `-DSANITIZE=ON`,
  ASan + UBSan), matching the C/Zig tier of per-port hardening. Details in
  [`cpp/CHANGELOG.md`](cpp/CHANGELOG.md).
- **Haskell port** (`haskell/`), the ninth implementation: an SDK plus the
  `dorado`/`gyotaku` CLIs, byte-for-byte cross-compatible with the others (verified by
  decrypting the Rust CLI's `.mahi` fixtures and by Rust decrypting its output). It is
  the first port to implement SHA-256/HMAC-SHA256 from scratch as well; KDFs are
  delegated to `crypton`. The docs now say "nine implementations" (`README.md`, root
  `CLAUDE.md`, `docs/implementations.md`, `VERSIONS.md`). CI gains a path-filtered
  `haskell` job (GHC 9.14 + cabal, `cabal test`), wired into the `changes` filter and
  re-run on `docs/spec.md` changes like the other ports. Per-port details are in
  [`haskell/CHANGELOG.md`](haskell/CHANGELOG.md).
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
- CI is now path-filtered: a `changes` job (`dorny/paths-filter`) detects which
  component folders changed, and each job runs only when relevant. To preserve the
  cross-compat invariant, a change to the wire-format spec (`docs/spec.md`) or to the
  workflow itself re-runs every port's suite; a pure docs/changelog change runs no
  build jobs. Skipped jobs are reported as passing, so required checks are unaffected.
- Docs: standardized the per-language port READMEs (`go`, `ts`, `java`, `python`, `c`,
  `zig`) to one template (intro, Layout, Build, Use with SDK + CLI, Testing,
  Cross-compatibility, then port-specific notes); the Rust README stays the fuller
  reference. Corrected stale "all four implementations" wording to "all the ports" in
  `docs/spec.md`, `rust/docs/overview.md`, `rust/CLAUDE.md`, and `rust/README.md`.

### Removed

- **ChaCha20-Poly1305 extracted to its own project.** The from-scratch ChaCha20
  stream cipher, Poly1305 one-time MAC, and ChaCha20-Poly1305 AEAD (RFC 8439) were
  removed from the Rust, Go, and TypeScript ports and moved into a standalone sibling
  project, `foxtrot`. They were verified library code only, never wired into the
  container (dorado stays Threefish-based), so this is not a wire-format change and
  cross-compatibility is unaffected. Per-port removals are in each port's changelog.
