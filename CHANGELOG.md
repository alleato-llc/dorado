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

- **Both standard forms of key derivation are now public API in every port**, a
  cross-port decision recorded here. Each port exposes the slow password
  stretch (`derive_from_password` in its per-language spelling) and the fast
  key-based fan-out (`derive_from_key`: one keyed hash over the fixed
  `DRDOkdrv` domain prefix plus a caller domain string, splitting an already
  high-entropy key into independent per-purpose children, with a selectable
  PRF, Skein-512 by default or BLAKE3 keyed, the latter requiring a 32-byte
  key). The parallel names are the guardrail: a password must never take the
  fast path (nothing stretches it), a key never needs the slow one. The
  feature originated in Rust (see [`rust/CHANGELOG.md`](rust/CHANGELOG.md)
  for the rationale and its first consumer) and is now ported to all nine
  code ports with idiomatic naming; every port verifies the six shared
  known-answer vectors in
  [`docs/fixtures/derive-from-key.md`](docs/fixtures/derive-from-key.md),
  generated from and pinned by the Rust reference. Library API only: the
  on-disk container format is untouched.
- **Raw-key mode gains an authenticated construction** (encrypt-then-MAC), a
  cross-port decision recorded here and being ported to every language
  (Rust is the reference; see [`rust/CHANGELOG.md`](rust/CHANGELOG.md) for the
  Rust-specific entry, and the byte-level construction is documented in
  [`docs/spec.md`](docs/spec.md) under "Raw-key modes"). Bare raw-key CTR is
  unauthenticated by design (confidentiality only, no header) — a corrupted or
  tampered ciphertext byte silently decrypts to a flipped plaintext byte, with
  no error, because CTR mode has nothing that can detect it. This was
  considered acceptable when raw mode's only consumer needed a low-level,
  bring-your-own-integrity primitive, but it is the wrong tool for a consumer
  that needs to detect corruption or tampering and refuse to load rather than
  silently produce wrong data. Rather than have that consumer build its own
  MAC composition ad hoc (reintroducing the hand-rolled-composition risk this
  project exists to avoid, just one layer up), the fix is in dorado itself:
  raw-key mode gains a second path that reuses already-shipped, already-tested
  pieces (the password container's chunk/frame/MAC machinery, Skein-512 keyed
  hashing) rather than inventing new primitives. The caller's raw key is split
  into an independent encryption subkey and MAC subkey via domain-separated
  Skein-512 keyed hashing (not a password KDF — the caller's key is assumed
  already high-entropy, so no cost-parameterized stretching is needed, only
  subkey separation); frames reuse the password container's exact wire
  layout; the tweak and IV are bound into the frame AAD (there being no
  header to bind them into the way the password container does), under a
  domain separator distinct from the password path's so the two can never
  collide. At the library level both raw-key functions (bare and
  authenticated) are equally first-class — a caller always names the one it
  wants, there is no "default" to speak of there. **The CLI is a different
  matter, and its default changed**: `dorado encrypt --key ...` is now
  authenticated by default, with bare CTR moved behind an explicit
  `--unauthenticated` opt-out (see [`rust/CHANGELOG.md`](rust/CHANGELOG.md)'s
  own Changed entry for the concrete behavior and breakage). The reasoning:
  tools that treat security as a primary design goal (libsodium, age) make
  the authenticated construction the thing you get by default and demote or
  omit the bare primitive; tools that expose the bare primitive as the plain
  default (`openssl enc -ctr` and similar) are the older style the security
  community has spent years steering people away from for anything
  sensitive. A casual CLI user typing `--key`/`--iv` is far more likely to be
  protecting real data than building a custom protocol layer on the bare
  primitive, and is much less likely to already know to ask for
  authentication than someone with the latter need is to tolerate an extra
  flag. The bare primitive remains fully available, at both the library and
  CLI layers — it still has legitimate uses (cross-language interop,
  composability, dorado's own educational purpose) — it is simply no longer
  what you get by not asking.
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
- **Screenshot-generation script + CI workflow** (`scripts/generate_screenshots.py`,
  `.github/workflows/screenshots.yml`), ported from soroban's own
  (`soroban/scripts/generate_screenshots.py` /
  `.github/workflows/screenshots.yml`): drives `dorado-gui`'s and
  `dorado-gyotaku-gui`'s permanent env-gated `src/shot.rs` harnesses (see
  [`rust/CHANGELOG.md`](rust/CHANGELOG.md)) to produce a small, fixed set of PNGs
  landing in [`web/public/screenshots/`](web/public/screenshots/) — an "encrypt"
  scene for `dorado-gui` and a "hash" scene for `dorado-gyotaku-gui`, each in
  rime's "Dracula" (dark) and "Solarized Light" (light) built-in themes (4
  images total: `dorado-encrypt-<theme>.png`, `gyotaku-hash-<theme>.png`). Each
  crate is excluded from the main Rust workspace
  and resolves its own `Cargo.lock` (see `rust/Cargo.toml`'s exclude comment), so
  the script runs `cargo run` separately in each crate's own directory rather than
  from one shared workspace root, unlike soroban's single `rust/gui`. The workflow
  is manual (`workflow_dispatch`) plus path-filtered on push to `main`
  (`rust/crates/dorado-gui/**`, `rust/crates/dorado-gyotaku-gui/**`, the script
  itself); it checks out `dorado` and the sibling `alleato-llc/rime` repo side by
  side (matching `ci.yml`'s `gui` job), captures headlessly via Xvfb + software
  Vulkan (lavapipe) with a software-GL (llvmpipe) fallback, and commits the
  regenerated PNGs as `github-actions[bot]` with no `[skip ci]` so the commit's
  `web/**` path re-triggers `deploy-site.yml`.
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

- **The raw-key CLI default is now uniform across every port**: all eight
  CLI-bearing ports (Rust, Go, TS/Node, Python, C, Zig, Haskell, C++; Java is
  SDK-only by design) encrypt and decrypt `--key`/`--key-file` mode
  authenticated by default, with the same `--unauthenticated` opt-out to bare
  CTR and the same rejection of that flag in password mode. This completes
  the rollout of the CLI-default decision recorded under the raw-key
  authenticated entry above, which initially shipped in the Rust CLI only.
  Per-port details and breakage notes are in each port's changelog.

### Fixed

- **PBKDF2 `rounds: 0` is now rejected as invalid parameters in every port**
  (the fix first landed in Rust). Zero rounds would "derive" an all-zero key
  without error; decryption already failed authentication in that case, so
  this closes an oddity, not a vulnerability.
- **Haskell and C++ caught up to the untrusted-header hardening policy** the
  other seven implementations already followed: both were missing KDF cost
  validation entirely (a crafted header could demand gigabytes of Argon2
  memory or a multi-minute derivation) and the accepted-chunk-size cap with
  its `DORADO_MAX_CHUNK_BYTES` override (64 MiB default, 1 GiB hard ceiling,
  the knob can only tighten). Both now bound headers identically to the other
  ports, before any key derivation. Details in
  [`haskell/CHANGELOG.md`](haskell/CHANGELOG.md) and
  [`cpp/CHANGELOG.md`](cpp/CHANGELOG.md).

- CI (`.github/workflows/ci.yml`) gains soroban-style hardening: a least-privilege
  top-level `permissions: contents: read` (the RustSec audit job widens its own token to
  `issues: write`), workflow-level `concurrency` so a new push supersedes the in-flight
  run for the same ref, and a human-readable `name:` on every job. The path-filtered
  per-component structure is unchanged.
- CI: the `cpp` job gains a sanitized rerun (a second CMake build with `-DSANITIZE=ON`,
  ASan + UBSan), matching the C/Zig tier of per-port hardening. Details in
  [`cpp/CHANGELOG.md`](cpp/CHANGELOG.md).
- **New cross-repo dependency: `rime`** (`github.com/alleato-llc/rime`, a public sibling
  repo; a small house `iced` component/theming kit already used by `soroban`). Both Rust
  GUIs (`dorado-gui`, `dorado-gyotaku-gui`) are rebuilt on it, consumed as a path
  dependency (mirroring `soroban`'s own convention). Because that path dependency would
  otherwise force every job touching the main Rust workspace (notably the CLI-only
  release pipeline, across four platforms) to also check out `rime`, the three
  GUI-related crates (`dorado-gui`, the new `dorado-gui-kit`, `dorado-gyotaku-gui`) are
  excluded from the main workspace and CI's `gui` job checks `rime` out as a sibling of
  `dorado` itself, matching the pattern the screenshot workflow below also uses. Full
  per-crate details are in [`rust/CHANGELOG.md`](rust/CHANGELOG.md).
- **Release pipeline (`.github/workflows/release.yml`) now ships the two GUI apps**
  (`dorado-gui`, `gyotaku-gui`), not just the CLIs. Two new jobs, both landing on the
  same `rust-v<version>` release the CLI jobs already create: `build-gui-macos`
  produces a **signed + notarized universal** dmg per app (macOS Gatekeeper is far
  more hostile to an unsigned, double-clicked GUI app than a terminal-launched CLI
  binary, so this track diverges from the CLI's unsigned-everywhere policy on this one
  platform), needing a one-time secrets setup (`rust/docs/RELEASING.md`, new); and
  `build-gui-portable` produces bare unsigned Linux/Windows binaries, same convention
  as the CLI. Per-crate packaging/icon details are in
  [`rust/CHANGELOG.md`](rust/CHANGELOG.md).
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
