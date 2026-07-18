# Changelog - Rust port

Changes to the **Rust port only** (`rust/`, the reference implementation). Cross-cutting
changes (project docs, CI, the chunk-size cap policy, the wire format) live in the
[Core CHANGELOG](../CHANGELOG.md) and [docs/spec.md](../docs/spec.md); this file records
the Rust-specific details. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
[VERSIONS.md](../VERSIONS.md) is the master table.

## [Unreleased]

### Changed

- **Raw-key mode (`--key`/`--key-file`) is now authenticated by default in the
  CLI.** Previously `dorado encrypt --key ... --iv ...` produced bare,
  unauthenticated CTR ciphertext (output length exactly equal to input
  length); it now produces encrypt-then-MAC output (larger than the input, by
  a per-chunk tag and framing overhead) unless you pass the new
  `--unauthenticated` flag to opt back into the old bare behavior. **This
  breaks any existing script or pipeline** that assumed raw-key mode's old
  output shape or that fed a bare-CTR file from an older build into a newer
  `decrypt` (or vice versa) without also adding `--unauthenticated` on both
  ends. The change is deliberate: bare CTR silently decrypts a corrupted or
  tampered byte to a flipped plaintext byte with no error, and a user who
  doesn't already know that distinction exists has no way to discover it
  before it matters. See the [Core CHANGELOG](../CHANGELOG.md) for the
  precedent this follows (libsodium, age — authenticated as the default,
  reach-for API; openssl's `enc -ctr`-style bare-by-default is the
  discouraged counterexample) and `--unauthenticated`'s own `--help` text for
  why the opt-out still exists.

### Added

- **Raw-key mode gains an authenticated construction**
  (`dorado-engine::{encrypt,decrypt}_raw_authenticated_stream` / `*_bytes`),
  encrypt-then-MAC over the caller-supplied key with no password or KDF,
  reusing the password container's chunk/frame machinery. See the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale and
  [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for the byte-level
  construction (key-splitting via domain-separated Skein-512, the frame AAD).
  Bare `raw_ctr_stream` is unchanged and still exists, reachable via the CLI's
  `--unauthenticated` (see Changed, above) or directly as a library call.
- **`dorado-gui` and `dorado-gyotaku-gui` now ship real release artifacts.**
  Each gets its own `salpa.yaml` (in its own crate directory, since both are
  excluded from the main workspace over their `rime` path dependency) driving
  `.github/workflows/release.yml`'s two new jobs: `build-gui-macos` produces a
  **signed + notarized universal** `Dorado-<version>.dmg` /
  `Gyotaku-<version>.dmg` (both Apple Silicon and Intel in one dmg), while
  `build-gui-portable` produces bare, unsigned Linux/Windows binaries, matching
  the CLI's own unsigned binaries there. macOS signing needs a one-time
  secrets setup — see `rust/docs/RELEASING.md` (new). Each app gets its own
  icon: a stylized dorado (mahi-mahi) fish for `dorado-gui`, a gyotaku-style
  fish-print/stamp motif (with a 魚 hanko seal) for `dorado-gyotaku-gui` — a
  source SVG plus a generated `packaging/AppIcon.icns` (the macOS `.app`
  bundle icon) in each crate directory, and a 256×256 PNG at
  `src/assets/icon.png` (each crate's iced window/taskbar icon on Linux and
  Windows; macOS takes its Dock icon from the `.app` bundle instead).
- `dorado-gui` and `dorado-gyotaku-gui` each gain a permanent, env-gated
  review-screenshot harness (`src/shot.rs`), ported from soroban's own
  (`soroban/rust/gui/src/shot.rs`): inert unless `DORADO_SHOT` /
  `GYOTAKU_SHOT` is set, in which case it seeds the app's state from
  `DORADO_SHOT_*` / `GYOTAKU_SHOT_*` env vars (direction, source, options,
  theme, KDF, variant, MAC, password/text for `dorado-gui`; source, bits,
  theme, text, expected digest for `dorado-gyotaku-gui`), waits three painted
  frames, captures the window via iced's wgpu-readback `window::screenshot`
  (no macOS screen-recording prompt, works headlessly), PNG-encodes it via the
  `png` crate, and exits. `dorado-gui`'s harness runs the real encrypt/decrypt
  synchronously (text source, non-empty password) so the shot shows genuinely
  computed output/status instead of a blank pre-run state; `dorado-gyotaku-gui`'s
  always runs the real (cheap, KDF-free) hash for a text source. Added `png =
  "0.17"` to `dorado-gyotaku-gui`'s `Cargo.toml` (already present in
  `dorado-gui`'s from the iced 0.14 migration). Feeds a later automated
  screenshot gallery.

- New crate `dorado-gui-kit`: composite, dorado-flavored widgets (a segmented
  control, a labeled dropdown, a theme picker, a password field, a file-path
  field with a browse slot, a progress/status row, an output+copy panel) built
  on top of `rime`, the house iced component kit (sibling repo
  `alleato-llc/rime`). Shared by both `dorado-gui` and `dorado-gyotaku-gui`.

### Changed

- **Both GUIs (`dorado-gui`, `dorado-gyotaku-gui`) migrated from raw iced 0.12 to
  iced 0.14 + `rime`.** Same behavior in each (`dorado-gui`: direction/source
  toggles, password field, text/file inputs, the collapsible KDF/variant/MAC/
  chunk/tweak options panel; `dorado-gyotaku-gui`: source toggle, output-length
  toggle, text/expected-digest fields; both: the worker-thread job execution and
  the busy/progress/status/output/copy flow), rebuilt on `rime` widgets and
  `dorado-gui-kit` composites instead of each crate's hand-rolled, near-identical
  Darcula-only `style.rs` `StyleSheet` theme (both deleted). Both gain a theme
  picker (any of rime's built-in named palettes, default Dracula) and native file
  dialogs via `rfd` (`dorado-gui`: Open + Save, for its input/output path fields;
  `dorado-gyotaku-gui`: Open only, since it only ever reads a file), replacing
  bare text entry for paths. `iced`'s `application`/`Task` builder API replaces
  the old `Application` trait/`Command` in both. All three GUI-related crates
  (`dorado-gui`, `dorado-gui-kit`, `dorado-gyotaku-gui`) are excluded from the
  main workspace (see `rust/Cargo.toml`) and each resolves its own `Cargo.lock`:
  their path dependency on the sibling `rime` repo would otherwise force every
  job touching the main workspace (notably the CLI-only release pipeline, which
  builds `dorado`/`gyotaku` across four platforms) to also check out `rime`,
  for crates those jobs never build. `png` was added to `dorado-gui` in this
  migration (unused at the time); it is now used by both GUIs' screenshot
  harness (see Added, above).

- **Release packaging: no more archives.** `rust/salpa.yaml` now drives only the shared
  `test`/`version` stages; `build`/`publish` instead run against two new configs,
  `rust/salpa-dorado.yaml` and `rust/salpa-gyotaku.yaml` (one `bin:` each, no
  `package:`), so each CLI ships as its own bare per-platform binary
  (`dorado-<os>-<arch>[.exe]`, `gyotaku-<os>-<arch>[.exe]`) instead of both being
  bundled with `LICENSE` into one `tar.gz`/`zip`. `LICENSE` is now attached to the
  release once (workflow-level) instead of duplicated inside every platform archive.
  Matches soroban's convention for its portable (non-macOS) binaries. See the Core
  changelog for the workflow-level change.

## [0.1.1] - 2026-07-07

The first cut of the salpa-driven auto-release track (bootstrapped from the
`rust-v0.1.0` tag). Everything below had already landed on `main`; this heading just
dates it for the release, per [VERSIONS.md](../VERSIONS.md)'s policy.

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
