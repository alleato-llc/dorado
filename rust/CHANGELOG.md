# Changelog - Rust port

Changes to the **Rust port only** (`rust/`, the reference implementation). Cross-cutting
changes (project docs, CI, the chunk-size cap policy, the wire format) live in the
[Core CHANGELOG](../CHANGELOG.md) and [docs/spec.md](../docs/spec.md); this file records
the Rust-specific details. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
[VERSIONS.md](../VERSIONS.md) is the master table.

## [Unreleased]

### Added

- **`dorado-gui` now hardens the process at startup**, covering the one
  in-memory residual the app cannot reach any other way. Displaying decrypted
  plaintext forces iced/cosmic-text to keep their own copies of it in text and
  glyph buffers that no widget can wipe (which is why a "sensitive output"
  widget would not have helped, and was not built). Instead the GUI disables
  core dumps (`RLIMIT_CORE` = 0) so a crash cannot spill secrets to disk, and
  on Linux marks itself non-dumpable (`PR_SET_DUMPABLE` = 0), which also
  refuses `ptrace` from same-user processes; those un-wipeable toolkit copies
  then stop being reachable by anything short of code already running as the
  user. This is the measure KeePassXC and libsodium apply for the same reason.
  Done through the safe `rustix` wrapper (already in the tree via iced/winit),
  so `#![forbid(unsafe_code)]` still holds, exactly as `region` does for the
  CLI's `mlock`. Best-effort and honest about it: macOS gets only the core-dump
  limit (its `PT_DENY_ATTACH` is a private, unreliable API that fights
  notarization), and nothing here defends against root or a compromised kernel.
  Skipped under `DORADO_NO_HARDEN` (local debugging) and `DORADO_SHOT`. The
  in-memory threat model is now documented in `rust/docs/overview.md`.

- **`dorado` (CLI) now suppresses core dumps** too, so the frontends match. It
  already `mlock`'d and wiped the password, but `mlock` keeps pages out of
  swap, not out of a core dump, so a crash could still spill the password or
  derived keys into a core file. It now sets `RLIMIT_CORE` = 0 at startup, via
  the tiny safe `rlimit` crate (libc only, already in the tree through
  `region`), so `#![forbid(unsafe_code)]` still holds. Unix-only and a no-op
  elsewhere. Unlike the GUI it does not also refuse `ptrace`: the CLI is
  short-lived, and `RLIMIT_CORE` leaves debugging intact, so no opt-out is
  needed. Of the ports, TypeScript already had core-dump exclusion for free
  (its CLI delegates to libsodium's `sodium_malloc`, which bundles `mlock` +
  guard pages + `MADV_DONTDUMP`); the other `mlock`'ing ports (Go, C, Zig, C++)
  share the gap this closes for Rust.

- **`dorado-gui` gained a settings panel**, behind a gear in the header
  (rime's `settings` shell over its `icons::glyph::SETTINGS`; the app now
  loads rime's icon font, without which the glyph renders as tofu). Three
  sections: Encryption, which is where the old inline "Options" disclosure's
  controls now live; Appearance, which takes over the theme picker that used
  to sit in the main column and adds an output-panel font; and Clipboard.
  The main column is correspondingly shorter, with the theme picker and the
  options toggle both gone from it.

  Sections are an enum rather than the bare indices the rail speaks, so the
  labels and the content dispatch cannot drift apart, and an out-of-range
  index degrades to the first section instead of panicking. **Nothing is
  written to disk**: the app persists no configuration at all, so every
  choice resets on launch. That is deliberate rather than unfinished, and it
  suits a tool whose whole job is secrets: no config file means nothing left
  behind, not even evidence the app was used.

- **A clipboard-clear timer** (Clipboard section; default 30s, or Never).
  Copying arms a deadline and the countdown only subscribes while a copy is
  pending, so an idle window is not waking for nothing. Documented in the
  panel as best-effort, because it is: it bounds how long the *system*
  clipboard holds a copy and cannot recall one, anything watching the
  clipboard has already read the value, and clipboard managers keep their own
  history dorado cannot reach.

- **An output-panel font picker** (Appearance). iced 0.14 fixes the
  application-wide default font at startup, so a runtime change has to be
  handed to widgets directly; `output_panel` now takes an `Option<Font>` and
  the setting reaches the one place a monospace face genuinely helps, long
  unbroken ciphertext hex. Families resolve by name from a fixed list, so an
  absent one falls back to the default; the lookup only ever returns the
  `&'static str`s already in that list, which avoids leaking a `String` per
  change the way the obvious `Box::leak` spelling would.

- `dorado-gui`: unit tests (`src/tests.rs`) for the settings helpers that can
  silently drift: the section label/index mapping, the uniqueness and reverse
  lookup of the clipboard interval labels, and the font resolver.

- **`dorado-gui` now wipes its message and output buffers too**, not just the
  password. The message being encrypted, the recovered plaintext, the worker
  thread's copies, and the whole-file buffers on the file path are all held in
  `Zeroizing`. The typing case is the one that actually accumulated: iced's
  `text_input` is a controlled widget that hands the app a fresh `String` of
  the entire field on every keystroke, so an n-character message previously
  left n superseded copies of itself on the freed heap; moving each into
  `Zeroizing` wipes the one it replaces. `Job::run` wipes in both directions
  without branching on which side is the secret, since a wiped buffer of
  ciphertext costs nothing and is easier to review than a per-branch rule.

  Still uncovered, and documented as such in `docs/implementations.md`: the
  copies iced keeps internally (paragraph and shaping buffers), and the fact
  that these fields are not `mlock`'d, so unlike the password they can reach
  swap. Closing that needs the same from-scratch widget treatment the password
  field got.

- The screenshot harness learned `DORADO_SHOT_SETTINGS=<section>` and
  `DORADO_SHOT_FONT=<family>`. `DORADO_SHOT_OPTIONS` keeps working and now
  opens the settings panel on Encryption, where those controls moved.

- **The reverse cross-compat direction is now verified in committed tests.**
  `crates/dorado-cli/tests/fixtures/ports/` holds one password container
  encrypted by each of the eight other ports' own encrypt paths (spanning
  every KDF, MAC, and variant across the set), and a new end-to-end test in
  `tests/cli.rs` decrypts them all with the built binary and checks the
  plaintexts. Until now all cross-compat fixtures were Rust-generated, so
  only the forward direction (ports decrypting Rust's output) was tested.
- **The six raw-authenticated known-answer vectors from
  `docs/fixtures/raw-authenticated.md` are pinned in the engine's own suite**
  (`raw_authenticated_matches_cross_language_vectors`), so the reference
  implementation that generated them has a regression test against the same
  bytes the other eight ports embed.
- `dorado-wasm`: `#![forbid(unsafe_code)]`, making the no-unsafe guarantee
  hold across every crate including the WASM bindings.

### Changed

- **The GUI crates now depend on `rime` as a pinned git dependency instead of a
  relative path.** `dorado-gui`, `dorado-gui-kit`, and `dorado-gyotaku-gui`
  previously pointed at `../../../../rime/rime`, which only resolved when `rime`
  was checked out as a sibling of `dorado`, so a fresh clone could not build the
  GUIs. They now use `{ git = "https://github.com/alleato-llc/rime", rev = ... }`
  pinned to a specific commit (rime is public), so a clone builds them with no
  extra setup. The now-redundant `rime` sibling checkout is dropped from the CI,
  release, and screenshot workflows (Cargo fetches it), and the docs are updated.

- **`dorado-gui`'s password handling now matches the CLI's: wiped *and*
  locked.** The field is rime's new `secure_input`, and the app state holds
  its `SecretHandle` in place of the `Zeroizing<String>` this entry
  previously described. The buffer is fixed-capacity (never reallocated, so
  no `realloc` leaves a stale copy behind), `mlock`'d out of swap
  best-effort, and zeroized on drop; because `mlock` acts on whole pages, it
  sits in a page-aligned window that no other allocation shares. The widget
  edits it in place and emits only unit messages, so the password no longer
  enters iced's message queue, widget tree, or text shaper, which is what
  the previous `Zeroizing<String>` approach could not cover. A job copies
  the bytes out under the handle's lock into its own `Zeroizing` buffer for
  the engine call. `shot.rs` seeds the handle directly and wipes the
  intermediate `String`.

  Residual risks, documented rather than papered over: the OS keyboard/IME
  path and the compositor see keystrokes first, winit's event struct briefly
  holds each typed character, a paste source keeps its own copy in the
  system clipboard, and hibernation writes locked pages to disk regardless.
  Deliberate omissions: no copy-out, no selection, no reveal toggle.
  `docs/implementations.md` is updated to match. `gyotaku-gui` is unchanged;
  it is an unkeyed hash tool and handles no secrets.

### Fixed

- **The Windows `dorado-gui` build was broken by the process-hardening
  addition.** `harden.rs` referenced `rustix::process` unconditionally, but
  rustix gates that whole module behind `cfg(not(windows))`, so the Windows GUI
  failed to compile (`E0433`) and no Windows GUI binary shipped in the
  `rust-v0.2.x` releases cut while it was broken. The `rustix` usage and its
  dependency entry are now `cfg(unix)`-gated; on Windows `apply()` is a no-op
  (no `RLIMIT_CORE` to set), matching how the CLI already gated its `rlimit`
  dependency. Verified with `cargo check --target x86_64-pc-windows-gnu`. The
  core-dump suppression on Unix and macOS is unchanged.

- `dorado-gui-kit`: the output panel's ciphertext hex ran off the right edge
  instead of wrapping. Hex is one unbroken token and iced wraps on words by
  default, so the text now uses `Wrapping::WordOrGlyph`, which breaks the
  hex mid-token while still wrapping decrypted plaintext on word
  boundaries. Wrapped lines also gained a trailing gutter so they clear the
  overlaid scrollbar rather than running underneath it.

- **The output panel copied the decrypted plaintext on every redraw.** iced's
  text takes a `Cow`, and `text(body.to_string())` hands it an owned `String`,
  so each frame allocated a fresh unwiped copy of whatever the panel was
  showing. In decrypt mode that is the recovered plaintext, and no amount of
  wiping on the app's side could catch those: they were allocated and dropped
  inside `view`. The panel now borrows (`Cow::Borrowed`, no allocation), as
  does the status row. Found while scoping a `sensitive_output` widget, which
  is what that widget's real value would have been.

- **The result area no longer pops into existence when a job finishes.** Both
  GUIs only rendered the output panel once there was output, and the status
  row collapsed to nothing while empty, so finishing a job inserted a "Done"
  line *and* a whole panel at once and shoved the layout down at the moment
  the user was reading it. `output_panel` now takes a `placeholder` and is
  rendered unconditionally: an empty body draws the same frame with muted
  placeholder text and an inert Copy button (`on_press_maybe`), so the panel
  is a fixed part of the window. `progress_status_row` is likewise a constant
  height in every state, holding the bar's slot open when idle and reserving
  the caption's line when the status is empty. Idle and finished layouts are
  now identical except for their contents.

- `dorado-gui`: the KDF-cost and chunk-size sliders rendered as bare labels
  with no track once they moved into the settings panel. rime's `slider` puts
  its label in a fixed 170px gutter and its readout in another 48px, which
  fits the main column but leaves nothing for the track in the panel's
  narrower content pane. They now stack the label above the slider, using the
  empty-label form rime documents for exactly this case.

## [0.2.1] - 2026-07-19

### Fixed

- **A flaky `gyotaku` CLI test race.** `tests/cli.rs`'s stdin helper
  `unwrap`ped its write to the child, but a child that rejects its arguments
  (the bad `--bits` case) can exit before reading stdin, so the write
  intermittently died with `BrokenPipe` and failed the suite (first seen on
  a CI runner; timing-dependent, so usually green locally). The helper now
  accepts `BrokenPipe` specifically, since an early exit is exactly what
  that test asserts. Test-only; the binaries are unchanged.

## [0.2.0] - 2026-07-19

### Added

- **`dorado-engine`'s `kdf` module is now public, with both standard forms
  of key derivation.** `kdf::derive_from_password` (the former private
  `derive`: Argon2id, scrypt, PBKDF2-HMAC-SHA256 behind one call, plus
  `kdf::validate` bounding untrusted cost parameters) stretches a weak
  secret, deliberately slowly. The new `kdf::derive_from_key` is the fast,
  key-based form (one domain-separated Skein-512 keyed hash, its own
  `DRDOkdrv` domain prefix): it fans an already high-entropy key out into
  independent per-purpose children, the same discipline `split_raw_key`
  applies internally. The parallel names are deliberate guardrails: a
  password must never take the fast path, a key never needs the slow one.
  Both were private implementation details of the password container;
  embedders of the raw-key modes need exactly these two steps with their own
  parameter storage (stretch or fetch a master once per session, fan it out,
  encrypt many files), so re-implementing them outside the crate was pure
  duplication. API surface only: the container wire format, the CLI, and the
  other ports are unchanged. First consumer: tty's encrypted command
  history. `KdfParams`/`PrfId` remain re-exported at the crate root.
- **`kdf::derive_from_key_with` — a selectable fan-out PRF.** The new
  `kdf::KdfPrf { Skein512, Blake3 }` lets a caller fan a master key out with
  BLAKE3's keyed hash instead of the default Skein-512, so a ChaCha-family
  construction can stay single-family top to bottom (both are secure PRFs and
  yield equally strong children; the choice is about matching the surrounding
  cipher, not security). `derive_from_key` is unchanged and now delegates to
  `derive_from_key_with(KdfPrf::Skein512, ..)`, byte-for-byte identical. The
  BLAKE3 variant requires a 32-byte key. API surface only; the container,
  CLI, and wire format are untouched. Consumer: tty's per-cipher history
  key hierarchy.
- **Raw-key mode gains an authenticated construction**
  (`dorado-engine::{encrypt,decrypt}_raw_authenticated_stream` / `*_bytes`),
  encrypt-then-MAC over the caller-supplied key with no password or KDF,
  reusing the password container's chunk/frame machinery. See the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale and
  [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for the byte-level
  construction (key-splitting via domain-separated Skein-512, the frame AAD).
  Bare `raw_ctr_stream` is unchanged and still exists, reachable via the CLI's
  `--unauthenticated` (see Changed, below) or directly as a library call.
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

### Fixed

- **`kdf::validate` now rejects `rounds: 0` for PBKDF2.** Zero rounds would
  "derive" an all-zero key without error; a crafted or corrupted header
  carrying it now fails cleanly at validation instead. (Decryption already
  failed authentication in that case, so this closes an oddity, not a
  vulnerability.)

## [0.1.5] - 2026-07-19

### Added

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

## [0.1.4] - 2026-07-07

No Rust-side changes to record (a C++-port-focused merge); version cut by
the auto-release track.

## [0.1.3] - 2026-07-07

### Changed

- **Release packaging: no more archives.** `rust/salpa.yaml` now drives only the shared
  `test`/`version` stages; `build`/`publish` instead run against two new configs,
  `rust/salpa-dorado.yaml` and `rust/salpa-gyotaku.yaml` (one `bin:` each, no
  `package:`), so each CLI ships as its own bare per-platform binary
  (`dorado-<os>-<arch>[.exe]`, `gyotaku-<os>-<arch>[.exe]`) instead of both being
  bundled with `LICENSE` into one `tar.gz`/`zip`. `LICENSE` is now attached to the
  release once (workflow-level) instead of duplicated inside every platform archive.
  Matches soroban's convention for its portable (non-macOS) binaries. See the Core
  changelog for the workflow-level change.

## [0.1.2] - 2026-07-07

No Rust-side changes to record (a release-workflow fix); version cut by the
auto-release track.

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
