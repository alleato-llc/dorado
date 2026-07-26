# CLAUDE.md

This is the Rust workspace of the dorado monorepo. It lives in `rust/`; a separate
Astro marketing landing page lives alongside it in `web/` (see `../web/CLAUDE.md`),
and CI for both is at the repo root in `../.github/workflows/ci.yml`. Everything
below concerns the Rust workspace.

## What this is

Dorado is a Cargo workspace of seven crates:

- `crates/dorado` — the primitives library, zero runtime dependencies. The core is
  a from-scratch Threefish (256/512/1024) following Skein 1.3, plus CTR mode.
  Alongside it, each verified against official vectors or differentially against an
  audited crate, are: Skein-512 (`src/skein.rs`, UBI over Threefish-512) and BLAKE3
  (`src/blake3.rs`).
- `crates/dorado-engine` — the construction over the cipher: the three KDFs, the
  authenticated chunked password container, raw CTR (bare and, as of the
  raw-authenticated construction, encrypt-then-MAC), and the MAC menu. Depends on
  `dorado`.
- `crates/dorado-cli` — clap frontend; produces the `dorado` binary.
- `crates/dorado-gui` — iced frontend; produces `dorado-gui`. Built on `rime` (a
  sibling repo, `alleato-llc/rime`; a small `iced` component/theming kit consumed
  as a pinned git dependency) plus `dorado-gui-kit`'s composites over it. A theme picker
  offers any of rime's built-in named palettes (default Dracula); native Open/Save
  file dialogs (`rfd`) fill the input/output path fields. `src/shot.rs` is a
  permanent, env-gated (`DORADO_SHOT`) review-screenshot harness (ported from
  soroban), inert unless set. `packaging/AppIcon.icns` (+ source `icon.svg`) is
  the macOS `.app` bundle icon, `src/assets/icon.png` the Linux/Windows window
  icon; `salpa.yaml` drives its own signed macOS release leg (see
  `rust/docs/RELEASING.md`).
- `crates/dorado-gui-kit` — composite, dorado-flavored widgets (a segmented
  control, a labeled dropdown, a theme picker, a password field, a file-path field
  with a browse slot, a progress/status row, an output+copy panel) built on top of
  `rime`. Internal; shared by `dorado-gui` and `dorado-gyotaku-gui` so neither
  re-derives its own copy. Depends on `rime` + `iced`.
- `crates/dorado-gyotaku` — clap frontend; produces the standalone `gyotaku`
  hashing binary (Skein-512, like `sha256sum`; named for the Japanese fish-print
  art, a file's fingerprint). Depends only on `dorado` + `clap`, kept separate so
  a hash tool does not pull in the KDF/engine stack.
- `crates/dorado-gyotaku-gui` — iced frontend; produces `gyotaku-gui`, the hashing
  tool in a window (a sibling of `dorado-gui`, sharing its look via `rime` +
  `dorado-gui-kit`, including the same theme picker). Hashes text or streams a
  file with the same `dorado::skein` code the CLI uses, on a worker thread, at a
  selectable output length; a native Open dialog (`rfd`) fills the input-file
  field. Depends on `dorado` + `iced` + `rime` + `dorado-gui-kit`. `src/shot.rs`
  is a permanent, env-gated (`GYOTAKU_SHOT`) review-screenshot harness (a sibling
  of `dorado-gui`'s own), inert unless set. `packaging/AppIcon.icns` (+ source
  `icon.svg`) is the macOS `.app` bundle icon, `src/assets/icon.png` the
  Linux/Windows window icon; `salpa.yaml` drives its own signed macOS release
  leg (see `rust/docs/RELEASING.md`).

Educational and unaudited. The cipher provides confidentiality only; the engine
adds authentication (encrypt-then-MAC) for password files, and by default for
raw-key mode too (`--unauthenticated` opts out; see below).

Threefish is the project's reason to exist; dorado stays Threefish-based. Skein is
a construction on Threefish, so it is built and surfaced (as the default MAC and as
the `gyotaku` CLI). ChaCha20-Poly1305 is an integrated cipher-plus-MAC that would
*replace* Threefish, so it is not part of dorado; the from-scratch ChaCha20,
Poly1305, and ChaCha20-Poly1305 that once lived here were extracted into their own
project, `foxtrot` (a sibling repo). Do not reintroduce ChaCha into the container
or rearchitect for it without an explicit request.

## Architecture

Three docs back this up. `docs/overview.md` (Rust-local) is the accessible,
conceptual tour with diagrams (layers, flows, threat model). The other two are
project-wide, since all the ports share the format, so they live at the
repo root: `../docs/spec.md` is the precise byte-level wire format and cipher
constants and the only place the on-disk format is documented (keep it in sync when
the format changes, and bump `format::VERSION`), and `../docs/glossary.md` defines
the terminology.


There is a single generic ARX engine (`encrypt` / `decrypt` in `src/lib.rs`) that
operates on the cipher state as a `&mut [u64]` of length Nw. The three public
variants, `Threefish256`, `Threefish512`, and `Threefish1024`, are written out
explicitly as thin typed wrappers around that engine; they differ only in their
state width, block size, rotation table, permutation table, and round count. The
cipher logic lives once in the generic functions, so the wrappers just convert
bytes to and from words and call in.

The per-variant rotation constants (`ROT_256` / `ROT_512` / `ROT_1024`),
permutation tables (`PERM_*`), and the key-schedule constant `C240` are taken from
the Skein 1.3 specification. The key schedule extends the key with a parity word
(C240 xored with all key words) and the tweak with `t0 ^ t1`; subkeys are injected
every four rounds. All conversion between bytes and `u64` words happens at the API
boundary and is little-endian.

CTR mode is the `ctr_apply` method on each variant: it encrypts successive counter
blocks (the IV as a big-endian counter, incremented by `ctr_increment`) and xors
the keystream into the data. The counter is public, so the carry branch in
`ctr_increment` is not secret-dependent.

The `dorado-engine` crate is the shared construction; both frontends are thin
clients of it (`use dorado_engine as engine`). Its `lib.rs` is the engine API; it
uses three modules: `kdf.rs` (both standard forms of key derivation:
`derive_from_password`, the slow password stretch behind Argon2id, scrypt, and
PBKDF2-HMAC-SHA256 plus a `validate` that bounds untrusted cost params, and
`derive_from_key`, the fast domain-separated Skein-512 fan-out of an
already-strong key into per-purpose children, with `derive_from_key_with`
taking a `KdfPrf` (`Skein512`/`Blake3`) to fan out under either PRF so a
ChaCha-family construction can stay single-family; public, so embedders of the
raw-key modes can reuse both steps with their own parameter storage instead of
re-implementing them. First external consumer: tty's encrypted command
history),
`format.rs` (the container header and streaming reader; magic `DRDO`, version,
variant, KDF id and params, MAC id, chunk size, salt, tweak, IV), and `mac.rs`
(encrypt-then-MAC, dispatching the `MacId` to one of three from-scratch keyed
hashes: Skein-512 by default, HMAC-SHA256, or BLAKE3 keyed; all yield 32-byte tags
verified with a constant-time compare). It re-exports `Variant`, `KdfParams`,
`PrfId`, and `MacId` for the frontends, plus its typed error: `Error` (an enum of
`AuthFailed`, `MalformedHeader`, `UnsupportedVersion`, `InvalidParams`, `Io`) and a
`Result<T>` alias. Callers match on the kind; wrong password and tampering both map to
`AuthFailed` and must stay indistinguishable. `Error` implements `Display` and
`From<Error> for String`, so the string-based frontends absorb it with `?`. Because it
is a real library crate, there is no dead-code hack: a different subset of its public
API is used by each frontend, and that is fine. It exposes streaming functions over `Read`/`Write` (the CLI, for
constant-memory files), in-memory `*_bytes` wrappers (the GUI), a single-block
`block_transform` (exercised by tests), and `inspect`/`inspect_bytes`, which read
only a container's header and return a `ContainerInfo` of its non-secret parameters
(behind the CLI's `dorado inspect`, which needs no password). `FORMAT_VERSION` is
re-exported for display. Keep new shared logic in `dorado-engine`.

The engine has two key paths, both streamable in constant memory. Raw key: no
header, no self-describing format; the caller supplies variant, key, tweak, and IV
directly and must remember them for decryption. Password: the KDF output is
split into a separate encryption key and MAC key, then the data is processed in
fixed-size chunks (`--chunk-kib`, default 64 KiB, stored in the header). Each chunk
is CTR-encrypted on a continuous counter and carries a MAC tag (the selected MAC)
over `domain || index || is_last || ciphertext`, with the header bound into chunk 0's tag
(`frame_aad` in `engine`). Decryption verifies each
chunk before decrypting it, so tampering, wrong passwords, reordering, dropping,
and truncation (an authenticated final-chunk flag that must be seen before EOF)
are all rejected. Streaming means verified plaintext can be emitted before a later
chunk fails, so a non-zero exit means the output is incomplete and untrusted.
Changing the container format is a version bump (`format::VERSION`, currently 4).

Raw key itself has two modes, selected by `--unauthenticated` in the CLI
(default off — raw-key mode is authenticated by default, matching the
password path; this is a deliberate secure-by-default choice, since a casual
user typing `--key`/`--iv` is unlikely to know to ask for authentication, and
the tools that treat security as a primary goal, e.g. libsodium and age, make
the authenticated construction the default reach-for API rather than the bare
primitive). Bare (`raw_ctr_stream`) is unauthenticated CTR with a running
counter: confidentiality only, and a corrupted or tampered byte decrypts to a
flipped plaintext byte silently, with no error, since CTR has no way to
detect it — reached only via the explicit `--unauthenticated` opt-out, kept
available for cross-language interop, composability (a caller layering its
own framing/authentication at a different protocol layer), and this project's
educational purpose. Authenticated
(`encrypt_raw_authenticated_stream` / `decrypt_raw_authenticated_stream`) adds
encrypt-then-MAC on top, reusing the password container's chunk/frame machinery
(`frame_aad`-shaped AAD, `write_frame`/`read_frame`) without a password or KDF:
the caller's key is split into an independent encryption subkey and MAC subkey
via domain-separated Skein-512 keyed hashing (`split_raw_key`; the caller's key
is assumed already high-entropy, so no cost-parameterized stretching is applied,
only subkey separation), and since there is no header to bind into chunk 0's tag,
the tweak and IV are bound directly into the frame AAD instead (`raw_frame_aad`,
domain `DRDOrwFr`, distinct from the password path's `DRDOchnk` so the two can
never collide). The byte-level construction is documented in `../docs/spec.md`
under "Raw-key modes". This construction stays within the Skein/Threefish family
(same reasoning as the MAC default above), so it does not touch the
ChaCha20-Poly1305 boundary described above.

Two standalone env knobs override in-code defaults (everything works with no env set).
`DORADO_RNG` picks the CSPRNG that `fill_random` draws the salt and IV from: `os`
(default, `OsRng`) or `thread` (`rand::thread_rng`); both are CSPRNGs and an unknown
value is an error, so the knob cannot select a weak source. `DORADO_MAX_CHUNK_BYTES`
overrides the accepted chunk-size cap, clamped into `(0, MAX_CHUNK_BYTES]` (1 GiB hard
ceiling) so it can only tighten; the default when unset is `DEFAULT_MAX_CHUNK_BYTES`
(64 MiB), well above the 64 KiB normal chunk size. Both are resolved by pure helpers
(`rng_kind`, `chunk_cap_from`) that are unit-tested without touching env state. The
decrypt path bounds allocation by `max_chunk_bytes()` before deriving any key.

The header carries an optional non-secret `label` (version 4; v3 files are still
read). It is authenticated for free because the whole header is bound into chunk
0's tag, and `to_bytes` keys off `Header::version` so a v3 header reserializes
byte-for-byte. `decrypt_password_stream_expecting` (and the `_bytes` variant) take
an optional expected label and reject a mismatch before emitting plaintext; the
plain `decrypt_password_*` functions pass `None`. This binds a file to a context
without closing the whole substitution gap (an attacker still cannot forge a label,
since it is authenticated).

Note the scrypt quirk in `kdf.rs`: scrypt's `Params::new` caps its `len` field at
64, but that field only feeds its PHC API; pass a placeholder and let the real
length come from the output slice, or the 1024 variant (160 key bytes) fails.

Secrets in the CLI (the password, the KDF output, derived keys) are held in
`zeroize::Zeroizing` buffers and wiped on drop. The CLI additionally `mlock`s the
password buffer into RAM (out of swap) for its lifetime via the `region` crate
(`LockedPassword` in `main.rs`); `region`'s API is safe, so the CLI keeps
`#![forbid(unsafe_code)]`, and the lock is best-effort (the bytes are still wiped if
the OS refuses the lock). The library also wipes the cipher's expanded key schedule:
with the default `zeroize` feature, each `Threefish*` has a `Drop` that zeroes its
`ek`/`et` arrays (see `zeroize_impls` in `lib.rs`). `--no-default-features` drops the
`zeroize` dependency for the bare, dependency-free core.

The cipher crate is `no_std` via `#![cfg_attr(not(test), no_std)]`, and supports
all three environment levels through the `alloc` feature (default on):

- std (default, on an OS) and no_std + alloc (no OS, has an allocator) are the same
  build; the std binaries link the no_std crate fine.
- no_std without an allocator (`--no-default-features`) is the bare core:
  `extern crate alloc` is itself `#[cfg(feature = "alloc")]`, so the allocator is
  not linked and any stray allocation is a compile error. CI builds this for a
  bare-metal target.

To make that work, the hashers are incremental and allocation-free. Each exposes a
fixed-size streaming type (`skein::Skein512`, `blake3::Hasher`)
with `new`/`update`/`finalize`, plus one-shot `*_into` functions that write into a
caller buffer; the `Vec`-returning `hash` is a thin `#[cfg(feature = "alloc")]`
wrapper over them. Because the hashers stream, an input larger than RAM can be
hashed (the `gyotaku` CLI does this, reading files in fixed buffers). Threefish and
CTR are allocation-free throughout. It is `std` under `cargo test` so the
differential harness is unaffected.

The incremental hashers share the hold-back-the-final-block pattern: `update`
processes only blocks it knows are not last, and `finalize` handles the final
(often partial) block. Skein's output length is fixed at `new` (it is folded into
the config block that seeds the chaining value); BLAKE3 is a free XOF so its length
is chosen at `finalize`. BLAKE3 streaming uses the chunk-stack algorithm (a
fixed-size CV stack, merged on the chunk counter's trailing zeros), which builds the
same tree as the recursive whole-input form; the differential test spans many chunk
counts to guard it.

## Hard invariants

These must never be violated:

- The whole suite must stay green: the cipher's known-answer/CTR/differential
  tests and the engine's construction and streaming-security tests.
- Do not modify the rotation tables, the permutation tables, `C240`, the round
  counts, or the MIX and key-schedule arithmetic. These values are verified
  against official test vectors. If you ever change one, you must re-run the full
  suite and confirm it still matches the reference before trusting the result. A
  "simplification" here silently breaks the cipher.
- All word arithmetic uses wrapping operations (`wrapping_add`, `wrapping_sub`).
- Preserve the constant-time discipline: no secret-dependent branching and no
  secret-dependent indexing.

## How to verify

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo bench -p dorado --no-run                       # benchmarks still compile
cargo build -p dorado --target thumbv7em-none-eabi   # no_std core builds bare-metal
cargo build -p dorado --no-default-features          # dependency-free core builds
```

The cipher crate has the known-answer and CTR tests plus the differential harness
(`crates/dorado/tests/diff.rs`, vs the RustCrypto `threefish` crate over random
inputs). The other primitives are verified the same way: Skein-512 and BLAKE3
differentially against the RustCrypto `skein` and `blake3` crates over random
inputs (all in `crates/dorado/src/<module>.rs` test modules). The engine crate has
the KDF/header/MAC tests and the construction tests: password round-trip,
wrong-password, tampering, multi-chunk, every-MAC round-trip-and-reject, and the
streaming security properties (truncation, header tampering, early-chunk
tampering), plus the KDF-cost `validate` bounds. The raw-authenticated
construction has the same shape of coverage under its own `raw_authenticated_*`
tests: round-trip, wrong-key, tampering, every MAC, every variant, multi-chunk,
truncation, early-chunk tampering, and mismatched-tweak-or-IV rejection (since
those are bound into the AAD instead of a header there).

Unit tests live in their own files, not inline: cipher tests in
`crates/dorado/src/tests.rs`, engine tests in `crates/dorado-engine/src/tests.rs`,
and each engine module's tests beside it (`kdf/tests.rs`, `format/tests.rs`,
`mac/tests.rs`). Each source file declares them with `#[cfg(test)] mod tests;`. The
two CLIs additionally have end-to-end tests in their own `tests/cli.rs` that drive
the built binary (raw-key and password round-trips, `inspect`, and gyotaku's
`--tag`/`-c`).

The two library crates set `#![warn(missing_docs)]`, so every public item is
documented; because CI runs clippy with `-D warnings`, an undocumented public item
fails the build. Public API examples are doctests, run by `cargo test`.

Audit-readiness: every crate sets `#![forbid(unsafe_code)]`. CI lives at the repo
root (`../.github/workflows/ci.yml`) and runs its Rust jobs from this `rust/`
directory: fmt/clippy/test, a bench compile-check, a bare-metal `no_std` build, and
`cargo audit`. A fuzz target
(`fuzz/fuzz_targets/decrypt.rs`, run with `cargo +nightly fuzz run decrypt`) feeds
arbitrary bytes to `decrypt_password_bytes`; it must never panic or over-allocate,
which is what the chunk-size and KDF-cost bounds guarantee.

## Roadmap

Candidate future work, not commitments:

- (No specific items queued. Past candidates are recorded below.)

Done (was roadmap): RustCrypto trait impls behind optional features in
`src/rustcrypto.rs` — `cipher` (block-cipher traits for the three Threefish
variants) and `digest` (BLAKE3 as a 32-byte `Digest` on `blake3::Hasher`, and
Skein fixed-output wrappers `Skein512_256`/`Skein512_512`); `no_std` for the
cipher crate at all three levels
(`#![cfg_attr(not(test), no_std)]` plus the `alloc` feature; bare-metal CI for the
allocator and no-allocator builds); incremental, allocation-free hashers
(`Skein512`, `blake3::Hasher`) with one-shot `*_into` wrappers, so
inputs larger than RAM can be hashed (the `gyotaku` CLI streams files); library
key-schedule zeroization (default `zeroize`
feature); criterion throughput benchmarks (`benches/throughput.rs`); format v4
label binding.

Done (was roadmap): Skein's UBI chaining mode is built on the block cipher
(`src/skein.rs`); Skein-512 is now the default container MAC and is also exposed as
the standalone `gyotaku` CLI.

## Conventions

- No em dashes anywhere.
- No fabricated metrics, benchmarks, or statistics. If a number cannot be measured
  or verified, leave it out.
- Direct prose, minimal formatting, no marketing tone.
- Keep changes scoped to what is asked. Do not refactor the cipher, add features,
  or restructure the project.
- Do not add dependencies without asking first.
- Be honest about limitations rather than papering over them.
