# CLAUDE.md

This is the Rust workspace of the dorado monorepo. It lives in `rust/`; a separate
Astro marketing landing page lives alongside it in `web/` (see `../web/CLAUDE.md`),
and CI for both is at the repo root in `../.github/workflows/ci.yml`. Everything
below concerns the Rust workspace.

## What this is

Dorado is a Cargo workspace of five crates:

- `crates/dorado` — the primitives library, zero runtime dependencies. The core is
  a from-scratch Threefish (256/512/1024) following Skein 1.3, plus CTR mode.
  Alongside it, each verified against official vectors or differentially against an
  audited crate, are: Skein-512 (`src/skein.rs`, UBI over Threefish-512), BLAKE3
  (`src/blake3.rs`), and ChaCha20 / Poly1305 / ChaCha20-Poly1305 (`src/chacha.rs`,
  `src/poly1305.rs`, `src/chacha20poly1305.rs`). The ChaCha primitives are
  deliberately not wired into the tool (see below); they exist as verified library
  code only.
- `crates/dorado-engine` — the construction over the cipher: the three KDFs, the
  authenticated chunked password container, raw CTR, and the MAC menu. Depends on
  `dorado`.
- `crates/dorado-cli` — clap frontend; produces the `dorado` binary.
- `crates/dorado-gui` — iced frontend; produces `dorado-gui`.
- `crates/dorado-gyotaku` — clap frontend; produces the standalone `gyotaku`
  hashing binary (Skein-512, like `sha256sum`; named for the Japanese fish-print
  art, a file's fingerprint). Depends only on `dorado` + `clap`, kept separate so
  a hash tool does not pull in the KDF/engine stack.

Educational and unaudited. The cipher provides confidentiality only; the engine
adds authentication (encrypt-then-MAC) for password files.

Threefish is the project's reason to exist; dorado stays Threefish-based. Skein is
a construction on Threefish, so it is built and surfaced (as the default MAC and as
the `gyotaku` CLI). ChaCha20-Poly1305 is an integrated cipher-plus-MAC that would
*replace* Threefish, so it is kept as a standalone verified primitive and is not
part of the tool. Do not wire ChaCha into the container or rearchitect for it
without an explicit request.

## Architecture

Two design docs back this up: `docs/overview.md` is the accessible, conceptual tour
with diagrams (layers, flows, threat model), and `docs/spec.md` is the precise
byte-level wire format and cipher constants. The on-disk format is documented only
in `spec.md`; keep it in sync when the format changes (and bump `format::VERSION`).
`docs/glossary.md` defines the terminology.


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
uses three private modules: `kdf.rs` (Argon2id, scrypt, PBKDF2-HMAC-SHA256 behind
one `derive` call, plus a `validate` that bounds untrusted cost params),
`format.rs` (the container header and streaming reader; magic `DRDO`, version,
variant, KDF id and params, MAC id, chunk size, salt, tweak, IV), and `mac.rs`
(encrypt-then-MAC, dispatching the `MacId` to one of three from-scratch keyed
hashes: Skein-512 by default, HMAC-SHA256, or BLAKE3 keyed; all yield 32-byte tags
verified with a constant-time compare). It re-exports `Variant`, `KdfParams`,
`PrfId`, and `MacId` for the frontends. Because it is a real library crate, there is no
dead-code hack: a different subset of its public API is used by each frontend, and
that is fine. It exposes streaming functions over `Read`/`Write` (the CLI, for
constant-memory files), in-memory `*_bytes` wrappers (the GUI), a single-block
`block_transform` (exercised by tests), and `inspect`/`inspect_bytes`, which read
only a container's header and return a `ContainerInfo` of its non-secret parameters
(behind the CLI's `dorado inspect`, which needs no password). `FORMAT_VERSION` is
re-exported for display. Keep new shared logic in `dorado-engine`.

The engine has two key paths, both streamable in constant memory. Raw key: bare,
unauthenticated CTR with a running counter, no header. Password: the KDF output is
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
`zeroize::Zeroizing` buffers and wiped on drop. The library now also wipes the
cipher's expanded key schedule: with the default `zeroize` feature, each
`Threefish*` has a `Drop` that zeroes its `ek`/`et` arrays (see `zeroize_impls` in
`lib.rs`). `--no-default-features` drops the `zeroize` dependency for the bare,
dependency-free core.

The cipher crate is `no_std` via `#![cfg_attr(not(test), no_std)]`, and supports
all three environment levels through the `alloc` feature (default on):

- std (default, on an OS) and no_std + alloc (no OS, has an allocator) are the same
  build; the std binaries link the no_std crate fine.
- no_std without an allocator (`--no-default-features`) is the bare core:
  `extern crate alloc` is itself `#[cfg(feature = "alloc")]`, so the allocator is
  not linked and any stray allocation is a compile error. CI builds this for a
  bare-metal target.

To make that work, the hashers are incremental and allocation-free. Each exposes a
fixed-size streaming type (`skein::Skein512`, `blake3::Hasher`, `poly1305::Poly1305`)
with `new`/`update`/`finalize`, plus one-shot `*_into` functions that write into a
caller buffer; the `Vec`-returning `hash`/`mac` are thin `#[cfg(feature = "alloc")]`
wrappers over them. Because the hashers stream, an input larger than RAM can be
hashed (the `gyotaku` CLI does this, reading files in fixed buffers). The
ChaCha20-Poly1305 AEAD has allocation-free `seal_in_place`/`open_in_place` (it feeds
the incremental Poly1305 piece by piece instead of assembling a buffer); the
`Vec`-returning `seal`/`open` are the `alloc` wrappers. Threefish/CTR, ChaCha20, and
Poly1305 are allocation-free throughout. It is `std` under `cargo test` so the
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
inputs). The other primitives are verified the same way: ChaCha20, Poly1305, and
ChaCha20-Poly1305 against the RFC 8439 vectors, and Skein-512 and BLAKE3
differentially against the RustCrypto `skein` and `blake3` crates over random
inputs (all in `crates/dorado/src/<module>.rs` test modules). The engine crate has
the KDF/header/MAC tests and the construction tests: password round-trip,
wrong-password, tampering, multi-chunk, every-MAC round-trip-and-reject, and the
streaming security properties (truncation, header tampering, early-chunk
tampering), plus the KDF-cost `validate` bounds.

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

- Optionally implement the RustCrypto `digest` traits for the hashers (the
  incremental `Skein512`/`blake3::Hasher` map onto `Update`/`FixedOutput`).

Done (was roadmap): RustCrypto `cipher` trait impls for the three Threefish
variants behind the optional `cipher` feature (`src/rustcrypto.rs`); `no_std` for
the cipher crate at all three levels
(`#![cfg_attr(not(test), no_std)]` plus the `alloc` feature; bare-metal CI for the
allocator and no-allocator builds); incremental, allocation-free hashers
(`Skein512`, `blake3::Hasher`, `Poly1305`) with one-shot `*_into` wrappers, so
inputs larger than RAM can be hashed (the `gyotaku` CLI streams files); an
allocation-free ChaCha20-Poly1305 AEAD (`seal_in_place`/`open_in_place` over the
incremental Poly1305); library key-schedule zeroization (default `zeroize`
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
