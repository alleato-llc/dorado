# CLAUDE.md

## What this is

Dorado is a Cargo workspace of four crates:

- `crates/dorado` — the cipher library: a from-scratch Threefish (256/512/1024)
  following Skein 1.3, plus CTR mode. Zero runtime dependencies.
- `crates/dorado-engine` — the construction over the cipher: the three KDFs, the
  authenticated chunked password container, and raw CTR. Depends on `dorado`.
- `crates/dorado-cli` — clap frontend; produces the `dorado` binary.
- `crates/dorado-gui` — iced frontend; produces `dorado-gui`.

Educational and unaudited. The cipher provides confidentiality only; the engine
adds authentication (encrypt-then-MAC) for password files.

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
(encrypt-then-MAC with HMAC-SHA256). It re-exports `Variant`, `KdfParams`, and
`PrfId` for the frontends. Because it is a real library crate, there is no
dead-code hack: a different subset of its public API is used by each frontend, and
that is fine. It exposes streaming functions over `Read`/`Write` (the CLI, for
constant-memory files), in-memory `*_bytes` wrappers (the GUI), and a single-block
`block_transform` (exercised by tests). Keep new shared logic in `dorado-engine`.

The engine has two key paths, both streamable in constant memory. Raw key: bare,
unauthenticated CTR with a running counter, no header. Password: the KDF output is
split into a separate encryption key and MAC key, then the data is processed in
fixed-size chunks (`--chunk-kib`, default 64 KiB, stored in the header). Each chunk
is CTR-encrypted on a continuous counter and carries an HMAC-SHA256 tag over
`domain || index || is_last || ciphertext`, with the header bound into chunk 0's tag
(`frame_aad` in `engine`). Decryption verifies each
chunk before decrypting it, so tampering, wrong passwords, reordering, dropping,
and truncation (an authenticated final-chunk flag that must be seen before EOF)
are all rejected. Streaming means verified plaintext can be emitted before a later
chunk fails, so a non-zero exit means the output is incomplete and untrusted.
Changing the container format is a version bump (`format::VERSION`, currently 3).

Note the scrypt quirk in `kdf.rs`: scrypt's `Params::new` caps its `len` field at
64, but that field only feeds its PHC API; pass a placeholder and let the real
length come from the output slice, or the 1024 variant (160 key bytes) fails.

Secrets in the CLI (the password, the KDF output, derived keys) are held in
`zeroize::Zeroizing` buffers and wiped on drop. The library itself is not zeroized:
a `Threefish*` keeps its expanded key schedule until dropped, since the core crate
stays dependency-free. Adding library zeroization would mean an optional `zeroize`
dependency and a `Drop`/`ZeroizeOnDrop` impl on the variant structs.

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
```

The cipher crate has the known-answer and CTR tests plus the differential harness
(`crates/dorado/tests/diff.rs`, vs the RustCrypto `threefish` crate over random
inputs). The engine crate has the KDF/header/MAC tests and the construction tests:
password round-trip, wrong-password, tampering, multi-chunk, and the streaming
security properties (truncation, header tampering, early-chunk tampering), plus the
KDF-cost `validate` bounds.

Unit tests live in their own files, not inline: cipher tests in
`crates/dorado/src/tests.rs`, engine tests in `crates/dorado-engine/src/tests.rs`,
and each engine module's tests beside it (`kdf/tests.rs`, `format/tests.rs`,
`mac/tests.rs`). Each source file declares them with `#[cfg(test)] mod tests;`.

Audit-readiness: every crate sets `#![forbid(unsafe_code)]`. CI
(`.github/workflows/ci.yml`) runs fmt/clippy/test and `cargo audit`. A fuzz target
(`fuzz/fuzz_targets/decrypt.rs`, run with `cargo +nightly fuzz run decrypt`) feeds
arbitrary bytes to `decrypt_password_bytes`; it must never panic or over-allocate,
which is what the chunk-size and KDF-cost bounds guarantee.

## Roadmap

Candidate future work, not commitments:

- Finish `no_std` for the cipher crate. The per-call heap scratch is already gone
  (a fixed `[u64; MAX_NW]` stack buffer), so the remaining work is the `no_std`
  attribute and confirming no other `std` use. The engine stays `std`-only.
- Build Skein's UBI chaining mode on top of the block cipher to get the hash
  function. A Skein-based MAC could then replace HMAC in the container for a
  single-primitive design.
- Optionally implement the RustCrypto `cipher` crate traits for ecosystem
  interop.

## Conventions

- No em dashes anywhere.
- No fabricated metrics, benchmarks, or statistics. If a number cannot be measured
  or verified, leave it out.
- Direct prose, minimal formatting, no marketing tone.
- Keep changes scoped to what is asked. Do not refactor the cipher, add features,
  or restructure the project.
- Do not add dependencies without asking first.
- Be honest about limitations rather than papering over them.
