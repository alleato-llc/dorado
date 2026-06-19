# CLAUDE.md

## What this crate is

Dorado is a from-scratch implementation of the Threefish tweakable block cipher
(256, 512, and 1024-bit variants), the cipher at the core of the Skein hash
function. It follows the Skein 1.3 specification. The scope is deliberately
narrow and educational: the block cipher, CTR mode for arbitrary-length data, and
(in the CLI only) password-based key derivation. There is no AEAD, no
authentication, and no broader key management. CTR provides confidentiality only.

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

There are two binaries: the CLI (`src/main.rs`, feature `cli`) and the iced GUI demo
(`src/gui.rs`, feature `gui`). Both are thin frontends over a shared construction in
`src/engine.rs`, which in turn uses three modules: `src/kdf.rs` (Argon2id, scrypt,
PBKDF2-HMAC-SHA256 behind one `derive` call), `src/format.rs` (the container header
and streaming reader; magic `DRDO`, version, variant, KDF id and params, MAC id,
chunk size, salt, tweak, IV), and `src/mac.rs` (encrypt-then-MAC with HMAC-SHA256).
The feature graph is `password` (the crypto deps: KDFs, hmac, rand, zeroize), with
`cli = password + clap + rpassword` and `gui = password + iced`. The library stays
dependency-free; a plain build compiles neither binary.

These four modules (`engine`, `format`, `kdf`, `mac`) are not in the library; each
binary declares them with `mod`, so they are compiled into whichever binary is
built (hence the `#![allow(dead_code)]` in `engine`: each frontend uses a different
subset of its API). `engine` exposes streaming functions over `Read`/`Write` (the
CLI, for constant-memory files) and in-memory `*_bytes` wrappers (the GUI, which is
password-only and runs the KDF on a background thread to stay responsive), plus a
single-block `block_transform` helper that is currently only exercised by tests.
Keep new shared logic in `engine` so both frontends get it.

`engine` has two key paths, both streamable in constant memory. Raw key: bare,
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

- The in-crate known-answer tests, the CTR tests, and the differential tests must
  stay green.
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
cargo test
```

This runs the cipher's known-answer and CTR tests, plus the differential harness
(`tests/diff.rs`). The differential harness checks dorado against the RustCrypto
`threefish` crate over random inputs and needs the dev-dependencies declared in
`Cargo.toml`. CTR mode has no official vectors, so its tests anchor it to the
verified block cipher (keystream equals the block cipher on successive counters) and
check round-trips at non-block-multiple lengths. The CLI's header, KDF, MAC, and
counter tests run only with `cargo test --features cli`.

Unit tests live in their own files, not inline with the implementation: the cipher
tests are in `src/tests.rs`, and each binary module's tests sit beside it
(`src/kdf/tests.rs`, `src/format/tests.rs`, `src/mac/tests.rs`, `src/engine/tests.rs`).
Each source file declares its tests with `#[cfg(test)] mod tests;`. The `engine`
tests cover the in-memory password round-trip (including wrong-password, tampering,
and multi-chunk) and `block_transform`, so the construction is now unit-tested, not
just exercised by hand. Keep new unit tests in these files rather than inline. Build the CLI with `cargo build --features cli`, and
lint everything with `cargo clippy --all-targets --features cli` and
`cargo fmt --check`.

## Roadmap

Candidate future work, not commitments:

- Make the crate `no_std` by replacing the per-call heap scratch buffer in
  `encrypt` / `decrypt` with a fixed-size stack buffer. Note the CLI's KDF,
  format, and MAC code would stay `std`-only.
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
