# Implementations

Dorado is implemented four ways. They share one cipher design and one on-disk
format, and are byte-for-byte cross-compatible: each can decrypt the others'
`.mahi` files, verified across every KDF, MAC, and cipher variant. What differs is
what each runtime can do around that shared core.

A note on the last two columns: "TypeScript (Node)" and "TypeScript (Browser)" are
the *same* code in the `ts/` package. They differ only in runtime: Node can hold
secrets in locked memory and run as a CLI; the browser runs the in-page demo and
cannot. They are listed separately because those runtime differences are the whole
point of the question "is the browser version as protected as the CLI?" (it is
not).

## At a glance

| Capability | Rust | Go | TypeScript (Node) | TypeScript (Browser) |
| --- | --- | --- | --- | --- |
| Role | Reference implementation | Port | Port | Same code, in the browser |
| From-scratch primitives (Threefish, CTR, Skein, BLAKE3, ChaCha20, Poly1305) | Yes | Yes | Yes | Yes |
| On-disk format (`.mahi`, DRDO v4) | Yes | Yes | Yes | Yes |
| Cross-compatible with the others | Yes | Yes | Yes | Yes |
| Frontends | `dorado` + `gyotaku` CLIs, two desktop GUIs | `dorado` + `gyotaku` CLIs | `dorado` + `gyotaku` CLIs | in-browser encrypt + hash demo |
| GUI | Yes (iced): `dorado-gui` and `gyotaku-gui` | No | No | No |
| Cipher engine actually run | native Rust | native Go | WASM (the verified Rust cipher); pure-TS available | WASM (the verified Rust cipher); pure-TS available |
| KDFs (Argon2id / scrypt / PBKDF2) | `argon2`/`scrypt`/`pbkdf2` crates | `golang.org/x/crypto` + stdlib | `hash-wasm` (WASM) | `hash-wasm` (WASM) |
| HMAC-SHA256 MAC | RustCrypto `hmac` + `sha2` | Go stdlib `crypto/hmac` | Web Crypto | Web Crypto |
| Streaming in constant memory (files larger than RAM) | Yes | Yes | No (in-memory) | No (in-memory) |
| `no_std` / bare-metal | Yes | No | No | No |
| Constant-time discipline | Documented invariant | Best-effort; constant-time compare | Not achievable (JIT) | Not achievable (JIT) |
| Secret memory protection | `zeroize` (key schedule and buffers wiped on drop) | Best-effort wipe (no guarantee) | `sodium-native` locked, off-heap buffers for CLI-held secrets; WASM keeps cipher transients off the JS heap | WASM keeps cipher transients off the JS heap; no locked memory |
| Verification | KAT + differential (RustCrypto) + fuzzing + full suite | Tests mirroring Rust | vitest + differential (`@noble/hashes`) | Same TS suite |

## What is the same everywhere

- **The cipher and the format.** Threefish (256/512/1024), CTR, Skein-512, BLAKE3,
  and the ChaCha20-Poly1305 primitives are reimplemented from scratch in each
  language and checked against the same official vectors. The container header,
  chunk framing, KDF and MAC identifiers, and v4 label binding are identical, which
  is why a file made by one tool opens in the others. The format and constants are
  specified once in [`spec.md`](spec.md).
- **The authentication.** Encrypt-then-MAC with a 32-byte tag per chunk, the header
  bound into chunk 0, and a constant-time tag compare. Tampering, wrong passwords,
  reordering, dropping, and truncation are rejected in every implementation.
- **The MAC menu.** Skein-512 (default) and keyed BLAKE3 are from-scratch
  everywhere. Only the HMAC-SHA256 option leans on each ecosystem's standard
  library (so SHA-256 is not reimplemented).

## Where they differ, and why it matters

- **Cipher engine.** Rust and Go run their native cipher. The TypeScript package
  has a swappable backend: a readable pure-TypeScript cipher (used by its test
  suite) and the verified Rust cipher compiled to WASM. The Node CLI and the
  browser demo both run the WASM backend, so the secret arithmetic happens in WASM
  linear memory rather than scattered across short-lived JavaScript numbers.
- **Streaming.** Rust and Go process files chunk by chunk over reader/writer
  interfaces, so they can encrypt or hash inputs larger than RAM in constant
  memory. The TypeScript engine works in-memory over byte arrays, so its working
  set is the size of the file.
- **`no_std` / bare-metal.** Only the Rust cipher crate builds without an operating
  system or an allocator (CI builds it for a bare-metal target). Go, Node, and the
  browser all require a managed runtime.
- **Secret handling.** This is the sharpest difference, and the reason the browser
  is the weakest tier:
  - *Rust* wipes secret buffers and the cipher's key schedule on drop (`zeroize`).
  - *Go* zeroes secret slices best-effort, but the language cannot guarantee a wipe
    (the garbage collector may have already copied the value).
  - *TypeScript on Node* holds CLI-held secrets (the password, a raw key, the
    plaintext) in `sodium-native` locked, off-heap, guard-paged buffers that stay
    out of swap and core dumps, and wipes them after use. The WASM backend keeps
    the cipher's transient values off the JavaScript heap.
  - *TypeScript in the browser* gets the WASM off-heap transients but has no locked
    memory, no wipe guarantee, and a password that arrives as an un-wipeable
    JavaScript string. It is a demo, not a secure tool.
- **Constant time.** Rust documents and preserves a no-secret-dependent-branching,
  no-secret-dependent-indexing discipline. Go uses a constant-time tag compare but
  makes no broader guarantee. A JIT-compiled language cannot promise constant time
  at all; WASM does not change that.

None of this is a security claim for any implementation. Dorado is educational and
unaudited; for real data, prefer an audited tool. The point of the table is to be
precise about what each version does and does not provide.
