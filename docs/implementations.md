# Implementations

Dorado is implemented six ways. They share one cipher design and one on-disk
format, and are byte-for-byte cross-compatible: each can decrypt the others'
`.mahi` files, verified across every KDF, MAC, and cipher variant. What differs is
what each runtime can do around that shared core. Rust is the reference
implementation and the baseline for test vectors and cross-compat fixtures.

Two notes on the columns. **Java** is an SDK only (a library: no CLI, no GUI);
**Python** ships an SDK plus the two CLIs. **TypeScript (Node)** and **TypeScript
(Browser)** are the *same* code in the `ts/` package, differing only in runtime:
Node can hold secrets in locked memory and run as a CLI; the browser runs the
in-page demo and cannot. They are listed separately because that difference is the
whole point of the question "is the browser version as protected as the CLI?" (it
is not).

## At a glance

| Capability | Rust | Go | Java | Python | TypeScript (Node) | TypeScript (Browser) |
| --- | --- | --- | --- | --- | --- | --- |
| Role | Reference | Port | Port (SDK only) | Port | Port | Same code, in the browser |
| From-scratch primitives | Threefish, CTR, Skein, BLAKE3, ChaCha20, Poly1305 | same | same, minus ChaCha20/Poly1305 | same, minus ChaCha20/Poly1305 | same | same |
| On-disk format (`.mahi`, DRDO v4) | Yes | Yes | Yes | Yes | Yes | Yes |
| Cross-compatible with the others | Yes | Yes | Yes | Yes | Yes | Yes |
| Frontends | `dorado` + `gyotaku` CLIs, two desktop GUIs | `dorado` + `gyotaku` CLIs | none (SDK only) | `dorado` + `gyotaku` CLIs | `dorado` + `gyotaku` CLIs | in-browser encrypt + hash demo |
| GUI | Yes (iced): `dorado-gui` and `gyotaku-gui` | No | No | No | No | No |
| Cipher engine actually run | native Rust | native Go | native Java | native Python | WASM (the verified Rust cipher); pure-TS available | WASM (the verified Rust cipher); pure-TS available |
| KDFs (Argon2id / scrypt / PBKDF2) | `argon2`/`scrypt`/`pbkdf2` crates | `golang.org/x/crypto` + stdlib | Bouncy Castle | `argon2-cffi` + `hashlib` | `hash-wasm` (WASM) | `hash-wasm` (WASM) |
| HMAC-SHA256 MAC | RustCrypto `hmac` + `sha2` | Go stdlib `crypto/hmac` | JDK `javax.crypto` | stdlib `hmac` | Web Crypto | Web Crypto |
| Streaming in constant memory (files larger than RAM) | Yes | Yes | Yes | Yes | No (in-memory) | No (in-memory) |
| `no_std` / bare-metal | Yes | No | No | No | No | No |
| Constant-time discipline | Documented invariant | Best-effort; constant-time compare | Not guaranteed (JIT); constant-time tag compare | Not guaranteed (interpreted); constant-time tag compare | Not achievable (JIT) | Not achievable (JIT) |
| Secret memory protection | `zeroize` (key schedule and buffers wiped on drop) | Best-effort wipe (no guarantee) | Caller-managed; no built-in wipe | Caller-managed; `bytes` immutable (no wipe) | `sodium-native` locked, off-heap buffers; WASM keeps transients off the JS heap | WASM keeps transients off the JS heap; no locked memory |
| Verification | KAT + differential (RustCrypto) + fuzzing + full suite | Tests mirroring Rust | JUnit: KATs + every KDF/MAC/variant + cross-compat fixtures from Rust | pytest: KATs + every KDF/MAC/variant + cross-compat fixtures from Rust | vitest + differential (`@noble/hashes`) | Same TS suite |

## What is the same everywhere

- **The cipher and the format.** Threefish (256/512/1024), CTR, Skein-512, and
  BLAKE3 are reimplemented from scratch in each language and checked against the
  same official vectors (Java and Python additionally omit the standalone
  ChaCha20-Poly1305 primitives, which are library-only and never wired into the
  tool). The container header, chunk framing, KDF and MAC identifiers, and v4 label
  binding are identical, which is why a file made by one opens in the others. The
  format and constants are specified once in [`spec.md`](spec.md).
- **The authentication.** Encrypt-then-MAC with a 32-byte tag per chunk, the header
  bound into chunk 0, and a constant-time tag compare. Tampering, wrong passwords,
  reordering, dropping, and truncation are rejected in every implementation.
- **The MAC menu.** Skein-512 (default) and keyed BLAKE3 are from-scratch
  everywhere. Only the HMAC-SHA256 option leans on each ecosystem's standard
  library (so SHA-256 is not reimplemented).

## Where they differ, and why it matters

- **Cipher engine.** Rust, Go, Java, and Python run their native cipher. The
  TypeScript package has a swappable backend: a readable pure-TypeScript cipher
  (used by its test suite) and the verified Rust cipher compiled to WASM. The Node
  CLI and the browser demo both run the WASM backend, so the secret arithmetic
  happens in WASM linear memory rather than scattered across short-lived JavaScript
  numbers.
- **Streaming.** Rust, Go, Java, and Python process files chunk by chunk over
  reader/writer interfaces, so they can encrypt or hash inputs larger than RAM in
  constant memory. The TypeScript engine works in-memory over byte arrays, so its
  working set is the size of the file.
- **`no_std` / bare-metal.** Only the Rust cipher crate builds without an operating
  system or an allocator (CI builds it for a bare-metal target). Everything else
  requires a managed runtime.
- **Secret handling.** This is the sharpest difference, and the reason the browser
  is the weakest tier:
  - *Rust* wipes secret buffers and the cipher's key schedule on drop (`zeroize`).
  - *Go* zeroes secret slices best-effort, but the language cannot guarantee a wipe
    (the garbage collector may have already copied the value).
  - *Java* and *Python* are SDKs: they leave the lifetime of secret buffers to the
    caller and do not wipe them. Python `bytes` are immutable, so they cannot even
    be wiped in place.
  - *TypeScript on Node* holds CLI-held secrets (the password, a raw key, the
    plaintext) in `sodium-native` locked, off-heap, guard-paged buffers that stay
    out of swap and core dumps, and wipes them after use. The WASM backend keeps
    the cipher's transient values off the JavaScript heap.
  - *TypeScript in the browser* gets the WASM off-heap transients but has no locked
    memory, no wipe guarantee, and a password that arrives as an un-wipeable
    JavaScript string. It is a demo, not a secure tool.
- **Constant time.** Rust documents and preserves a no-secret-dependent-branching,
  no-secret-dependent-indexing discipline. Go uses a constant-time tag compare but
  makes no broader guarantee. JIT-compiled or interpreted runtimes (the JVM,
  JavaScript, CPython) cannot promise constant time at all, though Java and Python
  still use a constant-time tag compare; WASM does not change that.

None of this is a security claim for any implementation. Dorado is educational and
unaudited; for real data, prefer an audited tool. The point of the table is to be
precise about what each version does and does not provide.
