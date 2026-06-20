# Implementations

Dorado is implemented seven ways. They share one cipher design and one on-disk
format, and are byte-for-byte cross-compatible: each can decrypt the others'
`.mahi` files, verified across every KDF, MAC, and cipher variant. What differs is
what each runtime can do around that shared core. Rust is the reference
implementation and the baseline for test vectors and cross-compat fixtures.

Two notes on the columns. **Java** is an SDK only (a library: no CLI, no GUI);
**Python** and **C** ship an SDK plus the two CLIs. **TypeScript (Node)** and
**TypeScript (Browser)** are the *same* code in the `ts/` package, differing only in
runtime: Node can hold secrets in locked memory and run as a CLI; the browser runs
the in-page demo and cannot.

## At a glance

| Capability | Rust | Go | Java | Python | C | TypeScript (Node) | TypeScript (Browser) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Role | Reference | Port | Port (SDK only) | Port | Port | Port | Same code, in the browser |
| From-scratch primitives | Threefish, CTR, Skein, BLAKE3, ChaCha20, Poly1305 | same | same, no ChaCha20/Poly1305 | same, no ChaCha20/Poly1305 | same, no ChaCha20/Poly1305 | same | same |
| On-disk format (`.mahi`, DRDO v4) | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Cross-compatible | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Frontends | `dorado` + `gyotaku` CLIs, two desktop GUIs | `dorado` + `gyotaku` CLIs | none (SDK only) | `dorado` + `gyotaku` CLIs | `dorado` + `gyotaku` CLIs | `dorado` + `gyotaku` CLIs | in-browser encrypt + hash demo |
| GUI | Yes (iced) | No | No | No | No | No | No |
| Cipher engine | native Rust | native Go | native Java | native Python | native C | WASM (Rust cipher); pure-TS available | WASM (Rust cipher); pure-TS available |
| KDFs (Argon2id / scrypt / PBKDF2) | `argon2`/`scrypt`/`pbkdf2` crates | `golang.org/x/crypto` + stdlib | Bouncy Castle | `argon2-cffi` + `hashlib` | system `libargon2` + OpenSSL | `hash-wasm` (WASM) | `hash-wasm` (WASM) |
| HMAC-SHA256 MAC | RustCrypto `hmac` + `sha2` | Go stdlib | JDK `javax.crypto` | stdlib `hmac` | OpenSSL | Web Crypto | Web Crypto |
| Streaming in constant memory | Yes | Yes | Yes | Yes | Yes | No (in-memory) | No (in-memory) |
| `no_std` / bare-metal | Yes | No | No | No | No | No | No |
| Constant-time discipline | Documented invariant | Best-effort; ct compare | Not guaranteed (JIT); ct compare | Not guaranteed (interpreted); ct compare | Best-effort; ct compare | Not achievable (JIT) | Not achievable (JIT) |
| Secret memory protection | `zeroize` (wiped on drop) | Best-effort wipe | Caller-managed; no wipe | Caller-managed; `bytes` immutable | Caller-managed; no built-in wipe | `sodium-native` locked buffers; WASM off-heap transients | WASM off-heap transients; no locked memory |
| Verification | KAT + differential + fuzzing + suite | Tests mirroring Rust | JUnit + cross-compat fixtures | pytest + cross-compat fixtures | Test harness + cross-compat fixtures (ASan/UBSan) | vitest + differential | Same TS suite |

## What is the same everywhere

- **The cipher and the format.** Threefish (256/512/1024), CTR, Skein-512, and
  BLAKE3 are reimplemented from scratch in each language and checked against the
  same official vectors (Java, Python, and C omit the standalone ChaCha20-Poly1305
  primitives, which are library-only and never wired into the tool). The container
  header, chunk framing, KDF and MAC identifiers, and v4 label binding are
  identical, which is why a file made by one opens in the others. The format and
  constants are specified once in [`spec.md`](spec.md).
- **The authentication.** Encrypt-then-MAC with a 32-byte tag per chunk, the header
  bound into chunk 0, and a constant-time tag compare. Tampering, wrong passwords,
  reordering, dropping, and truncation are rejected in every implementation.
- **The MAC menu.** Skein-512 (default) and keyed BLAKE3 are from-scratch
  everywhere. Only the HMAC-SHA256 option leans on each ecosystem's standard
  library (so SHA-256 is not reimplemented).

## Where they differ, and why it matters

- **Cipher engine.** Rust, Go, Java, Python, and C run their native cipher. The
  TypeScript package has a swappable backend: a readable pure-TypeScript cipher
  (used by its test suite) and the verified Rust cipher compiled to WASM. The Node
  CLI and the browser demo both run the WASM backend, so the secret arithmetic
  happens in WASM linear memory rather than scattered across short-lived JavaScript
  numbers.
- **Streaming.** Rust, Go, Java, Python, and C process files chunk by chunk over
  reader/writer interfaces (constant memory). The TypeScript engine works in-memory
  over byte arrays.
- **`no_std` / bare-metal.** Only the Rust cipher crate builds without an operating
  system or an allocator (CI builds it for a bare-metal target). Everything else
  requires a runtime or links libc.
- **Secret handling.** This is the sharpest difference, and the reason the browser
  is the weakest tier:
  - *Rust* wipes secret buffers and the cipher's key schedule on drop (`zeroize`).
  - *Go* zeroes secret slices best-effort, but the language cannot guarantee a wipe.
  - *Java*, *Python*, and *C* are SDKs that leave the lifetime of secret buffers to
    the caller and do not wipe them (Python `bytes` are immutable, so they cannot
    even be wiped in place).
  - *TypeScript on Node* holds CLI-held secrets in `sodium-native` locked, off-heap,
    guard-paged buffers and wipes them after use; the WASM backend keeps the
    cipher's transient values off the JavaScript heap.
  - *TypeScript in the browser* gets the WASM off-heap transients but has no locked
    memory, no wipe guarantee, and a password that arrives as an un-wipeable
    JavaScript string. It is a demo, not a secure tool.
- **Constant time.** Rust documents and preserves a no-secret-dependent-branching,
  no-secret-dependent-indexing discipline. Go and C are compiled ahead of time and
  use a constant-time tag compare but make no broader guarantee. JIT-compiled or
  interpreted runtimes (the JVM, JavaScript, CPython) cannot promise constant time
  at all, though Java and Python still use a constant-time tag compare.

None of this is a security claim for any implementation. Dorado is educational and
unaudited; for real data, prefer an audited tool. The point of the table is to be
precise about what each version does and does not provide.
