# Implementations

Dorado is implemented eight ways. They share one cipher design and one on-disk
format, and are byte-for-byte cross-compatible: each can decrypt the others'
`.mahi` files, verified across every KDF, MAC, and cipher variant. What differs is
what each runtime can do around that shared core. Rust is the reference
implementation and the baseline for test vectors and cross-compat fixtures.

What is identical in all eight (so it is left out of the table below): the
from-scratch primitives (Threefish 256/512/1024 + CTR, Skein-512, BLAKE3; Java,
Python, C, and Zig additionally omit the library-only ChaCha20-Poly1305), the
DRDO v4 on-disk format, cross-compatibility, and encrypt-then-MAC authentication
with a constant-time tag compare.

The six native ports (Rust, Go, Java, Python, C, Zig) run their own compiled cipher
and stream in constant memory. The TypeScript port is one codebase run two ways:
**Node** (a CLI, with locked secret memory) and **Browser** (the in-page demo);
both run the verified Rust cipher compiled to WASM and work in memory.

## At a glance

| Implementation | Role / frontends | Cipher engine | KDFs | Streaming | Secret memory |
| --- | --- | --- | --- | --- | --- |
| **Rust** | Reference; CLIs + 2 GUIs | native | `argon2`/`scrypt`/`pbkdf2` crates | Yes | `zeroize` (wiped on drop) |
| **Go** | Port; CLIs | native | `golang.org/x/crypto` + stdlib | Yes | best-effort wipe |
| **Java** | Port; SDK only | native | Bouncy Castle | Yes | caller-managed |
| **Python** | Port; CLIs | native | `argon2-cffi` + `hashlib` | Yes | caller-managed (`bytes` immutable) |
| **C** | Port; CLIs | native | system `libargon2` + OpenSSL | Yes | engine wipes keys; CLI mlocks password |
| **Zig** | Port; CLIs | native | Zig stdlib (no external deps) | Yes | engine wipes keys; CLI mlocks password |
| **TypeScript · Node** | Port; CLIs | WASM (Rust cipher) | `hash-wasm` (WASM) | No (in-memory) | `sodium-native` locked buffers |
| **TypeScript · Browser** | In-page demo | WASM (Rust cipher) | `hash-wasm` (WASM) | No (in-memory) | none (demo, not secure) |

Two more axes are not columns above. **`no_std` / bare-metal:** the from-scratch
cipher primitives (Threefish/CTR, Skein, BLAKE3) build with no OS and no allocator
in **Rust, C, and Zig** (CI cross-compiles them to a bare-metal ARM target); the
construction (whose KDFs need an allocator) is not bare-metal, and Go, Java, Python,
and TypeScript require a managed runtime. **Constant time:** only Rust documents and
preserves a full no-secret-dependent-branching discipline; every other port at least
uses a constant-time tag compare, and the cipher is ARX (no secret-dependent table
lookups) everywhere, but JIT/interpreted runtimes cannot promise constant time.

HMAC-SHA256 uses each ecosystem's standard library (RustCrypto, Go stdlib, the JDK,
Python `hmac`, OpenSSL, Zig stdlib, Web Crypto); Skein-512 and keyed BLAKE3 are
from-scratch everywhere. Each port is verified with KATs and cross-compat fixtures
produced by the Rust CLI (Rust adds differential tests and fuzzing; C also runs
under ASan/UBSan).

## Where they differ, and why it matters

- **Cipher engine.** Rust, Go, Java, Python, C, and Zig run their own compiled
  cipher. The TypeScript package has a swappable backend: a readable pure-TypeScript
  cipher (used by its test suite) and the verified Rust cipher compiled to WASM. The
  Node CLI and the browser demo both run the WASM backend, so the secret arithmetic
  happens in WASM linear memory rather than scattered across short-lived JavaScript
  numbers.
- **Streaming.** The six native ports process files chunk by chunk over
  reader/writer interfaces (constant memory). The TypeScript engine works in-memory
  over byte arrays, so its working set is the size of the file.
- **`no_std` / bare-metal.** The from-scratch cipher primitives build with no OS and
  no allocator in Rust, C, and Zig: Rust's cipher crate targets a bare-metal ARM
  build, C's primitives compile with `-ffreestanding` (`make freestanding`), and
  Zig cross-compiles them to a bare-metal ARM object (`zig build freestanding`). In
  all three the construction (the KDFs need an allocator) is excluded. Go, Java,
  Python, and TypeScript require a managed runtime.
- **Secret handling.** This is the sharpest difference, and the reason the browser
  is the weakest tier:
  - *Rust* wipes secret buffers and the cipher's key schedule on drop (`zeroize`).
  - *C* and *Zig* wipe the derived keys and the cipher's expanded key schedule after
    use (`OPENSSL_cleanse` / `std.crypto.secureZero`, which the compiler cannot
    optimize away), and their CLIs hold the password in a page-aligned, `mlock`'d
    buffer that is kept out of swap and wiped on free.
  - *Go* zeroes secret slices best-effort, but the language cannot guarantee a wipe.
  - *Java* and *Python* are libraries that leave the lifetime of secret buffers to
    the caller and do not wipe them (Python `bytes` are immutable, so they cannot
    even be wiped in place).
  - *TypeScript on Node* holds CLI-held secrets in `sodium-native` locked, off-heap,
    guard-paged buffers and wipes them after use; the WASM backend keeps the
    cipher's transient values off the JavaScript heap.
  - *TypeScript in the browser* gets the WASM off-heap transients but has no locked
    memory, no wipe guarantee, and a password that arrives as an un-wipeable
    JavaScript string. It is a demo, not a secure tool.
- **KDF dependencies.** The KDFs are the one part no port reimplements from scratch.
  Each delegates to its ecosystem's library; Zig is the only one that needs nothing
  external, since Argon2id, scrypt, and PBKDF2 are in its standard library.

None of this is a security claim for any implementation. Dorado is educational and
unaudited; for real data, prefer an audited tool. The point of the table is to be
precise about what each version does and does not provide.
