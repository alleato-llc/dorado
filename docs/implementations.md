# Implementations

Dorado is implemented eight ways. They share one cipher design and one on-disk
format, and are byte-for-byte cross-compatible: each can decrypt the others'
`.mahi` files, verified across every KDF, MAC, and cipher variant. What differs is
what each runtime can do around that shared core. Rust is the reference
implementation and the baseline for test vectors and cross-compat fixtures.

What is identical in all eight (so it is left out of the table below): the
from-scratch primitives (Threefish 256/512/1024 + CTR, Skein-512, BLAKE3), the
DRDO v4 on-disk format, cross-compatibility, and encrypt-then-MAC authentication
with a constant-time tag compare.

The six native ports (Rust, Go, Java, Python, C, Zig) run their own compiled cipher
and stream in constant memory. The TypeScript port is one codebase run two ways:
**Node** (a CLI, with locked secret memory) and **Browser** (the in-page demo);
both run the verified Rust cipher compiled to WASM and work in memory.

## At a glance

| Implementation | Role / frontends | Cipher engine | KDFs | Streaming | Secret memory |
| --- | --- | --- | --- | --- | --- |
| **Rust** | Reference; CLIs + 2 GUIs | native | `argon2`/`scrypt`/`pbkdf2` crates | Yes | `zeroize` (wiped on drop) + mlock'd password |
| **Go** | Port; CLIs | native | `golang.org/x/crypto` + stdlib | Yes | engine wipes keys; CLI mlocks password (off-heap) |
| **Java** | Port; SDK only | native | Bouncy Castle | Yes | caller-managed |
| **Python** | Port; CLIs | native | `argon2-cffi` + `hashlib` | Yes | caller-managed (`bytes` immutable) |
| **C** | Port; CLIs | native | system `libargon2` + OpenSSL | Yes | engine wipes keys; CLI mlocks password |
| **Zig** | Port; CLIs | native | Zig stdlib (no external deps) | Yes | engine wipes keys; CLI mlocks password |
| **TypeScript · Node** | Port; CLIs | WASM (Rust cipher) | `hash-wasm` (WASM) | No (in-memory) | `sodium-native` locked buffers |
| **TypeScript · Browser** | In-page demo | WASM (Rust cipher) | `hash-wasm` (WASM) | No (in-memory) | none (demo, not secure) |

Three more axes are not columns above. **`no_std` / bare-metal:** the from-scratch
cipher primitives (Threefish/CTR, Skein, BLAKE3) build with no OS and no allocator
in **Rust, C, and Zig** (CI cross-compiles them to a bare-metal ARM target); the
construction (whose KDFs need an allocator) is not bare-metal, and Go, Java, Python,
and TypeScript require a managed runtime. **Constant time:** only Rust documents and
preserves a full no-secret-dependent-branching discipline; every other port at least
uses a constant-time tag compare, and the cipher is ARX (no secret-dependent table
lookups) everywhere, but JIT/interpreted runtimes cannot promise constant time.
**Memory safety** is why Rust is the strongest tier overall (not the wipe/lock
mechanism, which C and Zig match): a use-after-free or buffer overrun can leak a
secret, and only Rust *prevents* those at compile time (with `#![forbid(unsafe_code)]`).
Zig *detects* the common classes at runtime when built `ReleaseSafe` (its release
default here: bounds, integer-overflow, and alignment checks stay in the binary), but
has no borrow checker, so general use-after-free is not caught. C relies on external
sanitizers (ASan/UBSan in CI), which detect bugs only on the paths a test exercises.
Go and the managed runtimes are memory-safe but pay for it elsewhere (the GC is what
makes Go's wipe a convention rather than a guarantee).

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
  - *Rust* wipes secret buffers and the cipher's key schedule on drop (`zeroize`,
    automatically on every path), and its CLI `mlock`s the password buffer out of
    swap (via the `region` crate, so `#![forbid(unsafe_code)]` still holds).
  - *C* and *Zig* wipe the derived keys and the cipher's expanded key schedule with a
    non-elidable clear (`OPENSSL_cleanse` / `std.crypto.secureZero`), and their CLIs
    hold the password in a page-aligned, `mlock`'d buffer kept out of swap. The wipe
    runs automatically on every exit path: C via `__attribute__((cleanup))`, Zig via
    `defer`, the analogs of Rust's `Drop`.
  - *Go* wipes the derived keys and the cipher's key schedule (a clear plus
    `runtime.KeepAlive` to defeat dead-store elimination; Go's heap is non-moving, so
    the slice is not relocated), and its CLI holds the password in an off-heap
    `mmap`'d, `mlock`'d buffer (out of swap, and not subject to growable-stack
    copies). What Go still lacks is a non-elidable wipe guaranteed the way Rust's
    `zeroize`, C's `OPENSSL_cleanse`, and Zig's `secureZero` are; its `KeepAlive`
    clear is reliable in practice but is a convention, not a language guarantee.
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
