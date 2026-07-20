# Implementations

Dorado has nine implementations (the TypeScript port is one codebase run two
ways, Node and the browser, so the table below has ten rows). They share one
cipher design and one on-disk format, and are byte-for-byte cross-compatible:
each can decrypt the others' `.mahi` files, verified in committed tests in both
directions through the Rust reference (every port decrypts fixtures produced by
the Rust CLI, and the Rust suite decrypts a container encrypted by each of the
other eight ports), across every KDF, MAC, and cipher variant. All-pairs
decryption is not tested directly; both directions run through Rust. What
differs is what each runtime can do around that shared core. Rust is the
reference implementation and the baseline for test vectors and cross-compat
fixtures.

What is identical in all nine (so it is left out of the table below): the
from-scratch primitives (Threefish 256/512/1024 + CTR, Skein-512, BLAKE3), the
DRDO v4 on-disk format, cross-compatibility, and encrypt-then-MAC authentication
with a constant-time tag compare. Every port's raw-key mode also gained an
authenticated construction alongside its original bare CTR: the caller's key
is split into an independent encryption subkey and MAC subkey via
domain-separated Skein-512 keyed hashing (not a password KDF — no
cost-parameterized stretching), reusing the password container's exact frame
layout, with the tweak and IV bound into frame 0's authenticated data since
raw mode has no header to bind them into. See
[`spec.md`](spec.md#raw-key-modes) for the byte-level construction and
[`fixtures/raw-authenticated.md`](fixtures/raw-authenticated.md) for the
cross-language known-answer vectors every port is verified against. Every
port with a CLI (all but Java, which is SDK-only) exposes it the same way:
raw-key mode is authenticated by default, and `--unauthenticated` opts out to
bare CTR. Every port also exposes both standard forms of key derivation as
public API: the slow password stretch (`derive_from_password` and its
per-language spellings) and the fast key-based fan-out (`derive_from_key`,
one domain-separated keyed hash under a selectable PRF, Skein-512 by default
or BLAKE3), verified against the shared vectors in
[`fixtures/derive-from-key.md`](fixtures/derive-from-key.md). Untrusted
container headers are bounded identically everywhere: KDF cost parameters are
validated before any derivation, and the accepted chunk size is capped
(64 MiB default; `DORADO_MAX_CHUNK_BYTES` can lower or raise the cap, clamped
to the 1 GiB hard ceiling).
The one Rust-only knob is `DORADO_RNG`, which selects between Rust's two
CSPRNG sources; the other languages each have a single canonical CSPRNG, so
there is nothing for such a knob to choose.

Eight ports (Rust, Go, C, C++, Zig, Java, Python, Haskell) run their own
from-scratch cipher (natively compiled everywhere but Python, whose cipher is
interpreted pure Python) and stream in constant memory. The TypeScript port is one codebase run two ways:
**Node** (a CLI, with locked secret memory) and **Browser** (the in-page demo);
both run the verified Rust cipher compiled to WASM and work in memory.

## At a glance

| Implementation | Role / frontends | Cipher engine | KDFs | Streaming | Secret memory |
| --- | --- | --- | --- | --- | --- |
| **Rust** | Reference; CLIs + 2 GUIs | native | `argon2`/`scrypt`/`pbkdf2` crates | Yes | `zeroize` (wiped on drop); CLI and `dorado-gui` mlock password |
| **Go** | Port; CLIs | native | `golang.org/x/crypto` + stdlib | Yes | engine wipes keys; CLI mlocks password (off-heap) |
| **C** | Port; CLIs | native | system `libargon2` + OpenSSL | Yes | engine wipes keys; CLI mlocks password |
| **C++** | Port; CLIs | native | OpenSSL `EVP_KDF` (argon2/scrypt/pbkdf2) | Yes | engine wipes keys; CLI mlocks password |
| **Zig** | Port; CLIs | native | Zig stdlib (no external deps) | Yes | engine wipes keys; CLI mlocks password |
| **Java** | Port; SDK only | native | Bouncy Castle | Yes | caller-managed; engine best-effort wipes its keymat |
| **Python** | Port; CLIs | native | `argon2-cffi` + `hashlib` | Yes | caller-managed (`bytes` immutable) |
| **Haskell** | Port; CLIs | native | `crypton` (argon2/scrypt/pbkdf2) | Yes | caller-managed (GC; no wipe) |
| **TypeScript · Node** | Port; CLIs | WASM (Rust cipher) | `hash-wasm` (WASM) | No (in-memory) | `sodium-native` locked buffers (fail-closed) |
| **TypeScript · Browser** | In-page demo | WASM (Rust cipher) | `hash-wasm` (WASM) | No (in-memory) | none (demo, not secure) |

Three more axes are not columns above. **`no_std` / bare-metal:** the from-scratch
cipher primitives (Threefish/CTR, Skein, BLAKE3) build with no OS and no allocator
in **Rust, C, and Zig** (CI cross-compiles them to a bare-metal ARM target); the
construction (whose KDFs need an allocator) is not bare-metal, and Go, Java, Python,
Haskell, and TypeScript require a managed runtime. C++ is natively compiled like those
three but has no wired bare-metal build here. **Constant time:** only Rust documents and
preserves a full no-secret-dependent-branching discipline; every other port at least
uses a constant-time tag compare, and the cipher is ARX (no secret-dependent table
lookups) everywhere, but JIT/interpreted runtimes cannot promise constant time.
**Memory safety** is why Rust is the strongest tier overall (not the wipe/lock
mechanism, which C and Zig match): a use-after-free or buffer overrun can leak a
secret, and only Rust *prevents* those at compile time (with `#![forbid(unsafe_code)]`).
Zig *detects* the common classes at runtime when built `ReleaseSafe` (its release
default here: bounds, integer-overflow, and alignment checks stay in the binary), but
has no borrow checker, so general use-after-free is not caught. C and C++ rely on
external sanitizers (ASan/UBSan in CI), which detect bugs only on the paths a test
exercises.
Go and the managed runtimes are memory-safe but pay for it elsewhere (the GC is what
makes Go's wipe a convention rather than a guarantee).

HMAC-SHA256 uses each ecosystem's standard library (RustCrypto, Go stdlib, the JDK,
Python `hmac`, OpenSSL, Zig stdlib, Web Crypto), except the Haskell and C++ ports, which
implement SHA-256 and HMAC-SHA256 from scratch; Skein-512 and keyed BLAKE3 are
from-scratch everywhere. Each port is verified with KATs and committed cross-compat
fixtures produced by the Rust CLI, and the Rust suite decrypts a committed container
produced by each of the other eight ports. Rust adds differential tests; Rust, C,
and C++ carry libFuzzer/cargo-fuzz harnesses for the decrypt path (Go, TypeScript,
Java, and Python run deterministic randomized fuzz-style tests in their suites;
Zig and Haskell have neither); C and C++ also run under ASan/UBSan in CI.

## Where they differ, and why it matters

- **Cipher engine.** Rust, Go, C, C++, Zig, Java, Python, and Haskell run their own
  from-scratch cipher (compiled in all but Python, whose cipher is interpreted).
  The TypeScript package has a swappable backend: a readable pure-TypeScript
  cipher (used by its test suite, and verified byte-identical to the WASM backend
  by a differential test) and the verified Rust cipher compiled to WASM. The
  Node CLI and the browser demo both run the WASM backend, so the secret arithmetic
  happens in WASM linear memory rather than scattered across short-lived JavaScript
  numbers.
- **Streaming.** The eight non-TypeScript ports process files chunk by chunk over
  reader/writer interfaces (constant memory). The TypeScript engine works in-memory
  over byte arrays, so its working set is the size of the file.
- **`no_std` / bare-metal.** The from-scratch cipher primitives build with no OS and
  no allocator in Rust, C, and Zig: Rust's cipher crate targets a bare-metal ARM
  build, C's primitives compile with `-ffreestanding` (`make freestanding`, and its
  CI additionally cross-compiles them to bare-metal ARM with `arm-none-eabi-gcc`), and
  Zig cross-compiles them to a bare-metal ARM object (`zig build freestanding`). In
  all three the construction (the KDFs need an allocator) is excluded. Go, Java,
  Python, Haskell, and TypeScript require a managed runtime; C++ is natively compiled
  but has no wired bare-metal build here.
- **Secret handling.** This is the sharpest difference, and the reason the browser
  is the weakest tier:
  - *Rust* wipes secret buffers and the cipher's key schedule on drop (`zeroize`,
    automatically on every path), and its CLI `mlock`s the password buffer out of
    swap (via the `region` crate, so `#![forbid(unsafe_code)]` still holds). The
    `dorado-gui` holds the typed password in rime's `secure_input` buffer, which
    is fixed-capacity (never reallocated, so no `realloc` leaves a stale copy),
    `mlock`'d out of swap best-effort, and zeroized on drop. Because `mlock` acts
    on whole pages, that buffer sits in a page-aligned window no other allocation
    shares. The widget edits it in place and emits only unit messages, so unlike
    iced's own `text_input` the password never enters the message queue, the
    widget tree, or the text shaper. What remains uncovered is outside the
    process or upstream of the widget: the OS keyboard/IME path, the winit event
    struct that briefly holds each typed character, and a paste source's own copy
    in the system clipboard. `gyotaku-gui` handles no secrets.
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
  - *Java* leaves the lifetime of caller-supplied secrets to the caller, but its
    engine best-effort wipes its internal key material (`Arrays.fill` in `finally`
    blocks; the JVM's GC may still have copied the bytes, so this is hygiene, not
    a guarantee). *Python* leaves secret lifetimes to the caller and does not wipe
    (Python `bytes` are immutable, so they cannot even be wiped in place).
  - *Haskell* is caller-managed like Java and Python: secrets live in GC-managed
    `ByteString`s that are not wiped, and the CLI does not `mlock` the password.
  - *C++* wipes the derived keys and the cipher's expanded key schedule, and its CLI
    holds the password in a page-aligned, `mlock`'d buffer kept out of swap. The wipe
    runs automatically on every exit path: the `Threefish` schedule in its destructor,
    the derived keys via a scope guard, the C++ analogs of C's `cleanup` attribute. The
    clear is a non-elidable volatile-write wipe (the standard forbids optimizing volatile
    stores away), the portable analog of C/Zig's `OPENSSL_cleanse`/`secureZero`. C++ is
    not memory-safe (like C); CI reruns its tests under ASan/UBSan (`-DSANITIZE=ON`)
    and a libFuzzer harness for the decrypt path builds with `-DFUZZ=ON` (Clang), but
    sanitizers only catch bugs on exercised paths, so a bug elsewhere could still
    expose a secret.
  - *TypeScript on Node* holds CLI-held passwords and raw keys in `sodium-native`
    locked, off-heap, guard-paged buffers and wipes them after use, and is
    fail-closed: if `sodium-native` cannot load, the CLI errors out unless
    `--insecure-memory` is passed (which prints a one-time warning). An
    interactively typed password still transits an immutable JS string before it
    enters the locked buffer. The WASM backend keeps the cipher's transient
    values off the JavaScript heap.
  - *TypeScript in the browser* gets the WASM off-heap transients but has no locked
    memory, no wipe guarantee, and a password that arrives as an un-wipeable
    JavaScript string. It is a demo, not a secure tool.
- **KDF dependencies.** The KDFs are the one part no port reimplements from scratch.
  Each delegates to its ecosystem's library; Zig is the only one that needs nothing
  external, since Argon2id, scrypt, and PBKDF2 are in its standard library.

None of this is a security claim for any implementation. Dorado is educational and
unaudited; for real data, prefer an audited tool. The point of the table is to be
precise about what each version does and does not provide.
