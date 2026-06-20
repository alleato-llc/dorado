# dorado (C)

A C port of dorado (C17), matching the Rust reference (`../rust`) and the Go, Java,
Python, and TypeScript ports. Same from-scratch primitives against the same official
vectors, the same on-disk container format (byte-for-byte cross-compatible), the
same CLIs, and the same streaming construction. An SDK (`libdorado.a`) plus the two
command-line tools.

Like the Rust reference, it **streams** over `FILE *` in constant memory (files
larger than RAM are fine); in-memory wrappers (`fmemopen`/`open_memstream`) are
provided. The cipher and the Skein/BLAKE3 hashes are from scratch; the KDFs are
delegated to system libraries: **Argon2id from `libargon2`**, scrypt/PBKDF2/HMAC
from **OpenSSL**, both found via `pkg-config`. Educational and unaudited.

## Build

Install the two system libraries first, then `make`:

```
# macOS
brew install argon2 openssl@3
# Debian/Ubuntu
sudo apt-get install -y libargon2-dev libssl-dev pkg-config

make            # builds libdorado.a, dorado, gyotaku
make test       # builds and runs the test suite
make freestanding   # compiles the primitives with no OS / allocator
```

On macOS the Makefile adds the Homebrew `pkg-config` paths automatically.

## Secret handling and bare-metal

The engine wipes the derived keys and the cipher's expanded key schedule with
`OPENSSL_cleanse` (which the compiler cannot optimize away). The wipe runs
automatically on every exit path via `__attribute__((cleanup(...)))` (a GCC/Clang
extension, the C analog of Rust's `Drop` and Zig's `defer`), so a future early return
cannot forget it. The `dorado` CLI holds the password in a page-aligned, `mlock`'d
buffer kept out of swap and wiped on free. This is a reduction in exposure, not a
guarantee: the password still transits `argv`/stdin first, and `mlock` is best-effort
(skipped without error if `RLIMIT_MEMLOCK` forbids it). C is not memory-safe, so a
bug elsewhere could still expose a secret; the test suite runs under
AddressSanitizer and UndefinedBehaviorSanitizer to catch that class in CI.

The from-scratch primitives (Threefish/CTR, Skein, BLAKE3) depend on no allocator
and no OS, so `make freestanding` compiles them with `-ffreestanding` for a
bare-metal target, mirroring the Rust port's `no_std` cipher crate. The construction
(KDFs, container, CLIs) needs `malloc`/`FILE`/`libargon2`/OpenSSL and is not
bare-metal.

## Layout

- `include/dorado/` — the public headers: `threefish.h`, `skein.h`, `blake3.h`,
  `engine.h`.
- `src/threefish.c`, `skein.c`, `blake3.c` — the from-scratch primitives.
- `src/format.c`, `kdf.c`, `mac.c`, `engine.c` — the construction: the container
  header, the KDFs (libargon2 + OpenSSL), the MAC menu, and the streaming password
  container, raw CTR, and inspect. Functions return `NULL` on success or a static
  error string.
- `src/cli_dorado.c`, `src/cli_gyotaku.c` — the two CLIs.

## Use

```c
#include <dorado/engine.h>

dorado_options opts = dorado_default_options();   /* Threefish-256, Argon2id, Skein-512 */
uint8_t *ct; size_t ct_len;
const char *err = dorado_encrypt_password(pw, pw_len, &opts, pt, pt_len, &ct, &ct_len);
/* ... dorado_decrypt_password(...); free(ct); ... */

/* or stream in constant memory: */
dorado_encrypt_password_stream(pw, pw_len, &opts, stdin, stdout);
```

```
dorado encrypt --password-stdin --in notes.txt --out notes.txt.mahi
gyotaku --bits 256 notes.txt
```

## Cross-compatibility

The container bytes are identical to the other ports: each can decrypt the others'
`.mahi` files. `make test` decrypts fixtures produced by the Rust reference (in
`tests/fixtures/`) covering every KDF, MAC, and variant plus a labeled and a
multi-frame file; the reverse direction is verified during development. The test
suite is also run under AddressSanitizer and UndefinedBehaviorSanitizer.
