# dorado (C++)

A C++ port of dorado (C++23), matching the Rust reference (`../rust`) and the other
ports. Same from-scratch primitives against the same official vectors, the same
on-disk container format (byte-for-byte cross-compatible), the same CLIs, and the
same streaming construction. A static library (`libdorado.a`) plus the two
command-line tools.

Like the Rust reference, it **streams** over `std::istream`/`std::ostream` in
constant memory (files larger than RAM are fine); in-memory wrappers (over
`std::stringstream`) are provided, so the streaming logic lives in one place. The
cipher, the Skein/BLAKE3 hashes, and **SHA-256 + HMAC** are all from scratch; only
the three password KDFs (Argon2id, scrypt, PBKDF2) are delegated, to OpenSSL's
`EVP_KDF`. Educational and unaudited.

## Layout

- `include/dorado/` — the public headers: `threefish.hpp`, `skein.hpp`,
  `blake3.hpp`, `sha256.hpp`, `mac.hpp`, `kdf.hpp`, `format.hpp`, `engine.hpp`.
- `src/threefish.cpp`, `skein.cpp`, `blake3.cpp`, `sha256.cpp` — the from-scratch
  primitives (incremental Skein/BLAKE3 hashers included for streaming).
- `src/mac.cpp`, `kdf.cpp`, `format.cpp`, `engine.cpp` — the construction: the MAC
  menu, the OpenSSL-delegated KDFs, the container header, and the streaming password
  container, raw CTR (bare and authenticated), and inspect. Engine results are `std::expected<T, std::string>`;
  the KDF layer throws `std::runtime_error`.
- `src/cli_dorado.cpp`, `src/cli_gyotaku.cpp` — the two CLIs.

## Build

OpenSSL >= 3.2 is the only dependency (it supplies Argon2id, scrypt, and PBKDF2 via
`EVP_KDF`):

```
# macOS
brew install openssl@3 cmake
# Debian/Ubuntu
sudo apt-get install -y libssl-dev cmake

cmake -S . -B build      # configure (Release by default)
cmake --build build      # builds libdorado.a, dorado, gyotaku, dorado_test
```

## Use

SDK:

```cpp
#include <dorado/engine.hpp>
using namespace dorado;

engine::Options opts = engine::default_options();   // Threefish-256, Argon2id, Skein-512
std::vector<std::uint8_t> ct = engine::encrypt_password(opts, tweak, password, plaintext);
std::expected<std::vector<std::uint8_t>, std::string> pt =
    engine::decrypt_password(password, ct);

// or stream in constant memory:
engine::encrypt_password_stream(opts, salt, tweak, iv, password, in, out);
```

CLI:

```
dorado encrypt --password-stdin --in notes.txt --out notes.txt.mahi
gyotaku --bits 256 notes.txt
```

## Testing

```
ctest --test-dir build           # or run ./build/dorado_test directly
```

The suite covers the primitive KATs (the Crypto++ Threefish vectors, RFC 8439/FIPS
SHA-256, RFC 4231 HMAC, RFC 7914 scrypt, PBKDF2), every MAC and variant, the
incremental hashers, and cross-compat fixtures produced by the Rust CLI (every
KDF/MAC/variant plus a labeled and a multi-frame file), with wrong-password and
tamper rejection and round-trips across variants/MACs/chunk sizes/empty input. The
test runs from the source dir so the committed fixtures resolve.

## Cross-compatibility

The container bytes are identical to the other ports: each can decrypt the others'
`.mahi` files. The test decrypts fixtures produced by the Rust reference (in
`tests/fixtures/`); the reverse direction (the Rust CLI decrypting this port's
container, and matching `gyotaku` digests) is verified during development.

## Secret handling

The engine wipes the derived keys and the cipher's expanded key schedule on every
exit path: the `Threefish` schedule in its destructor and the derived keys via a
scope guard (the C++ analogs of C's `cleanup` attribute). The clear is a
non-elidable volatile-write `secure_wipe`, the portable analog of `OPENSSL_cleanse`.
The CLI holds the password in a page-aligned, `mlock`'d buffer kept out of swap and
wiped on free (`mlock` is best-effort: skipped without error if `RLIMIT_MEMLOCK`
forbids it). This reduces exposure but is not a guarantee: the password still transits
stdin first, C++ is not memory-safe, and (unlike the C port) no sanitizer or fuzz
harness is wired yet. Educational and unaudited.
