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
the three password KDFs (Argon2id, scrypt, PBKDF2) and the CSPRNG are delegated,
to OpenSSL (`EVP_KDF` and `RAND_bytes`). Educational and unaudited.

## Layout

- `include/dorado/` — the public headers: `threefish.hpp`, `skein.hpp`,
  `blake3.hpp`, `sha256.hpp`, `mac.hpp`, `kdf.hpp`, `format.hpp`, `engine.hpp`.
- `src/threefish.cpp`, `skein.cpp`, `blake3.cpp`, `sha256.cpp` — the from-scratch
  primitives (incremental Skein/BLAKE3 hashers included for streaming).
- `src/mac.cpp`, `kdf.cpp`, `format.cpp`, `engine.cpp` — the construction: the MAC
  menu, the KDF layer (the OpenSSL-delegated password KDFs plus the from-scratch
  key-based `derive_from_key`, with `kdf::validate` bounding untrusted costs), the
  container header, and the streaming password container, raw CTR (bare and
  authenticated), and inspect. Engine results are `std::expected<T, std::string>`;
  the password-KDF `derive` throws `std::runtime_error` on an OpenSSL failure.
- `src/cli_dorado.cpp`, `src/cli_gyotaku.cpp` — the two CLIs.

## Build

OpenSSL >= 3.2 is the only dependency (it supplies Argon2id, scrypt, and PBKDF2 via
`EVP_KDF`, and the CSPRNG via `RAND_bytes`):

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

// Fan an already high-entropy key out into independent per-purpose subkeys
// (fast, one keyed hash, no stretching -- never pass a password here):
std::vector<std::uint8_t> sub = kdf::derive_from_key(master, "myapp/index", 32);
// or pick the PRF (Skein-512 is the default; BLAKE3 needs a 32-byte key):
auto sub2 = kdf::derive_from_key_with(kdf::KdfPrf::Blake3, master, "myapp/index", 32);
```

Decryption treats the file header as untrusted: the KDF cost parameters are bounded
(`kdf::validate`) before any derivation, and the chunk size is capped before any
allocation: 64 MiB by default, with the `DORADO_MAX_CHUNK_BYTES` env var able to
lower or raise the cap, clamped to the 1 GiB hard ceiling (`engine::max_chunk_bytes`).

CLI:

```
dorado encrypt --password-stdin --in notes.txt --out notes.txt.mahi
gyotaku --bits 256 notes.txt
```

Raw-key mode (`--key`/`--key-file` with `--iv`) is authenticated (encrypt-then-MAC)
by default, so a tampered, corrupted, or wrong-key stream is rejected on decrypt;
`--mac` and `--chunk-kib` select its MAC and chunk size. `--unauthenticated` opts
back into bare CTR (no authentication, output length equals input length), an expert
opt-out. Password mode is always authenticated, and rejects `--unauthenticated`.

## Testing

```
ctest --test-dir build           # or run ./build/dorado_test directly
```

The suite covers the primitive KATs (the Crypto++ Threefish vectors, FIPS 180-4
SHA-256, RFC 4231 HMAC, RFC 7914 scrypt, PBKDF2), every MAC and variant, the
incremental hashers, and cross-compat fixtures produced by the Rust CLI (every
KDF/MAC/variant plus a labeled and a multi-frame file), with wrong-password and
tamper rejection and round-trips across variants/MACs/chunk sizes/empty input. It
also covers the untrusted-header bounds (hostile KDF costs and chunk sizes rejected
before any derivation or allocation, plus the pure chunk-cap resolution) and the
`derive_from_key` known-answer vectors from `../docs/fixtures/derive-from-key.md`.
The test runs from the source dir so the committed fixtures resolve.

Two hardening builds are wired as well: configuring with `-DSANITIZE=ON` rebuilds
the suite under ASan/UBSan (CI reruns `ctest` this way), and `-DFUZZ=ON` (Clang
only) builds a libFuzzer harness for the decrypt path (`fuzz/fuzz_decrypt.cpp`).

## Cross-compatibility

The container bytes are identical to the other ports: each can decrypt the others'
`.mahi` files. The test decrypts fixtures produced by the Rust reference (in
`tests/fixtures/`, covering every KDF, MAC, and variant); the reverse direction is
covered by a committed fixture in the Rust suite (the Rust CLI decrypts a container
encrypted by this port).

## Secret handling

The engine wipes the derived keys and the cipher's expanded key schedule on every
exit path: the `Threefish` schedule in its destructor and the derived keys via a
scope guard (the C++ analogs of C's `cleanup` attribute). The clear is a
non-elidable volatile-write `secure_wipe`, the portable analog of `OPENSSL_cleanse`.
The CLI holds the password in a page-aligned, `mlock`'d buffer kept out of swap and
wiped on free (`mlock` is best-effort: skipped without error if `RLIMIT_MEMLOCK`
forbids it). This reduces exposure but is not a guarantee: the password still transits
stdin first, and C++ is not memory-safe; the sanitizer rerun in CI and the libFuzzer
harness (see Testing) catch bugs only on the paths they exercise. Educational and
unaudited.
