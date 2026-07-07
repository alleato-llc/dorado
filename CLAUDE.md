# CLAUDE.md

This is the dorado monorepo. It has several parts:

- `rust/` — the primary implementation: a Cargo workspace (the Threefish cipher,
  the primitives library, the construction engine, and the `dorado` / `dorado-gui`
  / `gyotaku` / `gyotaku-gui` frontends). All Rust work, invariants, and
  verification steps are in `rust/CLAUDE.md`. Run cargo from inside `rust/`.
- `go/` — a Go port (module `github.com/alleato-llc/dorado/go`) that mirrors the
  Rust implementation: same from-scratch primitives, same on-disk format
  (byte-for-byte cross-compatible, verified by decrypting each other's files),
  same CLIs, no GUI. Interop is via stdlib interfaces (`cipher.Block`,
  `cipher.AEAD`, `hash.Hash`). Run go from inside `go/`. When changing the wire
  format or an algorithm, keep `rust/` and `go/` in sync or cross-compatibility
  breaks.
- `ts/` — a TypeScript port (package `@dorado/ts`) that runs in Node and the
  browser: same from-scratch primitives, same on-disk format (cross-compatible
  with `rust/` and `go/`), same CLIs, no GUI. The 64-bit ARX uses `BigInt`; KDFs
  use `hash-wasm`; HMAC uses Web Crypto. The cipher backend is swappable
  (`src/engine/backend.ts`): the default `tsBackend` is the readable pure-TS code
  (used by the test suite), and `wasmBackend` runs the verified Rust cipher from
  WASM. The Node CLI uses `wasmBackend`. Run npm from inside `ts/`.
- `java/` — a Java port (Gradle, package `com.alleato.dorado`) that is an SDK only,
  no CLI and no GUI: same from-scratch primitives, same on-disk format
  (cross-compatible with the others), streaming over `InputStream`/`OutputStream` in
  constant memory like the Rust reference. Java's `long` makes the 64-bit ARX
  native (no `BigInt`). KDFs (Argon2id, scrypt, PBKDF2) use Bouncy Castle; HMAC uses
  the JDK. Comprehensive JUnit suite, including cross-compat fixtures made by the
  Rust CLI in `src/test/resources/`. Run `./gradlew test` from inside `java/`.
- `python/` — a Python port (package `dorado`, `src/` layout) with an SDK and the
  `dorado`/`gyotaku` CLIs: same from-scratch primitives, same on-disk format
  (cross-compatible), streaming over binary file-like objects in constant memory
  like the Rust reference. The 64-bit ARX uses arbitrary-precision ints masked to
  2**64. Argon2id uses `argon2-cffi`; scrypt and PBKDF2 use `hashlib`; HMAC uses
  `hmac`. pytest suite with cross-compat fixtures made by the Rust CLI in
  `tests/fixtures/`. Run `pytest` from inside `python/` (in a venv with `pip install
  -e ".[dev]"`).
- `c/` — a C port (C17) with an SDK (`libdorado.a`) and the `dorado`/`gyotaku`
  CLIs: same from-scratch primitives, same on-disk format (cross-compatible),
  streaming over `FILE *` in constant memory like the Rust reference. The KDFs are
  delegated to system libraries (no vendoring): Argon2id from `libargon2`,
  scrypt/PBKDF2/HMAC from OpenSSL, both via `pkg-config`. Engine functions return
  `NULL` or a static error string (with stable `dorado_err_auth`/`_malformed`/`_params`
  sentinels a caller can classify by pointer; wrong-password and tampering stay merged
  into `dorado_err_auth`). `make test` (KATs + cross-compat fixtures from the Rust CLI,
  plus a randomized decrypt "smash" pass); CI reruns it under ASan/UBSan via `make test
  SAN=1`, and `make fuzz` builds a libFuzzer harness for the decrypt path. Needs
  `libargon2` + OpenSSL installed
  (`brew install argon2 openssl@3` / `apt-get install libargon2-dev libssl-dev`).
- `zig/` — a Zig port (Zig 0.16) with an SDK and the `dorado`/`gyotaku` CLIs: same
  from-scratch primitives, same on-disk format (cross-compatible), streaming over a
  Reader/Writer callback interface in constant memory like the Rust reference (the
  CLIs wire it to `std.Io.File`). Zig's native `u64` makes the ARX direct. No
  external library: the KDFs come from `std.crypto.pwhash` (Argon2id, scrypt,
  PBKDF2) and HMAC from `std.crypto.auth.hmac`. `engine` functions return a Zig
  error set. `zig build test` runs the suite, including cross-compat fixtures made
  by the Rust CLI in `tests/fixtures/` (embedded via `@embedFile`). Run `zig build`
  from inside `zig/`.
- `haskell/` — a Haskell port (Cabal, package `dorado`) with an SDK and the
  `dorado`/`gyotaku` CLIs: same from-scratch primitives, same on-disk format
  (cross-compatible), streaming over `Handle`s in constant memory like the Rust
  reference. Strict throughout (no laziness in the hot path): the primitive cores
  run in `ST` over unboxed mutable arrays, with `IO` only at the streaming
  boundary; Haskell's native `Word64` makes the 64-bit ARX direct. The KDFs are
  delegated to `crypton` (Argon2id, scrypt, PBKDF2), matching the other ports' use
  of a KDF library; HMAC/SHA-256/Skein/BLAKE3 are from scratch. `cabal test` runs
  the suite, including cross-compat fixtures made by the Rust CLI in
  `test/fixtures/`. Run cabal from inside `haskell/`.
- `cpp/` — a C++ port (CMake, C++23) with an SDK (`libdorado.a`) and the
  `dorado`/`gyotaku` CLIs: same from-scratch primitives, same on-disk format
  (cross-compatible), streaming over `std::istream`/`std::ostream` in constant memory
  like the Rust reference (the in-memory byte APIs wrap the streaming core via
  `std::stringstream`). C++'s native `std::uint64_t` makes the 64-bit ARX direct;
  engine results are `std::expected<T, std::string>`. SHA-256 + HMAC are from scratch
  alongside the cipher/Skein/BLAKE3; only the three password KDFs (Argon2id, scrypt,
  PBKDF2) are delegated, to OpenSSL's `EVP_KDF` (OpenSSL >= 3.2, the sole dependency).
  `ctest` (or `./build/dorado_test`) runs the suite, including cross-compat fixtures
  made by the Rust CLI in `tests/fixtures/`; CI reruns it under ASan/UBSan via a second
  `-DSANITIZE=ON` build, and `-DFUZZ=ON` (Clang only) builds a libFuzzer harness for the
  decrypt path. Run cmake from inside `cpp/`.
- `rust/wasm/` — the verified Rust cipher compiled to WebAssembly via
  `wasm-bindgen` (a separate crate, excluded from the `rust/` workspace). It exports
  only the cipher/hash primitives (CTR, Skein, BLAKE3), not the engine; the engine
  stays in `ts/`. Build with `wasm-pack build --target nodejs` (for `ts/`) or
  `--target web` (for the browser demo). Never reimplement cipher logic here; it is
  a thin binding over `crates/dorado`.
- `web/` — the Astro landing page that advertises the app, with an in-browser
  encrypt/decrypt demo built on `ts/` + the browser WASM build. Site conventions
  are in `web/CLAUDE.md`. Run npm from inside `web/`.
- `bench/` — cross-language throughput benchmarks of the from-scratch primitives. One
  small native runner per language (in `bench/<lang>/`) under a uniform protocol
  (peak throughput over batches, MB/s). The scaffolding is Gota
  (github.com/alleato-llc/gota), a standalone cross-language micro-benchmark reference;
  `bench/` is a consumer. `bench/harness.py` (the generic orchestrator), `bench/report.py`
  + `bench/report_template.html` (the HTML report) are copies from Gota and carry a note
  saying so: do not edit them in place, change them in Gota and re-copy. The
  dorado-specific parts are ours to edit: `bench/run.py` (which runners, the labels, the
  framing) and the per-language `runner` sources. `run.py` writes `results.json` +
  `RESULTS.md`; `report.py` writes `report.html`. KDFs are deliberately out of scope
  (delegated libraries). The committed results are a snapshot from one stated machine,
  not from CI. Benchmarks the implementations only; never put fabricated numbers here.

When changing the wire format or an algorithm, keep `rust/`, `go/`, `ts/`, `java/`,
`python/`, `c/`, `zig/`, `haskell/`, and `cpp/` in sync or cross-compatibility breaks.
The ten implementations are byte-for-byte cross-compatible and that property is tested.
The Rust implementation is the reference and the baseline for vectors and fixtures.

CI lives at the repo root in `.github/workflows/ci.yml`. It is path-filtered: a
`changes` job detects which component folders moved and each job runs only when
relevant, but a change to the wire-format spec (`docs/spec.md`) or to the workflow
re-runs every port's cross-compat suite. The root `LICENSE` (MIT) covers the whole
repository.

## Conventions (whole repo)

- No em dashes anywhere.
- No fabricated metrics, benchmarks, or statistics. If a number cannot be measured
  or verified, leave it out.
- Direct prose, minimal formatting, no marketing tone (the landing page may be
  persuasive, but stays truthful: no invented benchmarks, no "production-ready" or
  "secure" claims, since the project is educational and unaudited).
- Keep changes scoped to what is asked.
- Do not add dependencies without asking first.
- Be honest about limitations rather than papering over them.
- Update the changelog as you go, routed by what you touched. Versioning is
  per-component (see `VERSIONS.md`): a change to a single port goes in that port's
  `<port>/CHANGELOG.md` (likewise `bench/` and `web/`); a project-wide doc, CI, or a
  cross-port decision goes in the top-level `CHANGELOG.md` (Core); a wire-format change
  is a coordinated `format::VERSION` bump recorded in Core and every port's changelog.
  A cross-port decision is recorded once in Core and pointed to from each port's log
  (do not duplicate the rationale across ports). Add the bullet under Added / Changed /
  Fixed / Removed in the same commit or PR, and call out wire-format/algorithm changes
  explicitly.
