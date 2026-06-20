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
  `NULL` or a static error string. `make test` (KATs + cross-compat fixtures from
  the Rust CLI, also run under ASan/UBSan). Needs `libargon2` + OpenSSL installed
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
`python/`, `c/`, and `zig/` in sync or cross-compatibility breaks. The eight
implementations are byte-for-byte cross-compatible and that property is tested. The
Rust implementation is the reference and the baseline for vectors and fixtures.

CI lives at the repo root in `.github/workflows/ci.yml`. The root `LICENSE` (MIT)
covers the whole repository.

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
- Update the changelog as you go: any change worth noting adds a bullet to the
  `Unreleased` section of `CHANGELOG.md` (grouped under Added / Changed / Fixed /
  Removed) in the same commit or PR. Call out wire-format/algorithm changes explicitly.
