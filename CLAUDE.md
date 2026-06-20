# CLAUDE.md

This is the dorado monorepo. It has several parts:

- `rust/` — the primary implementation: a Cargo workspace (the Threefish cipher,
  the primitives library, the construction engine, and the `dorado` /
  `dorado-gui` / `gyotaku` frontends). All Rust work, invariants, and verification
  steps are in `rust/CLAUDE.md`. Run cargo from inside `rust/`.
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
- `rust/wasm/` — the verified Rust cipher compiled to WebAssembly via
  `wasm-bindgen` (a separate crate, excluded from the `rust/` workspace). It exports
  only the cipher/hash primitives (CTR, Skein, BLAKE3), not the engine; the engine
  stays in `ts/`. Build with `wasm-pack build --target nodejs` (for `ts/`) or
  `--target web` (for the browser demo). Never reimplement cipher logic here; it is
  a thin binding over `crates/dorado`.
- `web/` — the Astro landing page that advertises the app, with an in-browser
  encrypt/decrypt demo built on `ts/` + the browser WASM build. Site conventions
  are in `web/CLAUDE.md`. Run npm from inside `web/`.

When changing the wire format or an algorithm, keep `rust/`, `go/`, and `ts/` in
sync or cross-compatibility breaks. The four implementations are byte-for-byte
cross-compatible and that property is tested.

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
