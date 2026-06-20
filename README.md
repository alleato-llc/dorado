# dorado

Dorado is a from-scratch, educational implementation of Threefish, the tweakable
block cipher at the core of the Skein hash function, with a small tool stack built
on top of it (KDFs, an authenticated chunked container, a CLI, a GUI, and a
standalone Skein hashing tool). It is unaudited; for real data, prefer an audited
crate.

This repository is a modular monorepo:

- **[`rust/`](rust/)** — the primary implementation: a Cargo workspace with the
  cipher and primitives library, the construction engine, and the frontends (the
  `dorado` CLI, the `dorado-gui` app, and the `gyotaku` Skein hashing tool). Start
  with [`rust/README.md`](rust/README.md); design docs are in [`rust/docs/`](rust/docs/).
- **[`go/`](go/)** — a Go port that matches the Rust implementation: the same
  from-scratch primitives against the same vectors, the same on-disk format, and
  the same CLIs (no GUI). See [`go/README.md`](go/README.md).
- **[`ts/`](ts/)** — a TypeScript port that runs in Node and the browser: the same
  primitives and format, the same CLIs, and the engine behind the in-browser demo.
  Its cipher backend is swappable, so it runs either the readable pure-TS code or
  the verified Rust cipher compiled to WASM. See [`ts/README.md`](ts/README.md).
- **[`rust/wasm/`](rust/wasm/)** — the verified Rust cipher compiled to WebAssembly
  via `wasm-bindgen`. The same `.wasm` is the cipher backend for the `ts/` Node CLI
  and the browser demo, so the secret arithmetic runs in WASM linear memory rather
  than on the JS heap.
- **[`web/`](web/)** — the landing page that advertises the app, an
  [Astro](https://astro.build/) site with an in-browser encrypt/decrypt demo. See
  [`web/README.md`](web/README.md).

The four implementations share one on-disk format and are byte-for-byte
cross-compatible: each can decrypt the others' `.mahi` files, verified across every
KDF, MAC, and cipher variant. They differ in what their runtime allows (frontends,
streaming, `no_std`, secret-memory protection); [`docs/implementations.md`](docs/implementations.md)
compares them side by side.

## Quick start

```
# The Rust tools
cd rust
cargo build --release --workspace
cargo test --workspace

# The TypeScript port and CLIs
cd ts
npm install
npm test

# The landing page (with the in-browser demo)
cd web
npm install
npm run dev
```

The browser demo needs the WASM cipher built first; see [`web/README.md`](web/README.md).

## Continuous integration

CI lives at the repository root in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
It runs the Rust jobs (fmt, clippy, test, and `cargo audit`) from `rust/` and builds
the `web/` site.

## License

Licensed under the MIT License (SPDX `MIT`). See [`LICENSE`](LICENSE).
