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
  with [`rust/README.md`](rust/README.md); the Rust-flavored conceptual tour is
  [`rust/docs/overview.md`](rust/docs/overview.md).
- **[`go/`](go/)** — a Go port that matches the Rust implementation: the same
  from-scratch primitives against the same vectors, the same on-disk format, and
  the same CLIs (no GUI). See [`go/README.md`](go/README.md).
- **[`ts/`](ts/)** — a TypeScript port that runs in Node and the browser: the same
  primitives and format, the same CLIs, and the engine behind the in-browser demo.
  Its cipher backend is swappable, so it runs either the readable pure-TS code or
  the verified Rust cipher compiled to WASM. See [`ts/README.md`](ts/README.md).
- **[`java/`](java/)** — a Java port, an SDK only (no CLI, no GUI): the same
  primitives and format, streaming in constant memory like the Rust reference, with
  KDFs via Bouncy Castle and a comprehensive JUnit suite. See
  [`java/README.md`](java/README.md).
- **[`python/`](python/)** — a Python port: the same primitives and format,
  streaming in constant memory, with an SDK and the `dorado`/`gyotaku` CLIs. KDFs
  use `argon2-cffi` + `hashlib`; tested with pytest. See
  [`python/README.md`](python/README.md).
- **[`c/`](c/)** — a C port (C17): the same primitives and format, streaming in
  constant memory, with an SDK (`libdorado.a`) and the `dorado`/`gyotaku` CLIs. KDFs
  link the system `libargon2` and OpenSSL via `pkg-config`. See
  [`c/README.md`](c/README.md).
- **[`zig/`](zig/)** — a Zig port (Zig 0.16): the same primitives and format,
  streaming in constant memory, with an SDK and the `dorado`/`gyotaku` CLIs. No
  external library: the KDFs come from Zig's standard library. See
  [`zig/README.md`](zig/README.md).
- **[`rust/wasm/`](rust/wasm/)** — the verified Rust cipher compiled to WebAssembly
  via `wasm-bindgen`. The same `.wasm` is the cipher backend for the `ts/` Node CLI
  and the browser demo, so the secret arithmetic runs in WASM linear memory rather
  than on the JS heap.
- **[`web/`](web/)** — the landing page that advertises the app, an
  [Astro](https://astro.build/) site with an in-browser encrypt/decrypt demo. See
  [`web/README.md`](web/README.md).
- **[`bench/`](bench/)** — cross-language throughput benchmarks of the from-scratch
  primitives, one small runner per language under a uniform protocol. `python3
  bench/run.py` builds and runs them all and writes a committed `RESULTS.md`; `python3
  bench/report.py` renders an HTML report. The scaffolding is
  [Gota](https://github.com/alleato-llc/gota), a standalone micro-benchmark reference
  that `bench/` consumes. See [`bench/README.md`](bench/README.md).

The eight implementations share one on-disk format and are byte-for-byte
cross-compatible: each can decrypt the others' `.mahi` files, verified across every
KDF, MAC, and cipher variant. They differ in what their runtime allows (frontends,
streaming, `no_std`, secret-memory protection); [`docs/implementations.md`](docs/implementations.md)
compares them side by side. The project-wide docs live in [`docs/`](docs/): the
shared wire format ([`spec.md`](docs/spec.md)), a [`glossary.md`](docs/glossary.md),
and the [implementations](docs/implementations.md) comparison. The Rust-flavored
conceptual tour stays in [`rust/docs/overview.md`](rust/docs/overview.md).

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

## Changelog and versions

dorado is versioned **per component**: each port (and `bench/`, `web/`) carries its own
[semantic version](https://semver.org/) and changelog, and the on-disk container format
has its own version. [`VERSIONS.md`](VERSIONS.md) is the master table. The top-level
[`CHANGELOG.md`](CHANGELOG.md) is the Core log (project-wide docs, CI, cross-port
decisions); per-port history lives in each `<port>/CHANGELOG.md`. All use the
[Keep a Changelog](https://keepachangelog.com/) format.

**Rule:** route each change to the changelog of whatever it touches (a port vs. Core),
in the same commit or PR; a cross-port decision is recorded once in Core and pointed to
from each port. Wire-format or algorithm changes must say so, since they affect
cross-compatibility across the ports.

## License

Licensed under the MIT License (SPDX `MIT`). See [`LICENSE`](LICENSE).
