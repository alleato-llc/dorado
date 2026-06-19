# dorado

Dorado is a from-scratch, educational implementation of Threefish, the tweakable
block cipher at the core of the Skein hash function, with a small tool stack built
on top of it (KDFs, an authenticated chunked container, a CLI, a GUI, and a
standalone Skein hashing tool). It is unaudited; for real data, prefer an audited
crate.

This repository is a modular monorepo with two parts:

- **[`rust/`](rust/)** — the Cargo workspace: the cipher and primitives library,
  the construction engine, and the frontends (the `dorado` CLI, the `dorado-gui`
  app, and the `gyotaku` Skein hashing tool). Start with [`rust/README.md`](rust/README.md);
  design docs are in [`rust/docs/`](rust/docs/).
- **[`web/`](web/)** — the landing page that advertises the app, an
  [Astro](https://astro.build/) site. See [`web/README.md`](web/README.md).

## Quick start

```
# The Rust tools
cd rust
cargo build --release --workspace
cargo test --workspace

# The landing page
cd web
npm install
npm run dev
```

## Continuous integration

CI lives at the repository root in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
It runs the Rust jobs (fmt, clippy, test, and `cargo audit`) from `rust/` and builds
the `web/` site.

## License

Licensed under the MIT License (SPDX `MIT`). See [`LICENSE`](LICENSE).
