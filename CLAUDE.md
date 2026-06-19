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
- `web/` — the Astro landing page that advertises the app. Site conventions are in
  `web/CLAUDE.md`. Run npm from inside `web/`.

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
