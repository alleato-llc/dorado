# CLAUDE.md

This is the dorado monorepo. It has two parts, each with its own `CLAUDE.md` that
carries the real detail:

- `rust/` — the Cargo workspace (the Threefish cipher, the primitives library, the
  construction engine, and the `dorado` / `dorado-gui` / `gyotaku` frontends). All
  Rust work, invariants, and verification steps are in `rust/CLAUDE.md`. Run cargo
  from inside `rust/`.
- `web/` — the Astro landing page that advertises the app. Site conventions are in
  `web/CLAUDE.md`. Run npm from inside `web/`.

CI for both lives at the repo root in `.github/workflows/ci.yml`. The root
`LICENSE` (MIT) covers the whole repository.

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
