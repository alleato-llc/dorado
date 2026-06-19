# CLAUDE.md

This is the `web/` part of the dorado monorepo: the marketing landing page. The
Rust workspace it advertises is in `../rust/` (see `../rust/CLAUDE.md`).

## What this is

A static [Astro](https://astro.build/) 5 site with the `@astrojs/preact`
integration and TypeScript, deliberately mirroring the sibling `soroban` project's
site setup (same stack, same theme-toggle pattern) so the two stay consistent.

- `astro.config.mjs` sets `build: { format: "file" }` so routes emit flat
  `name.html` files for static hosts.
- `src/layouts/Layout.astro` is the shared shell. An inline script resolves the
  theme before first paint: a stored choice (`localStorage["dorado-theme"]`) wins,
  otherwise it follows the system and keeps following it until the user picks.
- `src/components/ThemeToggle.tsx` is a Preact island (`client:load`) that flips
  and persists the theme.
- `src/styles/global.css` is the design system: two themes via the
  `data-theme` attribute on `:root`, with CSS custom properties. Light is warm
  sand and teal; dark is deep sea and aqua; a gold accent runs through both.
- `src/pages/` holds one file per route. `public/` is served as-is.

## Conventions

- No em dashes anywhere.
- The copy is persuasive but truthful. dorado is educational and unaudited, so do
  not claim it is secure, production-ready, or guaranteed constant-time, and do not
  invent benchmarks or statistics. This mirrors the Rust side's honesty rule.
- Keep the stack minimal: Astro + Preact + TypeScript. Do not add a UI framework
  or dependencies without asking first.
- `REPO` in `src/pages/index.astro` is the single source for the repository URL;
  update it there.

## Verify

```
npm install
npm run build
```

A successful `npm run build` (static output in `dist/`) is the check; CI runs it
from the repo-root workflow `../.github/workflows/ci.yml`.
