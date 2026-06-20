# dorado web

The landing page that advertises dorado. A static [Astro](https://astro.build/)
site with a Preact theme toggle, mirroring the setup of the sibling `soroban`
project's site. It also hosts an in-browser encrypt/decrypt demo.

## Develop

```
npm install
npm run dev      # local dev server
npm run build    # static output to dist/
npm run preview  # serve the built dist/
```

## The in-browser demo

`src/components/Demo.tsx` is a Preact island that encrypts a message to a password
container and decrypts it back, entirely client-side. It reuses the TypeScript
engine from the sibling `../ts` package (imported as `@ts/...`, aliased in
`astro.config.mjs`) on top of the verified Rust cipher compiled to WebAssembly. The
browser WASM build is vendored in `src/wasm/` so the site builds without a Rust
toolchain (CI and static hosts need no `wasm-pack`). Regenerate it after changing
the cipher:

```
npm run build:wasm   # needs wasm-pack + the Rust toolchain; rebuilds src/wasm/
```

The container bytes the demo produces are byte-for-byte identical to the CLIs', so
a file encrypted in the browser decrypts with `dorado decrypt` and vice versa. The
demo uses deliberately low KDF cost parameters for speed; it is an illustration,
not a secure tool.

## Layout

- `src/pages/` — one `.astro` file per route (`index.astro` is the home page).
- `src/layouts/Layout.astro` — the shared shell (head, header, footer, theme
  bootstrap).
- `src/components/` — Preact/Astro components (the theme toggle and the demo).
- `src/lib/backend.ts` — the browser cipher backend (loads `src/wasm/`).
- `src/wasm/` — the vendored browser build of the Rust cipher (regenerate with
  `npm run build:wasm`).
- `src/styles/global.css` — the two-theme design system (light / dark via the
  `data-theme` attribute).
- `public/` — static assets served as-is (favicon, images).

The copy is kept truthful: dorado is educational and unaudited, so the site makes
no security or production-readiness claims and uses no invented benchmarks. Update
the `REPO` constant in `src/pages/index.astro` once the repository URL is final.
