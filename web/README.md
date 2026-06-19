# dorado web

The landing page that advertises dorado. A static [Astro](https://astro.build/)
site with a Preact theme toggle, mirroring the setup of the sibling `soroban`
project's site.

## Develop

```
npm install
npm run dev      # local dev server
npm run build    # static output to dist/
npm run preview  # serve the built dist/
```

## Layout

- `src/pages/` — one `.astro` file per route (`index.astro` is the home page).
- `src/layouts/Layout.astro` — the shared shell (head, header, footer, theme
  bootstrap).
- `src/components/` — Preact/Astro components (the theme toggle).
- `src/styles/global.css` — the two-theme design system (light / dark via the
  `data-theme` attribute).
- `public/` — static assets served as-is (favicon, images).

The copy is kept truthful: dorado is educational and unaudited, so the site makes
no security or production-readiness claims and uses no invented benchmarks. Update
the `REPO` constant in `src/pages/index.astro` once the repository URL is final.
