# Changelog - web

Changes to the **landing page only** (`web/`, the Astro site with the in-browser demo).
Cross-cutting changes live in the [Core CHANGELOG](../CHANGELOG.md);
[VERSIONS.md](../VERSIONS.md) is the master table. Site conventions are in
[web/CLAUDE.md](CLAUDE.md). Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Download the CLIs** section: `src/lib/releases.ts` resolves the Rust CLI
  track's newest `rust-v*` release into its four platform archive URLs at build
  time; `src/components/Download.tsx` (a `client:load` Preact island) picks the
  right button by the visitor's detected OS/arch, falling back to a full
  all-platforms list pre-hydration or with JS off. Mirrors soroban's
  `site/src/lib/releases.ts`. `deploy-site.yml` gains a `release: published`
  trigger so a new release redeploys the site with fresh links.

### Fixed

- `REPO` in `src/pages/index.astro` pointed at `nycjv321/dorado`; corrected to
  the actual `alleato-llc/dorado`. Fixes every source/docs link on the page.

### Changed

- The hero lead and the page meta description now reflect all eight implementations
  (Rust, Go, Java, Python, C, Zig, TypeScript). They previously named only "Rust, Go,
  and TypeScript", inconsistent with the "eight implementations" section.
- Added the Haskell port: the comparison table gains a Haskell row and the page now
  says "nine implementations" (hero, meta description, and the implementations
  section).
- Added the C++ port: the comparison table gains a C++ row (engine wipes keys; CLI
  mlocks the password) and the page now says "ten implementations". Reordered the
  comparison table and the prose enumerations to the native-first order shared with
  the sibling foxtrot site (Rust, Go, C, C++, Zig, Java, Python, Haskell, TypeScript).

## [0.1.0]

### Added

- Initial landing page: an Astro site advertising dorado, with an in-browser
  encrypt/decrypt demo built on the `ts/` port and the browser WASM cipher build.
