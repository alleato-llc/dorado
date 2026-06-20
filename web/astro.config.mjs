// @ts-check
import { defineConfig } from "astro/config";
import preact from "@astrojs/preact";
import { fileURLToPath } from "node:url";

// The in-browser demo reuses the TypeScript engine from the sibling `ts/` package
// (imported as `@ts/...`) and the browser WASM build of the verified Rust cipher
// vendored in `src/wasm/`. Allow Vite to read the sibling package during dev.
const tsSrc = fileURLToPath(new URL("../ts/src", import.meta.url));
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
// The engine's only runtime npm dependency is `hash-wasm` (the KDFs). It is
// imported from `../ts/src`, so alias it to web's own copy; that keeps the site
// buildable from `web/` alone (CI and static hosts install only `web/`), without
// needing `ts/`'s node_modules present.
const hashWasm = fileURLToPath(new URL("./node_modules/hash-wasm", import.meta.url));

// When a repo doc (docs/glossary.md) is rendered as a page, its relative links to
// other docs (e.g. `../rust/docs/overview.md`, `spec.md`) would 404 on the site.
// Rewrite relative `.md` links to point at the file on GitHub instead. Paths are
// resolved relative to `docs/`, where the rendered markdown lives. No dependency:
// this walks the hast tree directly rather than pulling in unist-util-visit.
const REPO_BLOB = "https://github.com/nycjv321/dorado/blob/main";
function rehypeDocLinks() {
  const walk = (node) => {
    if (node.tagName === "a" && typeof node.properties?.href === "string") {
      const href = node.properties.href;
      if (href.endsWith(".md") && !/^https?:/.test(href)) {
        const rel = href.startsWith("../") ? href.slice(3) : `docs/${href}`;
        node.properties.href = `${REPO_BLOB}/${rel}`;
      }
    }
    for (const child of node.children ?? []) walk(child);
  };
  return (tree) => walk(tree);
}

export default defineConfig({
  integrations: [preact()],
  markdown: { rehypePlugins: [rehypeDocLinks] },
  // Emit flat files (about.html, not about/index.html) so extensionless URLs
  // resolve cleanly on static hosts that append `.html`.
  build: { format: "file" },
  vite: {
    resolve: { alias: { "@ts": tsSrc, "hash-wasm": hashWasm } },
    server: { fs: { allow: [repoRoot] } },
  },
});
