// @ts-check
import { defineConfig } from "astro/config";
import preact from "@astrojs/preact";
import { fileURLToPath } from "node:url";

// The in-browser demo reuses the TypeScript engine from the sibling `ts/` package
// (imported as `@ts/...`) and the browser WASM build of the verified Rust cipher
// vendored in `src/wasm/`. Allow Vite to read the sibling package during dev.
const tsSrc = fileURLToPath(new URL("../ts/src", import.meta.url));
const repoRoot = fileURLToPath(new URL("..", import.meta.url));

export default defineConfig({
  integrations: [preact()],
  // Emit flat files (about.html, not about/index.html) so extensionless URLs
  // resolve cleanly on static hosts that append `.html`.
  build: { format: "file" },
  vite: {
    resolve: { alias: { "@ts": tsSrc } },
    server: { fs: { allow: [repoRoot] } },
  },
});
