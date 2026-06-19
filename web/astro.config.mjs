// @ts-check
import { defineConfig } from "astro/config";
import preact from "@astrojs/preact";

export default defineConfig({
  integrations: [preact()],
  // Emit flat files (about.html, not about/index.html) so extensionless URLs
  // resolve cleanly on static hosts that append `.html`.
  build: { format: "file" },
});
