// Vite resolves a `?url` import to the served asset URL (a string). Astro's
// `vite/client` types cover this, but declaring it explicitly keeps the demo's
// WASM import typed without depending on that ambient declaration being present.
declare module "*.wasm?url" {
  const src: string;
  export default src;
}
