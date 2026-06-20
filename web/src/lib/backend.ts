// The browser cipher backend for the demo. It loads the vendored browser build of
// the verified Rust cipher (src/wasm/, built by `npm run build:wasm`) and adapts
// it to the engine's CipherBackend interface, so the demo's secret arithmetic runs
// in WASM linear memory instead of on the JS heap, exactly as the Node CLI does.

import type { CipherBackend } from "@ts/engine/backend";
import { T256, T512 } from "@ts/engine/format";
import init, { ctr256, ctr512, ctr1024, skein_mac, skein_hash, blake3_keyed_mac } from "../wasm/dorado_wasm.js";
import wasmUrl from "../wasm/dorado_wasm_bg.wasm?url";

let ready: Promise<void> | undefined;

/** Instantiate the WASM module once. Must resolve before using browserBackend. */
export function ensureWasm(): Promise<void> {
  if (!ready) ready = init(wasmUrl).then(() => undefined);
  return ready;
}

export const browserBackend: CipherBackend = {
  ctr(variant, key, tweak, iv, data) {
    if (variant === T256) return ctr256(key, tweak, iv, data);
    if (variant === T512) return ctr512(key, tweak, iv, data);
    return ctr1024(key, tweak, iv, data);
  },
  skeinMac: (key, outLen, msg) => skein_mac(key, outLen, msg),
  skeinHash: (outLen, msg) => skein_hash(outLen, msg),
  blake3KeyedMac: (key, outLen, input) => blake3_keyed_mac(key, outLen, input),
};
