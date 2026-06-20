// The WASM cipher backend (Node). Loads the wasm-pack `--target nodejs` build of
// the verified Rust cipher, so the secret arithmetic runs in WASM linear memory
// and the value stack instead of the JS heap. Node-only (uses createRequire and
// the CommonJS wasm-pack output); the browser would load the bundler/web build.
//
// Build it first: `cd ../rust/wasm && wasm-pack build --target nodejs`.

import { createRequire } from "node:module";
import { type CipherBackend } from "./backend";
import { T256, T512 } from "./format";

interface WasmExports {
  ctr256(key: Uint8Array, tweak: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;
  ctr512(key: Uint8Array, tweak: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;
  ctr1024(key: Uint8Array, tweak: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;
  skein_hash(outLen: number, msg: Uint8Array): Uint8Array;
  skein_mac(key: Uint8Array, outLen: number, msg: Uint8Array): Uint8Array;
  blake3_keyed_mac(key: Uint8Array, outLen: number, input: Uint8Array): Uint8Array;
}

const require = createRequire(import.meta.url);
const wasm = require("../../../rust/wasm/pkg/dorado_wasm.js") as WasmExports;

export const wasmBackend: CipherBackend = {
  ctr(variant, key, tweak, iv, data) {
    if (variant === T256) return wasm.ctr256(key, tweak, iv, data);
    if (variant === T512) return wasm.ctr512(key, tweak, iv, data);
    return wasm.ctr1024(key, tweak, iv, data);
  },
  skeinMac: (key, outLen, msg) => wasm.skein_mac(key, outLen, msg),
  skeinHash: (outLen, msg) => wasm.skein_hash(outLen, msg),
  blake3KeyedMac: (key, outLen, input) => wasm.blake3_keyed_mac(key, outLen, input),
};
