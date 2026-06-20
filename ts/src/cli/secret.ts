// Node-only secure memory for the secrets the CLI holds. When `sodium-native` is
// installed it uses libsodium's guarded allocator (sodium_malloc): the bytes live
// in mlock'd, off-heap pages that are kept out of swap, fenced with guard pages,
// and excluded from core dumps, rather than in ordinary swappable V8 heap memory.
// If the native module is missing it falls back to a plain buffer that is still
// zeroed on wipe, so the CLI keeps working (with a one-time warning).
//
// Scope, honestly: this covers the buffers the CLI itself owns (the decoded
// password bytes, a raw key, the plaintext). It does not reach transient values
// inside the engine, the KDF (hash-wasm), or the copies the cipher makes inside
// WASM linear memory, and it cannot touch a password that first arrived as a JS
// string. It reduces exposure; it is not a zeroization guarantee. Node-only: the
// browser has no equivalent, which is one reason the Node path is the stronger one.

import { createRequire } from "node:module";
import process from "node:process";

const require = createRequire(import.meta.url);

interface Sodium {
  sodium_malloc(size: number): Buffer;
  sodium_memzero(buf: Uint8Array): void;
  sodium_mlock(buf: Uint8Array): void;
}

let sodium: Sodium | undefined;
try {
  sodium = require("sodium-native") as Sodium;
} catch {
  sodium = undefined;
  process.emitWarning(
    "sodium-native is not installed; secrets are held in ordinary (swappable) memory and only zeroed on wipe. Run `npm install` in ts/ to enable mlock'd off-heap buffers.",
    { code: "DORADO_NO_SECURE_MEMORY" },
  );
}

/** True when secrets are held in libsodium guarded (mlock'd, off-heap) memory. */
export const secureMemoryAvailable = sodium !== undefined;

/** A secret byte buffer that can be wiped. Pass `.bytes` to the engine. */
export interface Secret {
  readonly bytes: Uint8Array;
  /** Zero the bytes. Idempotent; the buffer must not be used afterward. */
  wipe(): void;
}

/** Allocate a zeroed secret buffer of `size` bytes (guarded when available). */
export function secureAlloc(size: number): Secret {
  const bytes: Uint8Array = sodium ? sodium.sodium_malloc(size) : new Uint8Array(size);
  return {
    bytes,
    wipe() {
      if (sodium) sodium.sodium_memzero(bytes);
      else bytes.fill(0);
    },
  };
}

/** Copy `data` into a secret buffer, then wipe the (ordinary) source in place. */
export function secureFrom(data: Uint8Array): Secret {
  const s = secureAlloc(data.length);
  s.bytes.set(data);
  data.fill(0);
  return s;
}

/** Zero a buffer the CLI owns (e.g. a decoded key or plaintext) after use. */
export function wipe(buf: Uint8Array): void {
  if (sodium) sodium.sodium_memzero(buf);
  else buf.fill(0);
}
