// Node-only secure memory for the secrets the CLI holds. When `sodium-native`
// loads, it uses libsodium's guarded allocator (sodium_malloc): the bytes live
// in mlock'd, off-heap pages that are kept out of swap, fenced with guard pages,
// and excluded from core dumps, rather than in ordinary swappable V8 heap memory.
//
// Fail-closed: if the native module cannot be loaded, the CLI refuses to handle
// secrets rather than silently degrading to ordinary heap memory. The user can
// opt out explicitly with --insecure-memory (see assertSecureMemory), which
// falls back to plain buffers that are still zeroed on wipe. This mirrors the
// project's secure-by-default stance (like raw-key authenticated-by-default):
// degraded modes exist, but only as a deliberate, visible choice.
//
// Scope, honestly: this covers the buffers the CLI itself owns (the decoded
// password bytes, a raw key, the plaintext). It does not reach transient values
// inside the engine, the KDF (hash-wasm), or the copies the cipher makes inside
// WASM linear memory. And an interactively typed password unavoidably transits
// an immutable JS string inside Node's readline before it is copied into the
// locked buffer; JS strings cannot be wiped, so that copy lives on the V8 heap
// until garbage collection reclaims it. It reduces exposure; it is not a
// zeroization guarantee. Node-only: the browser has no equivalent, which is one
// reason the Node path is the stronger one.

import { createRequire } from "node:module";
import process from "node:process";

const require = createRequire(import.meta.url);

interface Sodium {
  sodium_malloc(size: number): Buffer;
  sodium_memzero(buf: Uint8Array): void;
  sodium_mlock(buf: Uint8Array): void;
}

let sodium: Sodium | undefined;
let loadError: unknown;
try {
  sodium = require("sodium-native") as Sodium;
} catch (e) {
  sodium = undefined;
  loadError = e;
}

/** True when secrets are held in libsodium guarded (mlock'd, off-heap) memory. */
export const secureMemoryAvailable = sodium !== undefined;

// Set only by assertSecureMemory(true): the user explicitly accepted ordinary
// heap memory. Until then, allocating a secret without sodium is an error.
let insecureAllowed = false;

function missingSodiumMessage(): string {
  // First line only: module-not-found errors append a multi-line require stack.
  const cause = loadError instanceof Error ? ` (underlying error: ${loadError.message.split("\n")[0]})` : "";
  return (
    "sodium-native failed to load, so secrets cannot be held in locked (mlock'd, " +
    "off-heap) memory. Reinstall it with `npm install` in ts/, or pass " +
    "--insecure-memory to proceed with ordinary swappable heap memory that is " +
    "only zeroed on wipe." + cause
  );
}

/**
 * Enforce the fail-closed policy before any secret is handled. With secure
 * memory available this is a no-op. Without it, throws unless the user passed
 * --insecure-memory, in which case the degradation is permitted for the rest of
 * the process and announced once via a process warning.
 */
export function assertSecureMemory(allowInsecure: boolean): void {
  if (sodium) return;
  if (!allowInsecure) throw new Error(missingSodiumMessage());
  insecureAllowed = true;
  process.emitWarning(
    "--insecure-memory: sodium-native is unavailable; secrets are held in ordinary (swappable) memory and only zeroed on wipe.",
    { code: "DORADO_INSECURE_MEMORY" },
  );
}

/** A secret byte buffer that can be wiped. Pass `.bytes` to the engine. */
export interface Secret {
  readonly bytes: Uint8Array;
  /** Zero the bytes. Idempotent; the buffer must not be used afterward. */
  wipe(): void;
}

/** Allocate a zeroed secret buffer of `size` bytes (guarded when available). */
export function secureAlloc(size: number): Secret {
  // Fail closed even if a caller forgot to gate: without sodium, allocating a
  // secret requires the explicit --insecure-memory opt-in recorded above.
  if (!sodium && !insecureAllowed) throw new Error(missingSodiumMessage());
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
