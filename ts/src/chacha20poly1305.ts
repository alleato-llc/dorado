// ChaCha20-Poly1305 AEAD (RFC 8439, section 2.8), TS port. The *InPlace
// functions feed Poly1305 incrementally, so nothing is assembled in memory.

import * as chacha from "./chacha";
import { Poly1305 } from "./poly1305";
import { equalBytes } from "./bytes";

export const TAG_LEN = 16;

const ZEROS = new Uint8Array(16);

function polyKey(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return chacha.block(key, 0, nonce).subarray(0, 32);
}

function computeTag(otk: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const p = new Poly1305(otk);
  p.update(aad);
  p.update(ZEROS.subarray(0, (16 - (aad.length % 16)) % 16));
  p.update(ciphertext);
  p.update(ZEROS.subarray(0, (16 - (ciphertext.length % 16)) % 16));
  const lens = new Uint8Array(16);
  new DataView(lens.buffer).setBigUint64(0, BigInt(aad.length), true);
  new DataView(lens.buffer).setBigUint64(8, BigInt(ciphertext.length), true);
  p.update(lens);
  return p.finalize();
}

/** Encrypt and authenticate in place; returns the 16-byte tag. */
export function sealInPlace(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, buf: Uint8Array): Uint8Array {
  const otk = polyKey(key, nonce);
  chacha.apply(key, 1, nonce, buf);
  return computeTag(otk, aad, buf);
}

/** Verify and decrypt in place; throws on authentication failure. */
export function openInPlace(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  buf: Uint8Array,
  tag: Uint8Array,
): void {
  const otk = polyKey(key, nonce);
  const expected = computeTag(otk, aad, buf);
  if (!equalBytes(expected, tag)) throw new Error("chacha20poly1305: authentication failed");
  chacha.apply(key, 1, nonce, buf);
}

/** Encrypt and authenticate, returning [ciphertext, tag]. */
export function seal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): [Uint8Array, Uint8Array] {
  const buf = plaintext.slice();
  const tag = sealInPlace(key, nonce, aad, buf);
  return [buf, tag];
}

/** Verify and decrypt, returning the plaintext (throws on failure). */
export function open(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  const buf = ciphertext.slice();
  openInPlace(key, nonce, aad, buf, tag);
  return buf;
}
