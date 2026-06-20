// A swappable cipher/hash backend, so the engine can run on either the readable
// pure-TS implementations (default) or the WASM build of the verified Rust cipher
// (which keeps the secret arithmetic off the JS heap). Output is identical.

import { newThreefish256, newThreefish512, newThreefish1024, type Threefish } from "../threefish";
import * as skein from "../skein";
import * as blake3 from "../blake3";
import { type Variant, T256, T512 } from "./format";

export interface CipherBackend {
  /** Apply CTR to data, returning the transformed bytes. */
  ctr(variant: Variant, key: Uint8Array, tweak: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;
  skeinMac(key: Uint8Array, outLen: number, msg: Uint8Array): Uint8Array;
  skeinHash(outLen: number, msg: Uint8Array): Uint8Array;
  blake3KeyedMac(key: Uint8Array, outLen: number, input: Uint8Array): Uint8Array;
}

function newCipher(v: Variant, key: Uint8Array, tweak: Uint8Array): Threefish {
  if (v === T256) return newThreefish256(key, tweak);
  if (v === T512) return newThreefish512(key, tweak);
  return newThreefish1024(key, tweak);
}

function incrementBE(c: Uint8Array): void {
  for (let i = c.length - 1; i >= 0; i--) {
    c[i] = (c[i] + 1) & 0xff;
    if (c[i] !== 0) break;
  }
}

function ctrInPlace(cipher: Threefish, iv: Uint8Array, data: Uint8Array): void {
  const bs = cipher.blockBytes;
  const counter = iv.slice();
  const ks = new Uint8Array(bs);
  for (let off = 0; off < data.length; off += bs) {
    ks.set(counter);
    cipher.encryptBlock(ks);
    const n = Math.min(bs, data.length - off);
    for (let j = 0; j < n; j++) data[off + j] ^= ks[j];
    incrementBE(counter);
  }
}

/** The pure-TypeScript backend (the readable reference). */
export const tsBackend: CipherBackend = {
  ctr(variant, key, tweak, iv, data) {
    const out = data.slice();
    ctrInPlace(newCipher(variant, key, tweak), iv, out);
    return out;
  },
  skeinMac: (key, outLen, msg) => skein.mac(key, outLen, msg),
  skeinHash: (outLen, msg) => skein.hash(outLen, msg),
  blake3KeyedMac: (key, outLen, input) => blake3.keyedMac(key, outLen, input),
};
