// Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI. TS port.
// One-shot (the streaming hold-back of the Rust/Go versions is an optimization
// not needed in the browser; the output is identical).

import { newThreefish512 } from "./threefish";
import { utf8 } from "./bytes";

const BLOCK = 64;
const T_KEY = 0n;
const T_CFG = 4n;
const T_MSG = 48n;
const T_OUT = 63n;

function storeU64LE(w: bigint, out: Uint8Array, off: number): void {
  for (let i = 0; i < 8; i++) {
    out[off + i] = Number(w & 0xffn);
    w >>= 8n;
  }
}

function tweak(position: bigint, ty: bigint, first: boolean, last: boolean): Uint8Array {
  let t1 = ty << 56n;
  if (first) t1 |= 1n << 62n;
  if (last) t1 |= 1n << 63n;
  const tw = new Uint8Array(16);
  storeU64LE(position, tw, 0);
  storeU64LE(t1, tw, 8);
  return tw;
}

// One UBI pass: chain msg into the 64-byte chaining value g under block type ty.
function ubi(g: Uint8Array, msg: Uint8Array, ty: bigint): void {
  const total = msg.length;
  let offset = 0;
  let position = 0n;
  let first = true;
  for (;;) {
    const take = Math.min(total - offset, BLOCK);
    const block = new Uint8Array(BLOCK);
    block.set(msg.subarray(offset, offset + take), 0);
    position += BigInt(take);
    offset += take;
    const last = offset >= total;

    const cipher = newThreefish512(g, tweak(position, ty, first, last));
    const enc = block.slice();
    cipher.encryptBlock(enc);
    for (let i = 0; i < BLOCK; i++) g[i] = enc[i] ^ block[i];
    first = false;
    if (last) break;
  }
}

function configBlock(outBits: number): Uint8Array {
  const c = new Uint8Array(32);
  c.set(utf8("SHA3"), 0);
  c[4] = 1;
  storeU64LE(BigInt(outBits), c, 8);
  return c;
}

function output(g: Uint8Array, outLen: number): Uint8Array {
  const out = new Uint8Array(outLen);
  let counter = 0n;
  let written = 0;
  while (written < outLen) {
    const block = g.slice();
    const ctr = new Uint8Array(8);
    storeU64LE(counter, ctr, 0);
    ubi(block, ctr, T_OUT);
    const n = Math.min(BLOCK, outLen - written);
    out.set(block.subarray(0, n), written);
    written += n;
    counter++;
  }
  return out;
}

/** Skein-512 hash of msg with outLen output bytes. */
export function hash(outLen: number, msg: Uint8Array): Uint8Array {
  const g = new Uint8Array(64);
  ubi(g, configBlock(outLen * 8), T_CFG);
  ubi(g, msg, T_MSG);
  return output(g, outLen);
}

/** Skein-512 keyed MAC producing outLen tag bytes. */
export function mac(key: Uint8Array, outLen: number, msg: Uint8Array): Uint8Array {
  const g = new Uint8Array(64);
  if (key.length > 0) ubi(g, key, T_KEY);
  ubi(g, configBlock(outLen * 8), T_CFG);
  ubi(g, msg, T_MSG);
  return output(g, outLen);
}
