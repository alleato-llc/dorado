// Threefish tweakable block cipher (256/512/1024-bit), the cipher at the core of
// the Skein hash function, following Skein 1.3. TypeScript port of the dorado
// Rust/Go implementations.
//
// The 64-bit ARX arithmetic uses BigInt for clarity (it mirrors the u64 source);
// this is an educational, unaudited demo, not a performance build. Keys, tweaks,
// and blocks are little-endian.

const MASK64 = (1n << 64n) - 1n;
const C240 = 0x1bd11bdaa9fc1a22n;

// Verified rotation and permutation tables (Skein 1.3). Do not change.
const ROT256 = [
  [14, 52, 23, 5, 25, 46, 58, 32],
  [16, 57, 40, 37, 33, 12, 22, 32],
];
const PERM256 = [0, 3, 2, 1];

const ROT512 = [
  [46, 33, 17, 44, 39, 13, 25, 8],
  [36, 27, 49, 9, 30, 50, 29, 35],
  [19, 14, 36, 54, 34, 10, 39, 56],
  [37, 42, 39, 56, 24, 17, 43, 22],
];
const PERM512 = [2, 1, 4, 7, 6, 5, 0, 3];

const ROT1024 = [
  [24, 38, 33, 5, 41, 16, 31, 9],
  [13, 19, 4, 20, 9, 34, 44, 48],
  [8, 10, 51, 48, 37, 56, 47, 35],
  [47, 55, 13, 41, 31, 51, 46, 52],
  [8, 49, 34, 47, 12, 4, 19, 23],
  [17, 18, 41, 28, 47, 53, 42, 31],
  [22, 23, 59, 16, 44, 42, 44, 37],
  [37, 52, 17, 25, 30, 41, 25, 20],
];
const PERM1024 = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1];

const add = (a: bigint, b: bigint): bigint => (a + b) & MASK64;
const sub = (a: bigint, b: bigint): bigint => (a - b) & MASK64;

function rotl(x: bigint, n: number): bigint {
  const k = BigInt(n);
  return ((x << k) | (x >> BigInt(64 - n))) & MASK64;
}
function rotr(x: bigint, n: number): bigint {
  const k = BigInt(n);
  return ((x >> k) | (x << BigInt(64 - n))) & MASK64;
}

function loadWord(b: Uint8Array, off: number): bigint {
  let w = 0n;
  for (let i = 7; i >= 0; i--) w = (w << 8n) | BigInt(b[off + i]);
  return w;
}
function storeWord(w: bigint, out: Uint8Array, off: number): void {
  for (let i = 0; i < 8; i++) {
    out[off + i] = Number(w & 0xffn);
    w >>= 8n;
  }
}

/** A Threefish variant with its key schedule built once. */
export class Threefish {
  private readonly ek: bigint[]; // extended key: nw key words + parity
  private readonly et: [bigint, bigint, bigint];
  private readonly rot: number[][];
  private readonly perm: number[];
  private readonly rounds: number;
  private readonly nw: number;
  readonly blockBytes: number;

  constructor(
    key: Uint8Array,
    tweak: Uint8Array,
    nw: number,
    rounds: number,
    rot: number[][],
    perm: number[],
  ) {
    this.blockBytes = nw * 8;
    if (key.length !== this.blockBytes) {
      throw new Error(`threefish: key must be ${this.blockBytes} bytes, got ${key.length}`);
    }
    if (tweak.length !== 16) {
      throw new Error(`threefish: tweak must be 16 bytes, got ${tweak.length}`);
    }
    const ek = new Array<bigint>(nw + 1);
    let parity = C240;
    for (let i = 0; i < nw; i++) {
      const w = loadWord(key, i * 8);
      ek[i] = w;
      parity ^= w;
    }
    ek[nw] = parity & MASK64;
    const t0 = loadWord(tweak, 0);
    const t1 = loadWord(tweak, 8);
    this.ek = ek;
    this.et = [t0, t1, (t0 ^ t1) & MASK64];
    this.rot = rot;
    this.perm = perm;
    this.rounds = rounds;
    this.nw = nw;
  }

  private subkeyWord(s: number, i: number): bigint {
    let k = this.ek[(s + i) % (this.nw + 1)];
    if (i === this.nw - 3) k = add(k, this.et[s % 3]);
    else if (i === this.nw - 2) k = add(k, this.et[(s + 1) % 3]);
    else if (i === this.nw - 1) k = add(k, BigInt(s) & MASK64);
    return k;
  }

  /** Encrypt one 64*nw-bit block in place. */
  encryptBlock(block: Uint8Array): void {
    const nw = this.nw;
    const state = new Array<bigint>(nw);
    for (let i = 0; i < nw; i++) state[i] = loadWord(block, i * 8);
    const scratch = new Array<bigint>(nw);
    for (let r = 0; r < this.rounds; r++) {
      if (r % 4 === 0) for (let i = 0; i < nw; i++) state[i] = add(state[i], this.subkeyWord(r >> 2, i));
      for (let j = 0; j < nw / 2; j++) {
        const x0 = state[2 * j];
        const x1 = state[2 * j + 1];
        const y0 = add(x0, x1);
        state[2 * j] = y0;
        state[2 * j + 1] = rotl(x1, this.rot[j][r % 8]) ^ y0;
      }
      for (let i = 0; i < nw; i++) scratch[i] = state[this.perm[i]];
      for (let i = 0; i < nw; i++) state[i] = scratch[i];
    }
    for (let i = 0; i < nw; i++) state[i] = add(state[i], this.subkeyWord(this.rounds >> 2, i));
    for (let i = 0; i < nw; i++) storeWord(state[i], block, i * 8);
  }

  /** Decrypt one block in place (exact inverse of encryptBlock). */
  decryptBlock(block: Uint8Array): void {
    const nw = this.nw;
    const state = new Array<bigint>(nw);
    for (let i = 0; i < nw; i++) state[i] = loadWord(block, i * 8);
    const scratch = new Array<bigint>(nw);
    for (let i = 0; i < nw; i++) state[i] = sub(state[i], this.subkeyWord(this.rounds >> 2, i));
    for (let r = this.rounds - 1; r >= 0; r--) {
      for (let i = 0; i < nw; i++) scratch[this.perm[i]] = state[i];
      for (let i = 0; i < nw; i++) state[i] = scratch[i];
      for (let j = 0; j < nw / 2; j++) {
        const y0 = state[2 * j];
        const y1 = state[2 * j + 1];
        const x1 = rotr(y1 ^ y0, this.rot[j][r % 8]);
        state[2 * j] = sub(y0, x1);
        state[2 * j + 1] = x1;
      }
      if (r % 4 === 0) for (let i = 0; i < nw; i++) state[i] = sub(state[i], this.subkeyWord(r >> 2, i));
    }
    for (let i = 0; i < nw; i++) storeWord(state[i], block, i * 8);
  }
}

export const newThreefish256 = (key: Uint8Array, tweak: Uint8Array) =>
  new Threefish(key, tweak, 4, 72, ROT256, PERM256);
export const newThreefish512 = (key: Uint8Array, tweak: Uint8Array) =>
  new Threefish(key, tweak, 8, 72, ROT512, PERM512);
export const newThreefish1024 = (key: Uint8Array, tweak: Uint8Array) =>
  new Threefish(key, tweak, 16, 80, ROT1024, PERM1024);
