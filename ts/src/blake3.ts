// BLAKE3 hash and keyed MAC, TS port using the streaming chunk-stack algorithm
// (the same as the Rust/Go ports). 32-bit arithmetic via Uint32Array.

const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;

const CHUNK_START = 1 << 0;
const CHUNK_END = 1 << 1;
const PARENT = 1 << 2;
const ROOT = 1 << 3;
const KEYED_HASH = 1 << 4;

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const rotr32 = (x: number, n: number): number => ((x >>> n) | (x << (32 - n))) >>> 0;

function g(s: Uint32Array, a: number, b: number, c: number, d: number, mx: number, my: number): void {
  s[a] = s[a] + s[b] + mx;
  s[d] = rotr32(s[d] ^ s[a], 16);
  s[c] = s[c] + s[d];
  s[b] = rotr32(s[b] ^ s[c], 12);
  s[a] = s[a] + s[b] + my;
  s[d] = rotr32(s[d] ^ s[a], 8);
  s[c] = s[c] + s[d];
  s[b] = rotr32(s[b] ^ s[c], 7);
}

function compress(cv: Uint32Array, block: Uint32Array, counter: number, blockLen: number, flags: number): Uint32Array {
  const lo = counter % 0x100000000;
  const hi = Math.floor(counter / 0x100000000);
  const state = new Uint32Array(16);
  state.set(cv.subarray(0, 8), 0);
  state.set(IV.subarray(0, 4), 8);
  state[12] = lo >>> 0;
  state[13] = hi >>> 0;
  state[14] = blockLen >>> 0;
  state[15] = flags >>> 0;

  let m = block.slice();
  for (let round = 0; round < 7; round++) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
    if (round < 6) {
      const permuted = new Uint32Array(16);
      for (let i = 0; i < 16; i++) permuted[i] = m[MSG_PERMUTATION[i]];
      m = permuted;
    }
  }
  for (let i = 0; i < 8; i++) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= cv[i];
  }
  return state;
}

function wordsFromBlock(b: Uint8Array): Uint32Array {
  const padded = new Uint8Array(BLOCK_LEN);
  padded.set(b.subarray(0, Math.min(b.length, BLOCK_LEN)), 0);
  const dv = new DataView(padded.buffer);
  const words = new Uint32Array(16);
  for (let i = 0; i < 16; i++) words[i] = dv.getUint32(i * 4, true);
  return words;
}

interface Output {
  inputCV: Uint32Array;
  block: Uint32Array;
  counter: number;
  blockLen: number;
  flags: number;
}

function chainingValue(o: Output): Uint32Array {
  return compress(o.inputCV, o.block, o.counter, o.blockLen, o.flags).slice(0, 8);
}

function rootOutputInto(o: Output, out: Uint8Array): void {
  let counter = 0;
  let written = 0;
  while (written < out.length) {
    const words = compress(o.inputCV, o.block, counter, o.blockLen, o.flags | ROOT);
    const dv = new DataView(new ArrayBuffer(64));
    for (let i = 0; i < 16; i++) dv.setUint32(i * 4, words[i], true);
    const n = Math.min(64, out.length - written);
    out.set(new Uint8Array(dv.buffer, 0, n), written);
    written += n;
    counter++;
  }
}

class ChunkState {
  cv: Uint32Array;
  block = new Uint8Array(BLOCK_LEN);
  blockLen = 0;
  blocksCompressed = 0;
  constructor(
    key: Uint32Array,
    public chunkCounter: number,
    public flags: number,
  ) {
    this.cv = key.slice(0, 8);
  }
  len(): number {
    return BLOCK_LEN * this.blocksCompressed + this.blockLen;
  }
  private startFlag(): number {
    return this.blocksCompressed === 0 ? CHUNK_START : 0;
  }
  update(input: Uint8Array): void {
    let off = 0;
    while (off < input.length) {
      if (this.blockLen === BLOCK_LEN) {
        const out = compress(this.cv, wordsFromBlock(this.block), this.chunkCounter, BLOCK_LEN, this.flags | this.startFlag());
        this.cv = out.slice(0, 8);
        this.blocksCompressed++;
        this.block = new Uint8Array(BLOCK_LEN);
        this.blockLen = 0;
      }
      const take = Math.min(BLOCK_LEN - this.blockLen, input.length - off);
      this.block.set(input.subarray(off, off + take), this.blockLen);
      this.blockLen += take;
      off += take;
    }
  }
  output(): Output {
    return {
      inputCV: this.cv,
      block: wordsFromBlock(this.block.subarray(0, this.blockLen)),
      counter: this.chunkCounter,
      blockLen: this.blockLen,
      flags: this.flags | this.startFlag() | CHUNK_END,
    };
  }
}

function parentOutput(left: Uint32Array, right: Uint32Array, key: Uint32Array, flags: number): Output {
  const block = new Uint32Array(16);
  block.set(left.subarray(0, 8), 0);
  block.set(right.subarray(0, 8), 8);
  return { inputCV: key.slice(0, 8), block, counter: 0, blockLen: BLOCK_LEN, flags: flags | PARENT };
}

/** Incremental BLAKE3 hash/MAC (chunk-stack streaming hasher). */
export class Blake3 {
  private chunkState: ChunkState;
  private readonly cvStack: Uint32Array[] = [];

  private constructor(
    private readonly key: Uint32Array,
    private readonly flags: number,
  ) {
    this.chunkState = new ChunkState(key, 0, flags);
  }

  static new(): Blake3 {
    return new Blake3(IV.slice(0, 8), 0);
  }

  static newKeyed(key: Uint8Array): Blake3 {
    const kw = new Uint32Array(8);
    const dv = new DataView(key.buffer, key.byteOffset, key.byteLength);
    for (let i = 0; i < 8; i++) kw[i] = dv.getUint32(i * 4, true);
    return new Blake3(kw, KEYED_HASH);
  }

  private addChunkCV(newCV: Uint32Array, totalChunks: number): void {
    while (totalChunks % 2 === 0) {
      newCV = chainingValue(parentOutput(this.cvStack.pop()!, newCV, this.key, this.flags));
      totalChunks = Math.floor(totalChunks / 2);
    }
    this.cvStack.push(newCV);
  }

  update(input: Uint8Array): void {
    let off = 0;
    while (off < input.length) {
      if (this.chunkState.len() === CHUNK_LEN) {
        const chunkCV = chainingValue(this.chunkState.output());
        const totalChunks = this.chunkState.chunkCounter + 1;
        this.addChunkCV(chunkCV, totalChunks);
        this.chunkState = new ChunkState(this.key, totalChunks, this.flags);
      }
      const take = Math.min(CHUNK_LEN - this.chunkState.len(), input.length - off);
      this.chunkState.update(input.subarray(off, off + take));
      off += take;
    }
  }

  finalizeInto(out: Uint8Array): void {
    let o = this.chunkState.output();
    for (let i = this.cvStack.length - 1; i >= 0; i--) {
      o = parentOutput(this.cvStack[i], chainingValue(o), this.key, this.flags);
    }
    rootOutputInto(o, out);
  }
}

/** One-shot BLAKE3 hash of input into outLen bytes (XOF for outLen > 32). */
export function hash(outLen: number, input: Uint8Array): Uint8Array {
  const h = Blake3.new();
  h.update(input);
  const out = new Uint8Array(outLen);
  h.finalizeInto(out);
  return out;
}

/** One-shot keyed BLAKE3 MAC under a 32-byte key. */
export function keyedMac(key: Uint8Array, outLen: number, input: Uint8Array): Uint8Array {
  const h = Blake3.newKeyed(key);
  h.update(input);
  const out = new Uint8Array(outLen);
  h.finalizeInto(out);
  return out;
}
