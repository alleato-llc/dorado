// Poly1305 one-time MAC (RFC 8439), TS port. Uses BigInt for the modulo
// 2^130-5 arithmetic (clean and exact, avoiding JS's 53-bit number limit).
//
// Poly1305 is a ONE-TIME MAC: each key authenticates exactly one message.

const P = (1n << 130n) - 5n;
const CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;
const MASK128 = (1n << 128n) - 1n;

function leToBig(b: Uint8Array, len: number): bigint {
  let w = 0n;
  for (let i = len - 1; i >= 0; i--) w = (w << 8n) | BigInt(b[i]);
  return w;
}

function bigToLe(w: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(w & 0xffn);
    w >>= 8n;
  }
  return out;
}

/** Incremental Poly1305 state. */
export class Poly1305 {
  private readonly r: bigint;
  private readonly s: bigint;
  private acc = 0n;
  private readonly buffer = new Uint8Array(16);
  private bufLen = 0;

  constructor(key: Uint8Array) {
    if (key.length < 32) throw new Error("poly1305: key must be 32 bytes");
    this.r = leToBig(key.subarray(0, 16), 16) & CLAMP;
    this.s = leToBig(key.subarray(16, 32), 16);
  }

  private processBlock(chunk: Uint8Array, len: number): void {
    const n = leToBig(chunk, len) + (1n << BigInt(8 * len));
    this.acc = ((this.acc + n) * this.r) % P;
  }

  update(data: Uint8Array): void {
    let off = 0;
    if (this.bufLen > 0) {
      const take = Math.min(16 - this.bufLen, data.length);
      this.buffer.set(data.subarray(0, take), this.bufLen);
      this.bufLen += take;
      off = take;
      if (this.bufLen < 16) return;
      this.processBlock(this.buffer, 16);
      this.bufLen = 0;
    }
    while (data.length - off >= 16) {
      this.processBlock(data.subarray(off, off + 16), 16);
      off += 16;
    }
    if (off < data.length) {
      this.buffer.set(data.subarray(off), 0);
      this.bufLen = data.length - off;
    }
  }

  finalize(): Uint8Array {
    if (this.bufLen > 0) this.processBlock(this.buffer.subarray(0, this.bufLen), this.bufLen);
    return bigToLe((this.acc + this.s) & MASK128, 16);
  }
}

/** One-shot Poly1305 tag of msg under the 32-byte one-time key. */
export function mac(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const p = new Poly1305(key);
  p.update(msg);
  return p.finalize();
}
