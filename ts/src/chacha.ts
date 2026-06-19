// ChaCha20 stream cipher (RFC 8439), TS port. Uses native 32-bit arithmetic via
// Uint32Array (which truncates on store).

const CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a] + s[b]) | 0;
  s[d] = rotl32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) | 0;
  s[b] = rotl32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) | 0;
  s[d] = rotl32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) | 0;
  s[b] = rotl32(s[b] ^ s[c], 7);
}

/** One 64-byte keystream block for the key, 32-bit counter, and 96-bit nonce. */
export function block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const state = new Uint32Array(16);
  state.set(CONSTANTS, 0);
  const kv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) state[4 + i] = kv.getUint32(i * 4, true);
  state[12] = counter >>> 0;
  const nv = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  for (let i = 0; i < 3; i++) state[13 + i] = nv.getUint32(i * 4, true);

  const w = state.slice();
  for (let i = 0; i < 10; i++) {
    quarterRound(w, 0, 4, 8, 12);
    quarterRound(w, 1, 5, 9, 13);
    quarterRound(w, 2, 6, 10, 14);
    quarterRound(w, 3, 7, 11, 15);
    quarterRound(w, 0, 5, 10, 15);
    quarterRound(w, 1, 6, 11, 12);
    quarterRound(w, 2, 7, 8, 13);
    quarterRound(w, 3, 4, 9, 14);
  }

  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) ov.setUint32(i * 4, (w[i] + state[i]) >>> 0, true);
  return out;
}

/** XOR ChaCha20 keystream into data in place, starting at counter. */
export function apply(key: Uint8Array, counter: number, nonce: Uint8Array, data: Uint8Array): void {
  let blk = 0;
  for (let off = 0; off < data.length; off += 64) {
    const ks = block(key, (counter + blk) >>> 0, nonce);
    const n = Math.min(64, data.length - off);
    for (let j = 0; j < n; j++) data[off + j] ^= ks[j];
    blk++;
  }
}
