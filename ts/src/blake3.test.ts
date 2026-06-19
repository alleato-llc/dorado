import { describe, it, expect } from "vitest";
import { blake3 as refBlake3 } from "@noble/hashes/blake3.js";
import { hash, keyedMac } from "./blake3";
import { bytesToHex, equalBytes } from "./bytes";

describe("BLAKE3", () => {
  it("official empty vector", () => {
    expect(bytesToHex(hash(32, new Uint8Array(0)))).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
  });

  it("differential vs @noble/hashes across sizes (hash, XOF, keyed)", () => {
    const lengths = [0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 4096, 8192, 16385, 50000];
    let seed = 1;
    const rand = (n: number) => {
      const b = new Uint8Array(n);
      for (let i = 0; i < n; i++) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        b[i] = seed & 0xff;
      }
      return b;
    };
    const key = rand(32);
    for (const n of lengths) {
      const msg = rand(n);
      expect(equalBytes(hash(32, msg), refBlake3(msg))).toBe(true);
      expect(equalBytes(hash(131, msg), refBlake3(msg, { dkLen: 131 }))).toBe(true);
      expect(equalBytes(keyedMac(key, 32, msg), refBlake3(msg, { key }))).toBe(true);
    }
  });
});
