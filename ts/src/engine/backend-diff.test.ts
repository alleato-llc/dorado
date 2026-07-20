// Differential test: the pure-TS backend and the WASM backend (the wasm-pack
// build of the verified Rust cipher) must produce byte-identical output for the
// same operations. The wasm build (rust/wasm/pkg) is not checked in, so this
// suite runs only when it is present and skips cleanly otherwise (CI's ts job
// does not build it). Run it locally after:
//   cd rust/wasm && wasm-pack build --target nodejs

import { createRequire } from "node:module";
import { describe, it, expect } from "vitest";
import { tsBackend } from "./backend";
import { wasmBackend } from "./wasm-backend";
import {
  encryptPasswordBytes,
  decryptPasswordBytes,
  rawCTR,
  encryptRawAuthenticatedBytes,
  decryptRawAuthenticatedBytes,
  defaultOptions,
  type PasswordOptions,
} from "./engine";
import { KDF_PBKDF2, MAC_SKEIN, MAC_HMAC, MAC_BLAKE3, T256, T512, T1024, keyLen, blockLen } from "./format";
import { bytesToHex, utf8 } from "../bytes";

const require = createRequire(import.meta.url);
let wasmPresent = true;
try {
  require("../../../rust/wasm/pkg/dorado_wasm.js");
} catch {
  wasmPresent = false;
}

// Deterministic patterned bytes so failures reproduce exactly.
function patterned(len: number, seed: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = (i * 131 + seed * 89 + 7) & 0xff;
  return out;
}

function fastOpts(): PasswordOptions {
  const o = defaultOptions();
  o.kdf = { kind: KDF_PBKDF2, rounds: 1000 };
  return o;
}

const VARIANTS = [T256, T512, T1024] as const;
const MACS = [MAC_SKEIN, MAC_HMAC, MAC_BLAKE3] as const;

describe.skipIf(!wasmPresent)("ts/wasm backend equivalence", () => {
  it("CTR keystream is byte-identical across variants and lengths", () => {
    for (const v of VARIANTS) {
      const key = patterned(keyLen(v), 1);
      const tweak = patterned(16, 2);
      const iv = patterned(blockLen(v), 3);
      // Lengths chosen to hit empty input, a partial block, exact blocks, and a
      // multi-block tail crossing a counter increment.
      for (const len of [0, 1, blockLen(v) - 1, blockLen(v), blockLen(v) + 7, 1000]) {
        const data = patterned(len, 4);
        const a = tsBackend.ctr(v, key, tweak, iv, data);
        const b = wasmBackend.ctr(v, key, tweak, iv, data);
        expect(bytesToHex(b)).toBe(bytesToHex(a));
      }
    }
  });

  it("rawCTR through the engine is identical on both backends", () => {
    for (const v of VARIANTS) {
      const key = patterned(keyLen(v), 5);
      const tweak = patterned(16, 6);
      const iv = patterned(blockLen(v), 7);
      const data = patterned(777, 8);
      const a = rawCTR(v, key, tweak, iv, data, tsBackend);
      const b = rawCTR(v, key, tweak, iv, data, wasmBackend);
      expect(bytesToHex(b)).toBe(bytesToHex(a));
    }
  });

  it("Skein hash, Skein MAC, and BLAKE3 keyed MAC are identical", () => {
    const msg = patterned(300, 9);
    const skeinKey = patterned(64, 10);
    const b3Key = patterned(32, 11);
    for (const outLen of [32, 64]) {
      expect(bytesToHex(wasmBackend.skeinHash(outLen, msg))).toBe(bytesToHex(tsBackend.skeinHash(outLen, msg)));
      expect(bytesToHex(wasmBackend.skeinMac(skeinKey, outLen, msg))).toBe(
        bytesToHex(tsBackend.skeinMac(skeinKey, outLen, msg)),
      );
      expect(bytesToHex(wasmBackend.blake3KeyedMac(b3Key, outLen, msg))).toBe(
        bytesToHex(tsBackend.blake3KeyedMac(b3Key, outLen, msg)),
      );
    }
  });

  it("raw-key authenticated encrypt is byte-identical; decrypt works cross-backend", async () => {
    const v = T256;
    const key = patterned(keyLen(v), 12);
    const tweak = patterned(16, 13);
    const iv = patterned(blockLen(v), 14);
    const chunkSize = blockLen(v) * 2; // force multiple frames
    const pt = patterned(500, 15);
    for (const mac of MACS) {
      const a = await encryptRawAuthenticatedBytes(v, key, tweak, iv, mac, chunkSize, pt, tsBackend);
      const b = await encryptRawAuthenticatedBytes(v, key, tweak, iv, mac, chunkSize, pt, wasmBackend);
      expect(bytesToHex(b)).toBe(bytesToHex(a));
      // Each backend must accept the other's output (and its own).
      const viaWasm = await decryptRawAuthenticatedBytes(v, key, tweak, iv, mac, chunkSize, a, wasmBackend);
      const viaTs = await decryptRawAuthenticatedBytes(v, key, tweak, iv, mac, chunkSize, b, tsBackend);
      expect(bytesToHex(viaWasm)).toBe(bytesToHex(pt));
      expect(bytesToHex(viaTs)).toBe(bytesToHex(pt));
    }
  });

  it("password container: one fixed container decrypts identically on both backends", async () => {
    // The KDF is backend-independent, but run one end-to-end container through
    // both backends for confidence: encrypt once (random salt/IV live in the
    // header, so the container is fixed from then on), then decrypt the same
    // bytes with each backend and in the cross direction.
    const pw = utf8("differential-pw");
    const pt = patterned(300, 16);
    const opts = fastOpts();
    opts.chunkSize = 64; // multiple frames
    const ctTs = await encryptPasswordBytes(pw, opts, pt, tsBackend);
    expect(bytesToHex(await decryptPasswordBytes(pw, ctTs, undefined, tsBackend))).toBe(bytesToHex(pt));
    expect(bytesToHex(await decryptPasswordBytes(pw, ctTs, undefined, wasmBackend))).toBe(bytesToHex(pt));
    const ctWasm = await encryptPasswordBytes(pw, opts, pt, wasmBackend);
    expect(bytesToHex(await decryptPasswordBytes(pw, ctWasm, undefined, tsBackend))).toBe(bytesToHex(pt));
  });
});
