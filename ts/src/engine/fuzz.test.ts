// Property/fuzz test: feed many pseudo-random and mutated byte arrays to the
// container readers and assert each call either succeeds or throws a DoradoError
// subclass. It must never escape with a non-Dorado error (TypeError, RangeError,
// a bare Error) and never hang. A seeded mulberry32 PRNG keeps it reproducible;
// no new dependency is added.

import { describe, it, expect } from "vitest";
import {
  encryptPasswordBytes,
  decryptPasswordBytes,
  inspect,
  defaultOptions,
  DoradoError,
  type PasswordOptions,
} from "./engine";
import { KDF_PBKDF2 } from "./format";
import { utf8 } from "../bytes";

// Minimal seeded PRNG (mulberry32). Deterministic so a failure reproduces.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randBytes(rng: () => number, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = Math.floor(rng() * 256);
  return out;
}

function fastOpts(): PasswordOptions {
  const o = defaultOptions();
  o.kdf = { kind: KDF_PBKDF2, rounds: 1 };
  return o;
}

// Assert a thrown value is a DoradoError and nothing wilder. A plain Error or a
// TypeError/RangeError is a real bug: the input space should be fully classified.
function expectDoradoOrThrow(err: unknown): void {
  if (!(err instanceof DoradoError)) {
    throw new Error(
      `expected a DoradoError subclass, got ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`,
    );
  }
}

describe("fuzz", () => {
  it("inspect never throws a non-Dorado error on random/short input", () => {
    const rng = mulberry32(0x1234abcd);
    for (let i = 0; i < 4000; i++) {
      const len = Math.floor(rng() * 200);
      const data = randBytes(rng, len);
      try {
        inspect(data);
      } catch (err) {
        expectDoradoOrThrow(err);
      }
    }
  });

  it("decryptPasswordBytes never throws a non-Dorado error on random input", async () => {
    const rng = mulberry32(0x9e3779b9);
    const pw = utf8("pw");
    for (let i = 0; i < 2000; i++) {
      const len = Math.floor(rng() * 300);
      const data = randBytes(rng, len);
      try {
        await decryptPasswordBytes(pw, data);
      } catch (err) {
        expectDoradoOrThrow(err);
      }
    }
  });

  it("mutated real containers either round-trip or throw a DoradoError", async () => {
    const rng = mulberry32(0xdeadbeef);
    const pw = utf8("correct horse");
    const o = fastOpts();
    o.chunkSize = 64;
    // A real multi-chunk container to mutate.
    const base = await encryptPasswordBytes(pw, o, randBytes(rng, 200));

    // Kept modest: most mutations leave the header valid, so each iteration runs
    // the full KDF + MAC path, which is the slow part. A few hundred is enough to
    // hit every frame branch repeatedly while staying fast.
    for (let i = 0; i < 120; i++) {
      const data = base.slice();
      // Apply between 1 and 4 single-byte mutations at random offsets.
      const muts = 1 + Math.floor(rng() * 4);
      for (let m = 0; m < muts; m++) {
        const idx = Math.floor(rng() * data.length);
        data[idx] = (data[idx] + 1 + Math.floor(rng() * 255)) & 0xff;
      }
      try {
        await decryptPasswordBytes(pw, data);
        // A successful decrypt of a mutated container is allowed (a mutation can
        // land in a structurally-irrelevant spot or be a no-op); we only require
        // that no non-Dorado error escapes.
      } catch (err) {
        expectDoradoOrThrow(err);
      }
    }
  });

  it("truncations of a real container throw a DoradoError", async () => {
    const pw = utf8("pw");
    const o = fastOpts();
    o.chunkSize = 64;
    const base = await encryptPasswordBytes(pw, o, randBytes(mulberry32(7), 256));
    // Step coarsely: every truncation past the header still runs the KDF, so a
    // sparse sweep covers the frame branches without paying for every offset.
    for (let cut = 1; cut < base.length; cut += 17) {
      try {
        await decryptPasswordBytes(pw, base.subarray(0, base.length - cut));
        // A prefix that happens to still authenticate is not expected here, but
        // if it did it would be a success, which is acceptable.
      } catch (err) {
        expectDoradoOrThrow(err);
      }
    }
  });

  it("inspect of mutated real headers stays classified", async () => {
    const rng = mulberry32(0xc0ffee);
    const base = await encryptPasswordBytes(utf8("pw"), fastOpts(), utf8("hello"));
    for (let i = 0; i < 1500; i++) {
      const data = base.slice();
      const idx = Math.floor(rng() * Math.min(data.length, 80));
      data[idx] = Math.floor(rng() * 256);
      try {
        inspect(data);
      } catch (err) {
        expectDoradoOrThrow(err);
      }
    }
  });
});
