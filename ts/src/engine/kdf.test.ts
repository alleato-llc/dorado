import { describe, it, expect } from "vitest";
import { deriveFromPassword, deriveFromKey, deriveFromKeyWith, validate, type KdfPrf } from "./kdf";
import { InvalidParamsError } from "./errors";
import { KDF_ARGON2ID, KDF_PBKDF2, KDF_SCRYPT } from "./format";
import { utf8, equalBytes, hexToBytes, bytesToHex } from "../bytes";

// Known-answer vectors from ../../../docs/fixtures/derive-from-key.md,
// generated from the Rust reference (dorado-engine::kdf::derive_from_key_with).
// out = PRF(key = caller_key, out_len, msg = "DRDOkdrv" || domain_utf8).
interface DeriveFromKeyVector {
  name: string;
  prf: KdfPrf;
  key: string;
  domain: string;
  outLen: number;
  out: string;
}

const DERIVE_FROM_KEY_VECTORS: DeriveFromKeyVector[] = [
  {
    name: "skein_32key_enc_32out",
    prf: "skein512",
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    domain: "dorado/fixture/enc",
    outLen: 32,
    out: "b638c503342dbd51bdfa8906b1cc6b18d7e54252b95e460c522ab3cd939802c6",
  },
  {
    name: "skein_32key_mac_64out",
    prf: "skein512",
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    domain: "dorado/fixture/mac",
    outLen: 64,
    out: "6ae3f6f7518e9a4c8a7be8269deb848186beb64b5b43f0bafef81bce4b27d40ef227e2064b941069cc6225cad0a39fcc22aba08fb87f3ba8aacdf4b70b100da6",
  },
  {
    name: "skein_16key_enc_32out",
    prf: "skein512",
    key: "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
    domain: "dorado/fixture/enc",
    outLen: 32,
    out: "3990e038c7235e62480afe99712203225194afb93910df4101447098e630d0e4",
  },
  {
    name: "skein_32key_empty_domain_32out",
    prf: "skein512",
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    domain: "",
    outLen: 32,
    out: "5bba4214745b3932c1fc620c660b60a4058613ff2bd9d80224d472cd810f7a99",
  },
  {
    name: "blake3_32key_enc_32out",
    prf: "blake3",
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    domain: "dorado/fixture/enc",
    outLen: 32,
    out: "8266bd0cfb0d73715aa841fe008c311a44d6b36e0aa01b94f13a90783fe62e1d",
  },
  {
    name: "blake3_32key_mac_64out",
    prf: "blake3",
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    domain: "dorado/fixture/mac",
    outLen: 64,
    out: "ea38a1780192707518d15003262a66c245680a579762a7d863cc33078f2f6eaa9a5086f70d00eb7c6cd12fdc7872e5a2023e63c28087631ce835d7e9c7264290",
  },
];

describe("deriveFromKey (key-based derivation)", () => {
  for (const v of DERIVE_FROM_KEY_VECTORS) {
    it(`KAT: ${v.name} matches the fixture bytes`, () => {
      const out = deriveFromKeyWith(v.prf, hexToBytes(v.key), v.domain, v.outLen);
      expect(bytesToHex(out)).toBe(v.out);
      if (v.prf === "skein512") {
        // The default, PRF-less form is defined as the Skein-512 case and must
        // match the same vectors byte-for-byte.
        expect(bytesToHex(deriveFromKey(hexToBytes(v.key), v.domain, v.outLen))).toBe(v.out);
      }
    });
  }

  it("is deterministic and domain-separated", () => {
    const master = new Uint8Array(32).fill(0x42);
    const a = deriveFromKey(master, "myapp/index", 32);
    const b = deriveFromKey(master, "myapp/index", 32);
    expect(equalBytes(a, b)).toBe(true); // same key + domain, same bytes

    const c = deriveFromKey(master, "myapp/data", 32);
    expect(equalBytes(a, c)).toBe(false); // a different domain, a different key

    const other = new Uint8Array(32).fill(0x43);
    const d = deriveFromKey(other, "myapp/index", 32);
    expect(equalBytes(a, d)).toBe(false); // a different master, a different key

    // Children reveal nothing about each other or the master: at minimum,
    // none of them may equal the master or one another.
    expect(equalBytes(a, master)).toBe(false);
    expect(equalBytes(c, master)).toBe(false);
  });

  it("supports arbitrary output lengths (Skein binds the length)", () => {
    // The 1024-bit variant's raw mode needs 128-byte keys; Skein's output
    // length is free, so longer outputs must work and must not merely
    // prefix-extend shorter ones (the length is bound into the hash).
    const master = new Uint8Array(32).fill(0x42);
    const short = deriveFromKey(master, "myapp/index", 32);
    const long = deriveFromKey(master, "myapp/index", 128);
    expect(long.length).toBe(128);
    expect(equalBytes(short, long.subarray(0, 32))).toBe(false);
  });

  it("the default form matches the skein512 PRF byte-for-byte", () => {
    const master = new Uint8Array(32).fill(0x42);
    const a = deriveFromKey(master, "myapp/index", 32);
    const b = deriveFromKeyWith("skein512", master, "myapp/index", 32);
    expect(equalBytes(a, b)).toBe(true);
  });

  it("blake3 is deterministic, domain-separated, and distinct from skein", () => {
    const master = new Uint8Array(32).fill(0x42);
    const a = deriveFromKeyWith("blake3", master, "myapp/index", 32);
    const b = deriveFromKeyWith("blake3", master, "myapp/index", 32);
    expect(equalBytes(a, b)).toBe(true);

    const c = deriveFromKeyWith("blake3", master, "myapp/data", 32);
    expect(equalBytes(a, c)).toBe(false);
    expect(equalBytes(a, master)).toBe(false); // a child never equals the master

    // The two PRFs are independent functions: the same key/domain under Skein
    // and under BLAKE3 must not coincide.
    const skein = deriveFromKeyWith("skein512", master, "myapp/index", 32);
    expect(equalBytes(a, skein)).toBe(false);
  });

  it("blake3 supports arbitrary output lengths (XOF: shorter is a prefix)", () => {
    const master = new Uint8Array(32).fill(0x42);
    const short = deriveFromKeyWith("blake3", master, "myapp/index", 32);
    const long = deriveFromKeyWith("blake3", master, "myapp/index", 128);
    expect(long.length).toBe(128);
    expect(equalBytes(short, long.subarray(0, 32))).toBe(true);
  });

  it("blake3 rejects a non-32-byte key", () => {
    expect(() => deriveFromKeyWith("blake3", new Uint8Array(16), "myapp/index", 32)).toThrowError(
      InvalidParamsError,
    );
    expect(() => deriveFromKeyWith("blake3", new Uint8Array(16), "myapp/index", 32)).toThrowError(
      /32-byte key/,
    );
  });
});

describe("deriveFromPassword", () => {
  it("pbkdf2 is deterministic and salt-sensitive", async () => {
    const params = { kind: KDF_PBKDF2, rounds: 1000 };
    const a = await deriveFromPassword(params, utf8("password"), utf8("saltsalt"), 32);
    const b = await deriveFromPassword(params, utf8("password"), utf8("saltsalt"), 32);
    expect(equalBytes(a, b)).toBe(true); // same inputs, same key

    const c = await deriveFromPassword(params, utf8("password"), utf8("different"), 32);
    expect(equalBytes(a, c)).toBe(false); // a different salt, a different key
  });
});

describe("validate", () => {
  it("accepts sane params and rejects absurd or zero pbkdf2 rounds", () => {
    // Defaults are fine.
    expect(() => validate({ kind: KDF_ARGON2ID, mCost: 64 * 1024, tCost: 3, pCost: 1 })).not.toThrow();
    expect(() => validate({ kind: KDF_SCRYPT, logN: 15, r: 8, p: 1 })).not.toThrow();
    expect(() => validate({ kind: KDF_PBKDF2, rounds: 600_000 })).not.toThrow();

    // Absurd costs (as a crafted header might carry) are rejected.
    expect(() => validate({ kind: KDF_PBKDF2, rounds: 0xffffffff })).toThrowError(InvalidParamsError);
    // Zero rounds would "derive" an all-zero key without error.
    expect(() => validate({ kind: KDF_PBKDF2, rounds: 0 })).toThrowError("pbkdf2 rounds must be nonzero");
  });
});
