import { describe, it, expect } from "vitest";
import * as chacha from "./chacha";
import { mac, Poly1305 } from "./poly1305";
import { seal, open, sealInPlace, openInPlace } from "./chacha20poly1305";
import { hexToBytes, bytesToHex, utf8, equalBytes } from "./bytes";

describe("ChaCha20 (RFC 8439)", () => {
  it("block function 2.3.2", () => {
    const key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const nonce = hexToBytes("000000090000004a00000000");
    const want =
      "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
      "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
    expect(bytesToHex(chacha.block(key, 1, nonce))).toBe(want);
  });

  it("encryption 2.4.2 round-trips", () => {
    const key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const nonce = hexToBytes("000000000000004a00000000");
    const pt = utf8(
      "Ladies and Gentlemen of the class of '99: " +
        "If I could offer you only one tip for the future, sunscreen would be it.",
    );
    const want =
      "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
      "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
      "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
      "5af90bbf74a35be6b40b8eedf2785e42874d";
    const buf = pt.slice();
    chacha.apply(key, 1, nonce, buf);
    expect(bytesToHex(buf)).toBe(want);
    chacha.apply(key, 1, nonce, buf);
    expect(equalBytes(buf, pt)).toBe(true);
  });
});

describe("Poly1305 (RFC 8439)", () => {
  it("tag 2.5.2", () => {
    const key = hexToBytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    const tag = mac(key, utf8("Cryptographic Forum Research Group"));
    expect(bytesToHex(tag)).toBe("a8061dc1305136c6c22b8baf0c0127a9");
  });

  it("incremental matches one-shot", () => {
    const key = new Uint8Array(32).fill(0x24);
    const msg = new Uint8Array(200);
    for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;
    const want = mac(key, msg);
    for (const step of [1, 3, 7, 16, 31, 64]) {
      const p = new Poly1305(key);
      for (let i = 0; i < msg.length; i += step) p.update(msg.subarray(i, Math.min(i + step, msg.length)));
      expect(equalBytes(p.finalize(), want)).toBe(true);
    }
  });
});

describe("ChaCha20-Poly1305 (RFC 8439 2.8.2)", () => {
  const key = hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const nonce = hexToBytes("070000004041424344454647");
  const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
  const pt = utf8(
    "Ladies and Gentlemen of the class of '99: " +
      "If I could offer you only one tip for the future, sunscreen would be it.",
  );

  it("seal matches the vector and open round-trips", () => {
    const [ct, tag] = seal(key, nonce, aad, pt);
    expect(bytesToHex(tag)).toBe("1ae10b594f09e26a7e902ecbd0600691");
    const got = open(key, nonce, aad, ct, tag);
    expect(equalBytes(got, pt)).toBe(true);
  });

  it("rejects tampering and wrong aad", () => {
    const [ct, tag] = seal(key, nonce, aad, pt);
    const bad = ct.slice();
    bad[0] ^= 1;
    expect(() => open(key, nonce, aad, bad, tag)).toThrow();
    expect(() => open(key, nonce, hexToBytes("00"), ct, tag)).toThrow();
  });

  it("in-place matches the allocating form", () => {
    const buf = pt.slice();
    const tag = sealInPlace(key, nonce, aad, buf);
    const [ct, tag2] = seal(key, nonce, aad, pt);
    expect(equalBytes(buf, ct)).toBe(true);
    expect(equalBytes(tag, tag2)).toBe(true);
    openInPlace(key, nonce, aad, buf, tag);
    expect(equalBytes(buf, pt)).toBe(true);
  });
});
