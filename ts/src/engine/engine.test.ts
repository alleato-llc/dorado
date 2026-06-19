import { describe, it, expect } from "vitest";
import { encryptPasswordBytes, decryptPasswordBytes, inspect, rawCTR, defaultOptions, type PasswordOptions } from "./engine";
import { KDF_PBKDF2, MAC_SKEIN, MAC_HMAC, MAC_BLAKE3, T256, T512, T1024, blockLen } from "./format";
import { utf8, equalBytes } from "../bytes";

function fastOpts(): PasswordOptions {
  const o = defaultOptions();
  o.kdf = { kind: KDF_PBKDF2, rounds: 1000 };
  return o;
}

describe("engine", () => {
  it("round-trip, wrong password, tampering", async () => {
    const pt = utf8("a secret message that spans more than nothing");
    const ct = await encryptPasswordBytes(utf8("pw"), fastOpts(), pt);
    expect(equalBytes(await decryptPasswordBytes(utf8("pw"), ct), pt)).toBe(true);
    await expect(decryptPasswordBytes(utf8("wrong"), ct)).rejects.toThrow();
    const bad = ct.slice();
    bad[bad.length - 1] ^= 1;
    await expect(decryptPasswordBytes(utf8("pw"), bad)).rejects.toThrow();
  });

  it("every MAC round-trips", async () => {
    for (const mac of [MAC_SKEIN, MAC_HMAC, MAC_BLAKE3] as const) {
      const o = fastOpts();
      o.mac = mac;
      const ct = await encryptPasswordBytes(utf8("pw"), o, utf8("authenticated by each MAC"));
      expect(equalBytes(await decryptPasswordBytes(utf8("pw"), ct), utf8("authenticated by each MAC"))).toBe(true);
    }
  });

  it("multi-chunk across variants", async () => {
    const pt = new Uint8Array(1000);
    for (let i = 0; i < pt.length; i++) pt[i] = i & 0xff;
    for (const v of [T256, T512, T1024] as const) {
      const o = fastOpts();
      o.variant = v;
      o.chunkSize = blockLen(v) * 2;
      const ct = await encryptPasswordBytes(utf8("pw"), o, pt);
      expect(equalBytes(await decryptPasswordBytes(utf8("pw"), ct), pt)).toBe(true);
    }
  });

  it("label binding and inspect", async () => {
    const o = fastOpts();
    o.label = utf8("backup-2026");
    const ct = await encryptPasswordBytes(utf8("pw"), o, utf8("secret"));
    const info = inspect(ct);
    expect(equalBytes(info.label, utf8("backup-2026"))).toBe(true);
    expect(info.version).toBe(4);
    expect(equalBytes(await decryptPasswordBytes(utf8("pw"), ct, utf8("backup-2026")), utf8("secret"))).toBe(true);
    await expect(decryptPasswordBytes(utf8("pw"), ct, utf8("other"))).rejects.toThrow();
  });

  it("truncation rejected", async () => {
    const o = fastOpts();
    o.chunkSize = 64;
    const pt = new Uint8Array(200);
    const ct = await encryptPasswordBytes(utf8("pw"), o, pt);
    for (const cut of [1, 33, 80, 150]) {
      await expect(decryptPasswordBytes(utf8("pw"), ct.subarray(0, ct.length - cut))).rejects.toThrow();
    }
  });

  it("raw CTR round-trips", () => {
    const key = new Uint8Array(32);
    const iv = new Uint8Array(32);
    const tweak = new Uint8Array(16);
    const pt = utf8("raw CTR, any length");
    const ct = rawCTR(T256, key, tweak, iv, pt);
    expect(equalBytes(ct, pt)).toBe(false);
    expect(equalBytes(rawCTR(T256, key, tweak, iv, ct), pt)).toBe(true);
  });
});
