import { describe, it, expect } from "vitest";
import {
  encryptPasswordBytes,
  decryptPasswordBytes,
  inspect,
  rawCTR,
  encryptRawAuthenticatedBytes,
  decryptRawAuthenticatedBytes,
  defaultOptions,
  AuthError,
  InvalidParamsError,
  MalformedContainerError,
  type PasswordOptions,
} from "./engine";
import { KDF_PBKDF2, MAC_SKEIN, MAC_HMAC, MAC_BLAKE3, T256, T512, T1024, blockLen, type MacId, type Variant } from "./format";
import { utf8, equalBytes, hexToBytes } from "../bytes";

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
    // Wrong password and tampering must both surface as the same AuthError class
    // and message so the two stay indistinguishable.
    const wrongPw = await decryptPasswordBytes(utf8("wrong"), ct).catch((e) => e);
    expect(wrongPw).toBeInstanceOf(AuthError);
    const bad = ct.slice();
    bad[bad.length - 1] ^= 1;
    const tampered = await decryptPasswordBytes(utf8("pw"), bad).catch((e) => e);
    expect(tampered).toBeInstanceOf(AuthError);
    expect(tampered.message).toBe(wrongPw.message);
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
    await expect(decryptPasswordBytes(utf8("pw"), ct, utf8("other"))).rejects.toBeInstanceOf(InvalidParamsError);
  });

  it("truncation rejected", async () => {
    const o = fastOpts();
    o.chunkSize = 64;
    const pt = new Uint8Array(200);
    const ct = await encryptPasswordBytes(utf8("pw"), o, pt);
    for (const cut of [1, 33, 80, 150]) {
      await expect(
        decryptPasswordBytes(utf8("pw"), ct.subarray(0, ct.length - cut)),
      ).rejects.toBeInstanceOf(MalformedContainerError);
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

// Known-answer vectors from ../../../docs/fixtures/raw-authenticated.md,
// generated from and verified against the Rust reference. These are the
// cross-language compatibility proof for raw-authenticated mode.
interface RawAuthVector {
  name: string;
  variant: Variant;
  mac: MacId;
  chunkKib: number;
  key: string;
  iv: string;
  tweak: string;
  plaintext: string;
  ciphertext: string;
}

const SINGLE_PLAINTEXT =
  "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573";

const RAW_AUTH_VECTORS: RawAuthVector[] = [
  {
    name: "t256_skein_single",
    variant: T256,
    mac: MAC_SKEIN,
    chunkKib: 64,
    key: "1111111111111111111111111111111111111111111111111111111111111111",
    iv: "0202020202020202020202020202020202020202020202020202020202020202",
    tweak: "00000000000000000000000000000000",
    plaintext: SINGLE_PLAINTEXT,
    ciphertext:
      "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8961a7bb9296d0da601e3aba580a70532ad6b83e8fc1050620de95d5ba50e545621",
  },
  {
    name: "t256_hmac_single",
    variant: T256,
    mac: MAC_HMAC,
    chunkKib: 64,
    key: "1111111111111111111111111111111111111111111111111111111111111111",
    iv: "0202020202020202020202020202020202020202020202020202020202020202",
    tweak: "00000000000000000000000000000000",
    plaintext: SINGLE_PLAINTEXT,
    ciphertext:
      "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8968381b4daded95b311377792e768eee91a63e2346b585ac3eda337afd6ed6dfff",
  },
  {
    name: "t256_blake3_single",
    variant: T256,
    mac: MAC_BLAKE3,
    chunkKib: 64,
    key: "1111111111111111111111111111111111111111111111111111111111111111",
    iv: "0202020202020202020202020202020202020202020202020202020202020202",
    tweak: "00000000000000000000000000000000",
    plaintext: SINGLE_PLAINTEXT,
    ciphertext:
      "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b896815761a7e9f6762a4a0dd0de969ab2bf00e7d04304b45fb53984b5e29deb9834",
  },
  {
    name: "t512_skein_single",
    variant: T512,
    mac: MAC_SKEIN,
    chunkKib: 64,
    key: "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    iv: "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
    tweak: "00000000000000000000000000000000",
    plaintext: SINGLE_PLAINTEXT,
    ciphertext:
      "010000003e9b6cf38a329d996ff458a80a5993a2fbbb8b29237d5561b5a7883b2b47eb06ca7ea842953feb5ebf6aec6b95d17c646a8294b66e6f04a98ffc255ee4e62d44f0b6fa861dc2ea6a8be5fd71b60863900177af52c649ede00952bde11f1394",
  },
  {
    name: "t1024_skein_single",
    variant: T1024,
    mac: MAC_SKEIN,
    chunkKib: 64,
    key: "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    iv: "0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
    tweak: "00000000000000000000000000000000",
    plaintext: SINGLE_PLAINTEXT,
    ciphertext:
      "010000003ef55cd4e609b16c109712985cc509501cd194befaa963a620c123816bd9fd494f85cd899f2a52b005a0fb1105fe6706ceb7f937573662a11b14b53c939c8ade26889e72113babe3236093b8855432a67c45888b131be41f72cd890a724f0f",
  },
  {
    name: "t256_skein_multichunk",
    variant: T256,
    mac: MAC_SKEIN,
    chunkKib: 1,
    key: "1111111111111111111111111111111111111111111111111111111111111111",
    iv: "0202020202020202020202020202020202020202020202020202020202020202",
    tweak: "00000000000000000000000000000000",
    plaintext:
      "61206c6f6e676572207061796c6f6164206d65616e7420746f207370616e206d756c7469706c65206f6e652d6b696c6f627974652061757468656e74696361746564206368756e6b7320736f207468652063726f73732d6c616e6775616765206669787475726520616c736f206578657263697365732074686520636f6e74696e756f757320636f756e74657220616e64207065722d6672616d652074616767696e67206163726f7373206368756e6b20626f756e6461726965732c206e6f74206a75737420612073696e676c65206672616d652e20787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
    ciphertext:
      "0000000400f22a092b48a93449b906d28f4e1d30649ff11c6761b40436f8837cfa9715f834310c46654feabc437288741b5f16b5ff8bab79018d524a3a5bc2f307b486959bdb2b43f608b3a624af1d302506d312ff8c536eee10f553ab87e39697249ea5f92050c9ee832a8c8c2d7e4dffba0d5b3650a65d4ec8ef92c6ec60d2030c334e56e091654db2e1ad8e3cbc921f7092bc34afc8d41226526e31b1da8240da06169ef5643695b82247984b334e4842a34b88789ff0886098e002521245065ba7e1550136a7817ed24f451cc0a1f8c778dbc3febc1e0de9fd4810f7077c85a8ac7dd49b0c34546708ccba6babcc1391a2f0d2d0e44f848f5f8d894f48d2b2f0f8854bb6257179d883d55cf7b21c5c764fb1008f582917a6d54ddd75209c39814a1f0c795fcdcf11fb69fa36bbbdf9d798338cf01a20326fc4c4d9e0ce7d874cd0f6b5bc493dcfaac173f8259f597a1d28c72e92e2b47a7573857e0dd47b1ef6192b97434fdc7572f5ed93c4eee4b0466bed9246a037334cc319ab9d06830edccd3bca5ef2e69769a4d2a57b5d3cde17381ba1d5dee0f828ff67b0b31b1f78d6684a2ef8596c0cf60ba76834ce054fb4f7e524df218c21c2f552f74e445efbbc24c8b29df788c92b0c0a08251583fa6f0dbc187ff8dc11f572160e9f813aa04868a69ca4c0f8b111d5213ef4d7e7be43d34c4db41241764093e1f259ce6430b754aaeeaa5fd010334928380060453213fde390d7d1b36f0f34242b5856df0e13f6bcc351c557c3b4b0fb5db5382bf229818a094b9ad714d0d73ba734da002a4c1fdf9613c25556ed9cb350f1d17a863ddb72a13688f51e7e56f9f6d97fcf1b7f050c4a5f45c0760ae09f19fdccebc47d48cb6a22de0b2327a30f19038b2bf06e69e3229fd9db1b55dad18a30bc67f3b4670a35b9c17884feb94f6c7b1183faadb7c60768c34e098754d59ce4b057249e5a7e0fc37a84925d8582a996e3ff38a3e844711f444a8ad1bbcda549b9d3b3d1f1a1c436cca8bd093056207951372661e6f1d673d04279a7bbb35bccb5bc5b16053506d66c0171417a7428b40e117b21f20d73ffd4a0b4c31a8314fc41415f23ea59fb375e090a1442f3a99b46ffcb2db05ae459912ace292e382feddede89ce478b2f09072e8415442d5208e7be684406bcd8d1daf671471c875e9473d23be31ae5cb4dd59166fca876d33c1bc4354275ac62acc6e797e78c6255fc4aa500776fdd556364c98c0c0bdb00f897bdf6e782a74a65b67539a0b5d2d0d18fb3368d45913b2e1cac5e4b6c6c790c0327b2fd8569c1182a945859c9fed3e0009cf6067ff4910f6fab39d77d8da052a1aec80b115391f717475e9f8ab01ca3a2e7f4ed45e15cb8590c01f6274aae9b75e3852fce44b07f41bfe18777395112bbafbfab1be72df1be7a16e502d3385ff547f083bab16cd43d57f00d8fcce0595e3b57f18b2ca2da0f94f8c42bdc5237a41673617ea43d010000018657d51b2abd9a7809306c46b7c1020a729dd1efddc182b7412e45fae64f45b3e33ad6440f1d827977eb3f5b3e583d718a8c0fb43d4b00d557dc9a7afeef9a361a3a18014fa545baa6a184836a082798c4de40c82b96a5a5cd557fb4a8e15d6d0d5f411e6083b3f2c14b716c7a4d5167e077b1a2ded34f9e30eea332309801843ea53f53bea4f265ee8176a28c08b80f0189d754bef399ebd1c4407432af717dd7b949f8eee02cf4dca067b4b6cd7f50dd53b8bff3e35af9352d0d62b3ccf4d3f5af2eb8ed593200c1826984322967bf1bd6f682ff312690bf64c277bad2ab306931e97e23dd5790127921af7d16617456c585b835117b08621c40dddd38929d0728da224e31dd1d2d5461b2ce6e162f41436c92b5515223aa3f9572ab9ede606fb0c2c94545cc6221179aa6c11508e2dc6f1be11d8c82d051609ca26b397fffdbfd26d76301e1ecc03ab9699df7863eeee1a9bdd861c71319b3195e32215a56ada80234a28b8c31376c6846df120d9f0eb0979b618dd62b78e2fb886e7412cd9137451c75ace33797024dadf2784b969e1c56a81088dd5ac19c8a6061d2c9519c4309170d8192",
  },
];

describe("raw-authenticated (encrypt-then-MAC, caller-supplied key)", () => {
  for (const v of RAW_AUTH_VECTORS) {
    it(`KAT: ${v.name} encrypts to the exact fixture ciphertext`, async () => {
      const key = hexToBytes(v.key);
      const iv = hexToBytes(v.iv);
      const tweak = hexToBytes(v.tweak);
      const pt = hexToBytes(v.plaintext);
      const expectedCt = hexToBytes(v.ciphertext);
      const ct = await encryptRawAuthenticatedBytes(v.variant, key, tweak, iv, v.mac, v.chunkKib * 1024, pt);
      expect(equalBytes(ct, expectedCt)).toBe(true);
    });

    it(`KAT: ${v.name} decrypts to the exact fixture plaintext`, async () => {
      const key = hexToBytes(v.key);
      const iv = hexToBytes(v.iv);
      const tweak = hexToBytes(v.tweak);
      const pt = hexToBytes(v.plaintext);
      const ct = hexToBytes(v.ciphertext);
      const decrypted = await decryptRawAuthenticatedBytes(v.variant, key, tweak, iv, v.mac, v.chunkKib * 1024, ct);
      expect(equalBytes(decrypted, pt)).toBe(true);
    });
  }

  it("round-trips with an arbitrary key/iv for a non-256 variant", async () => {
    const key = new Uint8Array(64);
    const iv = new Uint8Array(64);
    const tweak = new Uint8Array(16);
    crypto.getRandomValues(key);
    crypto.getRandomValues(iv);
    crypto.getRandomValues(tweak);
    const pt = utf8("a T512 raw-authenticated round trip with a random key, iv, and tweak");
    const ct = await encryptRawAuthenticatedBytes(T512, key, tweak, iv, MAC_SKEIN, 4096, pt);
    expect(equalBytes(await decryptRawAuthenticatedBytes(T512, key, tweak, iv, MAC_SKEIN, 4096, ct), pt)).toBe(true);
  });

  it("every MAC round-trips and rejects tampering", async () => {
    const key = new Uint8Array(32);
    const iv = new Uint8Array(32);
    const tweak = new Uint8Array(16);
    crypto.getRandomValues(key);
    crypto.getRandomValues(iv);
    for (const mac of [MAC_SKEIN, MAC_HMAC, MAC_BLAKE3] as const) {
      const pt = utf8("authenticated by each MAC option");
      const ct = await encryptRawAuthenticatedBytes(T256, key, tweak, iv, mac, 4096, pt);
      expect(equalBytes(await decryptRawAuthenticatedBytes(T256, key, tweak, iv, mac, 4096, ct), pt)).toBe(true);

      const tampered = ct.slice();
      tampered[tampered.length - 1] ^= 1;
      await expect(
        decryptRawAuthenticatedBytes(T256, key, tweak, iv, mac, 4096, tampered),
      ).rejects.toBeInstanceOf(AuthError);
    }
  });

  it("tamper detection: flipping any ciphertext byte (including the tag) is rejected", async () => {
    const v = RAW_AUTH_VECTORS[0];
    const key = hexToBytes(v.key);
    const iv = hexToBytes(v.iv);
    const tweak = hexToBytes(v.tweak);
    const ct = hexToBytes(v.ciphertext);
    for (const idx of [0, 5, ct.length - 1, ct.length - 32]) {
      const bad = ct.slice();
      bad[idx] ^= 1;
      await expect(
        decryptRawAuthenticatedBytes(v.variant, key, tweak, iv, v.mac, v.chunkKib * 1024, bad),
      ).rejects.toBeInstanceOf(AuthError);
    }
  });

  it("wrong key is rejected", async () => {
    const v = RAW_AUTH_VECTORS[0];
    const wrongKey = hexToBytes(v.key);
    wrongKey[0] ^= 1;
    const iv = hexToBytes(v.iv);
    const tweak = hexToBytes(v.tweak);
    const ct = hexToBytes(v.ciphertext);
    await expect(
      decryptRawAuthenticatedBytes(v.variant, wrongKey, tweak, iv, v.mac, v.chunkKib * 1024, ct),
    ).rejects.toBeInstanceOf(AuthError);
  });

  it("mismatched tweak or IV is rejected (ciphertext/tag held fixed)", async () => {
    // The tweak and IV are bound into frame 0's AAD, not just used for the
    // keystream, so swapping either alone (holding ciphertext and tag fixed)
    // must fail rather than silently produce different plaintext.
    const v = RAW_AUTH_VECTORS[0];
    const key = hexToBytes(v.key);
    const iv = hexToBytes(v.iv);
    const tweak = hexToBytes(v.tweak);
    const ct = hexToBytes(v.ciphertext);

    const wrongTweak = tweak.slice();
    wrongTweak[0] ^= 1;
    await expect(
      decryptRawAuthenticatedBytes(v.variant, key, wrongTweak, iv, v.mac, v.chunkKib * 1024, ct),
    ).rejects.toBeInstanceOf(AuthError);

    const wrongIv = iv.slice();
    wrongIv[0] ^= 1;
    await expect(
      decryptRawAuthenticatedBytes(v.variant, key, tweak, wrongIv, v.mac, v.chunkKib * 1024, ct),
    ).rejects.toBeInstanceOf(AuthError);
  });
});
