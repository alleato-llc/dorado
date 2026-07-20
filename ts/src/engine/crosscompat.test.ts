// Cross-compatibility: decrypt .mahi fixtures produced by the Rust reference (the
// baseline), one per KDF/MAC/variant plus a labeled and a multi-frame file.
// Checked-in regression guards that the TypeScript port stays byte-compatible with
// the shared format (on the default tsBackend, like the rest of the suite). The
// reverse direction is verified during development.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { decryptPasswordBytes, inspect, InvalidParamsError } from "./engine";
import { utf8, equalBytes } from "../bytes";

const PW = utf8("pw-cross");

function fixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url))));
}

describe("cross-compat with Rust fixtures", () => {
  for (const [name, expected] of [
    ["argon_skein_256.mahi", "rust argon+skein+256"],
    ["scrypt_hmac_512.mahi", "rust scrypt+hmac+512"],
    ["pbkdf2_blake3_1024.mahi", "rust pbkdf2+blake3+1024"],
  ] as const) {
    it(`decrypts ${name}`, async () => {
      expect(equalBytes(await decryptPasswordBytes(PW, fixture(name)), utf8(expected))).toBe(true);
    });
  }

  it("labeled fixture: label inspected, bound, and enforced", async () => {
    const data = fixture("labeled.mahi");
    expect(equalBytes(inspect(data).label, utf8("demo-context"))).toBe(true);
    expect(
      equalBytes(await decryptPasswordBytes(PW, data, utf8("demo-context")), utf8("rust labeled payload")),
    ).toBe(true);
    await expect(decryptPasswordBytes(PW, data, utf8("wrong"))).rejects.toBeInstanceOf(InvalidParamsError);
  });

  it("multi-frame fixture: 5000 bytes across frames", async () => {
    const back = await decryptPasswordBytes(PW, fixture("multichunk.mahi"));
    expect(back.length).toBe(5000);
    expect(back.every((b) => b === 0x78)).toBe(true);
  });
});
