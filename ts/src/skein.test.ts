import { describe, it, expect } from "vitest";
import { hash, mac } from "./skein";
import { bytesToHex, utf8, equalBytes } from "./bytes";

describe("Skein-512", () => {
  it("official empty 512 vector", () => {
    const want =
      "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4" +
      "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a";
    expect(bytesToHex(hash(64, new Uint8Array(0)))).toBe(want);
  });

  it('256-bit hash of "abc" (cross-checked against the Rust/Go ports)', () => {
    expect(bytesToHex(hash(32, utf8("abc")))).toBe(
      "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527",
    );
  });

  it("MAC is key- and message-sensitive", () => {
    const key = new Uint8Array(32).fill(0x9c);
    const a = mac(key, 32, utf8("authenticate me"));
    expect(a.length).toBe(32);
    expect(equalBytes(a, mac(new Uint8Array(32).fill(0x22), 32, utf8("authenticate me")))).toBe(false);
    expect(equalBytes(a, mac(key, 32, utf8("authenticate ne")))).toBe(false);
  });
});
