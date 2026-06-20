import { describe, it, expect } from "vitest";
import { chunkCapFrom, DEFAULT_MAX_CHUNK_BYTES, MAX_CHUNK_BYTES } from "./format";

describe("chunkCapFrom", () => {
  it("undefined yields the default cap", () => {
    expect(chunkCapFrom(undefined)).toBe(DEFAULT_MAX_CHUNK_BYTES);
  });

  it("empty or whitespace yields the default cap", () => {
    expect(chunkCapFrom("")).toBe(DEFAULT_MAX_CHUNK_BYTES);
    expect(chunkCapFrom("   ")).toBe(DEFAULT_MAX_CHUNK_BYTES);
  });

  it("unparseable yields the default cap", () => {
    expect(chunkCapFrom("abc")).toBe(DEFAULT_MAX_CHUNK_BYTES);
    expect(chunkCapFrom("12x")).toBe(DEFAULT_MAX_CHUNK_BYTES);
    expect(chunkCapFrom("1.5")).toBe(DEFAULT_MAX_CHUNK_BYTES);
    expect(chunkCapFrom("-1")).toBe(DEFAULT_MAX_CHUNK_BYTES);
    expect(chunkCapFrom("Infinity")).toBe(DEFAULT_MAX_CHUNK_BYTES);
  });

  it("a plain value passes through", () => {
    expect(chunkCapFrom("1048576")).toBe(1048576);
  });

  it("0 is clamped up to 1", () => {
    expect(chunkCapFrom("0")).toBe(1);
  });

  it("a value above 1 GiB is clamped to the hard ceiling", () => {
    expect(chunkCapFrom(String(MAX_CHUNK_BYTES + 1))).toBe(MAX_CHUNK_BYTES);
    expect(chunkCapFrom("9999999999")).toBe(MAX_CHUNK_BYTES);
  });
});
