import { describe, it, expect } from "vitest";
import { findPattern, hexDump, parseHexPattern } from "../src/inspect/bytes.js";
import { makeElf64 } from "./helpers.js";

describe("parseHexPattern", () => {
  it("parses spaced hex pairs", () => {
    expect(parseHexPattern("4d 5a 90 00")).toEqual([0x4d, 0x5a, 0x90, 0x00]);
  });

  it("parses contiguous hex", () => {
    expect(parseHexPattern("4d5a9000")).toEqual([0x4d, 0x5a, 0x90, 0x00]);
  });

  it("parses wildcards in both forms", () => {
    expect(parseHexPattern("4d ?? ?? 00")).toEqual([0x4d, null, null, 0x00]);
    expect(parseHexPattern("4d5a??00")).toEqual([0x4d, 0x5a, null, 0x00]);
  });

  it("rejects invalid tokens and empty patterns", () => {
    expect(() => parseHexPattern("zz 5a")).toThrow(/Invalid/);
    expect(() => parseHexPattern("   ")).toThrow(/Empty/);
    expect(() => parseHexPattern("4d 5g")).toThrow(/Invalid/);
  });

  it("rejects patterns longer than 64 bytes", () => {
    expect(() => parseHexPattern(Array.from({ length: 65 }, () => "00").join(" "))).toThrow(/too long/);
  });
});

describe("findPattern", () => {
  const elf = makeElf64();

  it("finds the ELF magic at offset 0", () => {
    const result = findPattern(elf, "7f 45 4c 46");
    expect(result.offsets).toContain(0);
    expect(result.totalMatches).toBeGreaterThanOrEqual(1);
  });

  it("finds nothing when the pattern is absent", () => {
    const result = findPattern(elf, "de ad be ef ca fe ba be");
    expect(result.offsets).toEqual([]);
    expect(result.totalMatches).toBe(0);
  });

  it("supports wildcards and caps results", () => {
    const haystack = new Uint8Array(64).fill(0);
    haystack[4] = 0xaa;
    haystack[20] = 0xaa;
    haystack[36] = 0xaa;
    const result = findPattern(haystack, "?? aa", 2);
    expect(result.totalMatches).toBe(3);
    expect(result.offsets).toEqual([3, 19]);
    expect(result.truncated).toBe(true);
  });
});

describe("hexDump", () => {
  it("renders offsets, hex pairs and the ASCII gutter", () => {
    const buf = Buffer.from("Hello, reverso!!", "ascii");
    const dump = hexDump(new Uint8Array(buf), 0, buf.length, 16);
    expect(dump).toContain("00000000");
    expect(dump).toContain("48 65 6c 6c 6f");
    expect(dump).toContain("|Hello, reverso!!|");
  });

  it("clamps offset and length to the buffer", () => {
    const buf = new Uint8Array([1, 2, 3]);
    expect(hexDump(buf, 100, 16, 16)).toBe("");
    const dump = hexDump(buf, 0, 100, 16);
    expect(dump).toContain("01 02 03");
  });

  it("replaces non-printable bytes with dots", () => {
    const buf = new Uint8Array([0x00, 0x41, 0x7f]);
    expect(hexDump(buf, 0, 3, 16)).toContain("|.A.|");
  });
});
