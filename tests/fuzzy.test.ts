import { describe, it, expect } from "vitest";
import { fuzzyHash, fuzzySimilarity } from "../src/inspect/fuzzy.js";

describe("fuzzy hashing", () => {
  it("is deterministic and format consistent", () => {
    const data = new TextEncoder().encode("the quick brown fox jumps over the lazy dog ".repeat(20));
    const a = fuzzyHash(data);
    const b = fuzzyHash(data);
    expect(a.hash).toBe(b.hash);
    expect(a.hash).toMatch(/^3:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+$/);
  });

  it("scores identical files at 100 and unrelated files low", () => {
    const a = fuzzyHash(new TextEncoder().encode("alpha beta gamma ".repeat(40))).hash;
    const same = fuzzyHash(new TextEncoder().encode("alpha beta gamma ".repeat(40))).hash;
    const other = fuzzyHash(new Uint8Array(Array.from({ length: 700 }, (_, i) => (i * 37) & 0xff))).hash;
    expect(fuzzySimilarity(a, same)).toBe(100);
    expect(fuzzySimilarity(a, other)).toBeLessThan(60);
  });

  it("scores a slightly modified file above a completely different one", () => {
    const original = new TextEncoder().encode("common prefix data common prefix data common prefix data ".repeat(10));
    const modified = new TextEncoder().encode("common prefix data common prefix DATA common prefix data ".repeat(10));
    const unrelated = new Uint8Array(Array.from({ length: original.length }, (_, i) => (i * 91) & 0xff));
    const base = fuzzyHash(original).hash;
    expect(fuzzySimilarity(base, fuzzyHash(modified).hash)).toBeGreaterThan(
      fuzzySimilarity(base, fuzzyHash(unrelated).hash),
    );
  });

  it("returns zero for invalid hashes", () => {
    expect(fuzzySimilarity("nope", "3:aaa:bbb")).toBe(0);
  });
});
