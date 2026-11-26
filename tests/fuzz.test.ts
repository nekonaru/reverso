import { describe, it, expect } from "vitest";
import { analyzeBuffer } from "../src/core/analyze-buffer.js";
import { parseElf } from "../src/binary/elf.js";
import { parsePe } from "../src/binary/pe.js";
import { parseWasm } from "../src/inspect/wasm.js";
import { parseDex } from "../src/inspect/dex.js";
import { parsePcap } from "../src/inspect/pcap.js";

/** Deterministic PRNG so the fuzz corpus is reproducible in CI. */
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

describe("parser fuzz corpus", () => {
  it("analyzes random and truncated inputs without throwing", () => {
    const next = random(0x5eed1234);
    for (let i = 0; i < 120; i++) {
      const length = Math.floor(next() * 4096);
      const buf = new Uint8Array(length);
      for (let j = 0; j < length; j++) buf[j] = Math.floor(next() * 256);
      expect(() => analyzeBuffer(buf, `fuzz-${i}.bin`)).not.toThrow();
      if (next() > 0.5) {
        const truncated = buf.subarray(0, Math.floor(buf.length * next()));
        expect(() => analyzeBuffer(truncated, `trunc-${i}.bin`)).not.toThrow();
      }
    }
  });

  it("individual parsers fail cleanly on random input", () => {
    const next = random(0x1234abcd);
    for (let i = 0; i < 60; i++) {
      const buf = new Uint8Array(Math.floor(next() * 2048));
      for (let j = 0; j < buf.length; j++) buf[j] = Math.floor(next() * 256);
      for (const parser of [parseElf, parsePe, parseWasm, parseDex, parsePcap]) {
        expect(() => parser(buf)).toThrow();
      }
    }
  });
});
