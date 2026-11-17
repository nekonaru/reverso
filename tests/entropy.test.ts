import { describe, it, expect } from "vitest";
import { shannonEntropy, highEntropyWindows } from "../src/core/entropy.js";

describe("shannonEntropy", () => {
  it("returns 0 for an empty buffer", () => {
    expect(shannonEntropy(new Uint8Array(0))).toBe(0);
  });

  it("returns 0 for a constant buffer", () => {
    expect(shannonEntropy(new Uint8Array(1024).fill(0x41))).toBe(0);
  });

  it("returns 8 for a buffer with all 256 byte values equally represented", () => {
    const buf = new Uint8Array(256 * 16);
    for (let i = 0; i < buf.length; i++) buf[i] = i % 256;
    expect(shannonEntropy(buf)).toBeCloseTo(8, 1);
  });

  it("reports typical English text between 4 and 6 bits", () => {
    const text = Buffer.from("the quick brown fox jumps over the lazy dog. ".repeat(200), "ascii");
    const entropy = shannonEntropy(text);
    expect(entropy).toBeGreaterThan(3.5);
    expect(entropy).toBeLessThan(6.5);
  });
});

describe("highEntropyWindows", () => {
  it("flags a high-entropy half embedded in zeros", () => {
    const buf = new Uint8Array(8192);
    for (let i = 4096; i < 8192; i++) buf[i] = (i * 2654435761) >>> 24 & 0xff;
    const windows = highEntropyWindows(buf, 1024, 3.5);
    expect(windows.length).toBeGreaterThan(0);
    for (const window of windows) expect(window.entropy).toBeGreaterThanOrEqual(3.5);
  });

  it("returns no windows for flat data", () => {
    expect(highEntropyWindows(new Uint8Array(8192).fill(0), 1024, 7.0)).toHaveLength(0);
  });

  it("returns empty when the buffer is smaller than the window", () => {
    expect(highEntropyWindows(new Uint8Array(10), 4096)).toHaveLength(0);
  });
});
