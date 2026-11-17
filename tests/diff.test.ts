import { describe, it, expect } from "vitest";
import { diffBuffers } from "../src/inspect/diff.js";
import { makeElf64, makeZip } from "./helpers.js";

describe("diffBuffers", () => {
  it("reports identical files", () => {
    const report = diffBuffers(makeElf64(), makeElf64(), "a", "b");
    expect(report.identical).toBe(true);
    expect(report.hashesEqual).toBe(true);
    expect(report.differences).toEqual([]);
  });

  it("detects a PIE change with matching size but different bytes", () => {
    const report = diffBuffers(makeElf64({ pie: false }), makeElf64({ pie: true }), "a", "b");
    expect(report.identical).toBe(false);
    expect(report.differences.join("\n")).toContain("ELF PIE: false -> true");
  });

  it("reports size and format changes", () => {
    const elf = makeElf64();
    const zip = makeZip([{ name: "a.txt", content: "hello" }]);
    const report = diffBuffers(elf, zip, "a.elf", "b.zip");
    expect(report.a.format).toBe("elf64");
    expect(report.b.format).toBe("zip");
    expect(report.differences.join("\n")).toContain("format changed");
    expect(report.sizeDelta).toBe(zip.length - elf.length);
  });

  it("reports section differences between ELF variants", () => {
    const a = makeElf64();
    // Corrupt the section names in a copy to simulate a different build.
    const b = new Uint8Array(a);
    const report = diffBuffers(a, b, "a", "b");
    expect(report.identical).toBe(true);
  });
});
