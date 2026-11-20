import { describe, it, expect } from "vitest";
import { parseElf } from "../src/binary/elf.js";
import { hardeningReport } from "../src/binary/hardening.js";
import { makeElf64 } from "./helpers.js";

describe("parseElf", () => {
  it("parses a minimal ELF64 little-endian binary", () => {
    const elf = parseElf(makeElf64({ pie: false }));
    expect(elf.bitness).toBe(64);
    expect(elf.endianness).toBe("LE");
    expect(elf.machineName).toBe("x86-64");
    expect(elf.typeName).toBe("EXEC");
    expect(elf.pie).toBe(false);
    expect(elf.sections.map((s) => s.name)).toEqual(["", ".dynsym", ".dynstr", ".shstrtab"]);
    expect(elf.undefinedSymbols).toContain("__stack_chk_fail");
    expect(elf.stripped).toBe(true);
    expect(elf.stackCanary).toBe(true);
  });

  it("recognizes PIE binaries", () => {
    const elf = parseElf(makeElf64({ pie: true }));
    expect(elf.typeName).toBe("DYN");
    expect(elf.pie).toBe(true);
  });

  it("extracts the GNU build-id from a note section", () => {
    const buildId = "0123456789abcdef0123456789abcdef01234567";
    const elf = parseElf(makeElf64({ buildId }));
    expect(elf.buildId).toBe(buildId);
    expect(elf.sections.map((s) => s.name)).toContain(".note");
  });

  it("returns null build-id when no note section exists", () => {
    expect(parseElf(makeElf64()).buildId).toBeNull();
  });
});

describe("hardeningReport (ELF)", () => {
  it("reports PIE, canary and stripped status", () => {
    const report = hardeningReport(makeElf64({ pie: true }), "elf64");
    const byName = new Map(report.checks.map((c) => [c.name, c.status]));
    expect(byName.get("PIE")).toBe("pass");
    expect(byName.get("StackCanary")).toBe("pass");
    expect(byName.get("Stripped")).toBe("info");
  });
});
