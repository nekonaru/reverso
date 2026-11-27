import { describe, it, expect } from "vitest";
import { parseEvm } from "../src/inspect/evm.js";

describe("parseEvm", () => {
  it("disassembles PUSH and control opcodes", () => {
    const info = parseEvm("0x6060604052636014526000");
    expect(info.bytes).toBe(11);
    expect(info.instructions.map((i) => i.name)).toEqual(["PUSH1", "PUSH1", "MSTORE", "PUSH4", "STOP"]);
    expect(info.instructions[3]!.pushValue).toBe("60145260");
    expect(info.push4Candidates).toContain("60145260");
  });

  it("maps common opcodes and unknown bytes", () => {
    const info = parseEvm("6001fdffef");
    expect(info.instructions.map((i) => i.name)).toContain("REVERT");
    expect(info.instructions.map((i) => i.name)).toContain("SELFDESTRUCT");
    expect(info.instructions.some((i) => i.name.startsWith("UNKNOWN"))).toBe(true);
  });

  it("rejects non-hex input", () => {
    expect(() => parseEvm("hello")).toThrow(/hex/);
  });
});
