import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseWasm } from "../src/inspect/wasm.js";
import { makeWasm } from "./wasm-helper.js";

describe("parseWasm", () => {
  it("parses types, imports, exports, counts and names", () => {
    const info = parseWasm(makeWasm());
    expect(info.version).toBe(1);
    expect(info.types.count).toBe(1);
    expect(info.types.functions).toEqual([{ params: ["i32"], results: ["i32"] }]);
    expect(info.imports).toEqual([{ module: "env", name: "mul", kind: "func" }]);
    expect(info.exports).toEqual([{ name: "main", kind: "func", index: 0 }]);
    expect(info.counts.functions).toBe(1);
    expect(info.names.module).toBeNull();
    expect(info.names.functions).toEqual([{ index: 0, name: "main" }]);
    expect(info.sections.map((s) => s.name)).toEqual(["type", "import", "function", "export", "code", "custom"]);
  });

  it("rejects non-wasm input", () => {
    expect(() => parseWasm(new Uint8Array([0x00, 0x61, 0x73]))).toThrow(/Not a WebAssembly/);
    expect(() => parseWasm(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))).toThrow(/Not a WebAssembly/);
  });

  it("rejects a truncated section", () => {
    const wasm = makeWasm();
    expect(() => parseWasm(wasm.subarray(0, wasm.length - 3))).toThrow();
  });
});
