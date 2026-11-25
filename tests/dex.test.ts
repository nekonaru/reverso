import { describe, it, expect } from "vitest";
import { parseDex } from "../src/inspect/dex.js";
import { makeDex } from "./dex-helper.js";

describe("parseDex", () => {
  it("parses the header and the string table", () => {
    const info = parseDex(makeDex());
    expect(info.version).toBe("035");
    expect(info.headerSize).toBe(0x70);
    expect(info.checksum).toBe("deadbeef");
    expect(info.signature).toMatch(/^[0-9a-f]{40}$/);
    expect(info.counts.stringIds).toBe(5);
    expect(info.counts.typeIds).toBe(4);
    expect(info.counts.methodIds).toBe(27);
    expect(info.counts.classDefs).toBe(3);
    expect(info.strings.total).toBe(5);
    expect(info.strings.truncated).toBe(false);
  });

  it("categorizes suspicious strings", () => {
    const info = parseDex(makeDex());
    const byCategory = new Map(info.strings.categories.map((c) => [c.category, c]));
    expect(byCategory.get("url")!.samples[0]).toBe("https://updates-malicious.example.com/beacon");
    expect(byCategory.get("aws-key")!.samples[0]).toBe("AKIAIOSFODNN7EXAMPLE");
    expect(byCategory.get("class-descriptor")!.count).toBe(2);
  });

  it("resolves class definitions to descriptors", () => {
    const info = parseDex(makeDex());
    expect(info.classes).toEqual([
      "Lcom/example/app/MainActivity;",
      "https://updates-malicious.example.com/beacon",
      "AKIAIOSFODNN7EXAMPLE",
    ]);
  });

  it("rejects non-DEX input", () => {
    expect(() => parseDex(new Uint8Array([1, 2, 3]))).toThrow(/Not a DEX/);
    const buf = new Uint8Array(0x70);
    buf.set([0x64, 0x65, 0x78, 0x0a], 0); // dex\n but truncated magic
    expect(() => parseDex(buf)).toThrow();
  });

  it("rejects a truncated but well-formed DEX", () => {
    const full = makeDex();
    expect(() => parseDex(full.subarray(0, 64))).toThrow(/too small|Not a DEX/);
  });
});
