import { describe, it, expect } from "vitest";
import { parseElf } from "../src/binary/elf.js";
import { makeElfWithDynamic } from "./elf-dynamic-helper.js";

describe("ELF dynamic entries", () => {
  it("resolves DT_NEEDED and DT_RPATH through DT_STRTAB", () => {
    const elf = parseElf(makeElfWithDynamic());
    expect(elf.needed).toEqual(["libc.so.6", "libm.so.6"]);
    expect(elf.rpath).toBe("/usr/lib");
    expect(elf.runpath).toBeNull();
    expect(elf.bindNow).toBe(true);
    expect(elf.relocations).toEqual({ rel: 0, rela: 2 });
  });

  it("returns empty dependency data for a static ELF", async () => {
    const { makeElf64 } = await import("./helpers.js");
    const elf = parseElf(makeElf64());
    expect(elf.needed).toEqual([]);
    expect(elf.rpath).toBeNull();
  });
});
