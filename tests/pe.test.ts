import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { parsePe } from "../src/binary/pe.js";
import { hardeningReport } from "../src/binary/hardening.js";

/**
 * Builds a minimal PE32 image with one import and one export, both routed
 * through a data section named .idata.
 *
 * .idata (RVA 0x2000, file 0x400):
 *   0x2000  import descriptor 0 (20 bytes) + terminator (20 bytes)
 *   0x2018  thunk array: [0x20c0, 0x00000000]
 *   0x2050  DLL name "kernel32.dll"
 *   0x2060  export directory (40 bytes), numberOfNames=1, addressOfNames=0x20a0
 *   0x20a0  name pointer array: [0x20b0]
 *   0x20b0  export name "ReversoExport"
 *   0x20c0  hint (u16) + "CreateFileA"
 */
function makePe(): Uint8Array {
  const buf = Buffer.alloc(0x800);
  const u16 = (o: number, v: number) => buf.writeUInt16LE(v, o);
  const u32 = (o: number, v: number) => buf.writeUInt32LE(v >>> 0, o);

  // DOS header
  buf.write("MZ", 0, "ascii");
  u32(0x3c, 0x80); // e_lfanew

  // Rich header in the DOS stub: DanS + 3 zero dwords + two compiler entries,
  // all XORed with the key, then the plain "Rich" marker and the key.
  const richKey = 0x12345678;
  u32(0x40, (0x536e6144 ^ richKey) >>> 0); // DanS XOR key
  for (let i = 1; i <= 3; i++) u32(0x40 + i * 4, richKey);
  u32(0x50, (0x00091234 ^ richKey) >>> 0); // product 9, build 0x1234
  u32(0x54, (5 ^ richKey) >>> 0); // count 5
  u32(0x58, (0x01045678 ^ richKey) >>> 0); // product 0x0104, build 0x5678
  u32(0x5c, (1 ^ richKey) >>> 0); // count 1
  buf.write("Rich", 0x60, "ascii");
  u32(0x64, richKey);

  // PE signature + COFF header at 0x80
  const coff = 0x80;
  u32(coff, 0x00004550);
  u16(coff + 4, 0x14c); // machine: x86
  u16(coff + 6, 2); // sections
  u32(coff + 8, 0x659f0000); // timestamp
  u16(coff + 20, 0x00e0); // sizeOfOptionalHeader (PE32)
  u16(coff + 22, 0x0102); // characteristics: executable + 32bit

  // Optional header at coff+24
  const opt = coff + 24;
  u16(opt, 0x10b); // PE32 magic
  buf.writeUInt8(8, opt + 2); // major linker version
  u32(opt + 4, 0x200); // size of code
  u32(opt + 16, 0x1000); // entry RVA
  u32(opt + 28, 0x400000); // image base
  u32(opt + 32, 0x1000); // section alignment
  u32(opt + 36, 0x200); // file alignment
  u16(opt + 40, 6); // major OS version
  u16(opt + 56, 3); // subsystem: console
  u16(opt + 70, 0x4160); // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | GUARD_CF
  u32(opt + 80, 0x3000); // size of image
  u32(opt + 84, 0x200); // size of headers
  u32(opt + 92, 16); // numberOfRvaAndSizes

  const dataDir = opt + 96;
  u32(dataDir + 0, 0x2060); // export directory RVA
  u32(dataDir + 4, 40); // export directory size
  u32(dataDir + 8, 0x2000); // import directory RVA
  u32(dataDir + 12, 40); // import directory size
  u32(dataDir + 4 * 8, 0x600); // certificate table (file offset)
  u32(dataDir + 4 * 8 + 4, 0x100); // certificate size

  // Section headers at opt+0xe0
  const sections = opt + 0xe0;
  const writeSection = (index: number, name: string, vsize: number, vaddr: number, rawSize: number, rawPtr: number, chars: number) => {
    const o = sections + index * 40;
    buf.write(name, o, "ascii");
    u32(o + 8, vsize);
    u32(o + 12, vaddr);
    u32(o + 16, rawSize);
    u32(o + 20, rawPtr);
    u32(o + 36, chars);
  };
  writeSection(0, ".text", 0x200, 0x1000, 0x200, 0x200, 0x60000020); // code | execute | read
  writeSection(1, ".idata", 0x200, 0x2000, 0x200, 0x400, 0xc0000040); // initialized data | read | write

  // .idata at file offset 0x400, RVA 0x2000
  const idata = 0x400;
  // Import descriptor 0 at 0x2000
  u32(idata + 0x0000, 0x2018); // OriginalFirstThunk
  u32(idata + 0x000c, 0x2050); // Name RVA
  u32(idata + 0x0010, 0x2018); // FirstThunk
  // Terminator descriptor at 0x2014 is all zero (buffer pre-zeroed)
  // Thunk array at 0x2018
  u32(idata + 0x0018, 0x20c0); // -> hint/name
  u32(idata + 0x001c, 0); // terminator
  // DLL name at 0x2050
  buf.write("kernel32.dll\0", idata + 0x50, "ascii");
  // Export directory at 0x2060
  const exp = idata + 0x60;
  u32(exp + 16, 1); // base
  u32(exp + 20, 1); // numberOfFunctions
  u32(exp + 24, 1); // numberOfNames
  u32(exp + 28, 0); // addressOfFunctions
  u32(exp + 32, 0x20a0); // addressOfNames
  u32(exp + 36, 0); // addressOfNameOrdinals
  // Name pointer array at 0x20a0
  u32(idata + 0xa0, 0x20b0);
  // Export name at 0x20b0
  buf.write("ReversoExport\0", idata + 0xb0, "ascii");
  // Import hint/name at 0x20c0
  u16(idata + 0xc0, 0); // hint
  buf.write("CreateFileA\0", idata + 0xc2, "ascii");

  return new Uint8Array(buf);
}

describe("parsePe", () => {
  it("parses sections, imports, exports and characteristics", () => {
    const buf = makePe();
    const pe = parsePe(buf);
    expect(pe.machineName).toBe("x86");
    expect(pe.bitness).toBe(32);
    expect(pe.isDotNet).toBe(false);
    expect(pe.sections.map((s) => s.name)).toEqual([".text", ".idata"]);
    expect(pe.imports).toHaveLength(1);
    expect(pe.imports[0]!.dll).toBe("kernel32.dll");
    expect(pe.imports[0]!.functions).toContain("CreateFileA");
    expect(pe.exports).toContain("ReversoExport");
    expect(pe.hasCertificate).toBe(true);
    expect(pe.imphash).toBe(createHash("md5").update("kernel32.createfilea", "utf8").digest("hex"));
    expect(pe.sections.every((s) => s.entropy >= 0 && s.entropy <= 8)).toBe(true);

    // Rich header: product 9, build 0x1234 (4660), count 5 and product 260, build 22136, count 1.
    expect(pe.rich?.compilers).toEqual([
      { productId: 9, buildNumber: 4660, count: 5 },
      { productId: 260, buildNumber: 22136, count: 1 },
    ]);
    expect(pe.rich?.richHash).toBe(createHash("md5").update("9.4660.5,260.22136.1", "utf8").digest("hex"));

    // Authenticode digest: checksum and certificate directory entry zeroed, cert table excluded.
    const csOff = 0x98 + 64;
    const certDirOff = 0x98 + 96 + 4 * 8;
    const digest = (algorithm: "sha1" | "sha256"): string => {
      const hash = createHash(algorithm);
      hash.update(buf.subarray(0, csOff));
      hash.update(Buffer.alloc(4));
      hash.update(buf.subarray(csOff + 4, certDirOff));
      hash.update(Buffer.alloc(8));
      hash.update(buf.subarray(certDirOff + 8, 0x600));
      hash.update(buf.subarray(0x700));
      return hash.digest("hex");
    };
    expect(pe.authenticode.sha256).toBe(digest("sha256"));
    expect(pe.authenticode.sha1).toBe(digest("sha1"));

    // Overlay: the 512 bytes appended after the last section's raw data.
    expect(pe.overlay?.size).toBe(512);
    expect(pe.overlay?.sha256).toBe(createHash("sha256").update(buf.subarray(0x600)).digest("hex"));
    expect(pe.aslr).toBe(true);
    expect(pe.nxCompat).toBe(true);
    expect(pe.highEntropyVa).toBe(true);
    expect(pe.cfg).toBe(true);
    expect(pe.characteristics).toContain("executable");
    expect(pe.dllCharacteristics).toContain("dynamic-base");
  });
});

describe("hardeningReport (PE)", () => {
  it("passes ASLR, NX and CFG", () => {
    const report = hardeningReport(makePe(), "pe");
    const byName = new Map(report.checks.map((c) => [c.name, c.status]));
    expect(byName.get("ASLR")).toBe("pass");
    expect(byName.get("NX compat")).toBe("pass");
    expect(byName.get("Control Flow Guard")).toBe("pass");
    expect(byName.get("Signed")).toBe("pass");
  });
});
