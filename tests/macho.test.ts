import { describe, it, expect } from "vitest";
import { parseMachO } from "../src/binary/macho.js";
import { hardeningReport } from "../src/binary/hardening.js";

/** Builds a minimal 64-bit Mach-O with one LC_SEGMENT_64, LC_MAIN, LC_CODE_SIGNATURE and LC_UUID. */
function makeMacho64(): Uint8Array {
  const buf = Buffer.alloc(0x400);
  buf.writeUInt32LE(0xfeedfacf, 0); // magic (bytes cf fa ed fe)
  buf.writeUInt32LE(0x0100000c, 4); // CPU_TYPE_ARM64
  buf.writeUInt32LE(0, 8); // cpusubtype
  buf.writeUInt32LE(2, 12); // filetype: execute
  buf.writeUInt32LE(4, 16); // ncmds
  buf.writeUInt32LE(0x48 + 0x18 + 0x10 + 0x18, 20); // sizeofcmds
  buf.writeUInt32LE(0x00218085, 24); // flags (PIE | dead-strippable | twolevel etc.)
  buf.writeUInt32LE(0, 28); // reserved

  let offset = 32;
  // LC_SEGMENT_64: 72 bytes
  buf.writeUInt32LE(0x19, offset);
  buf.writeUInt32LE(72, offset + 4);
  buf.write("__TEXT\0", offset + 8, "ascii");
  buf.writeBigUInt64LE(0x100000000n, offset + 24); // vmaddr
  buf.writeBigUInt64LE(0x1000n, offset + 32); // vmsize
  buf.writeBigUInt64LE(0x1000n, offset + 40); // fileoff
  buf.writeBigUInt64LE(0x1000n, offset + 48); // filesize
  buf.writeUInt32LE(7, offset + 56); // maxprot: rwx
  buf.writeUInt32LE(5, offset + 60); // initprot: r-x
  buf.writeUInt32LE(0, offset + 64); // nsects
  buf.writeUInt32LE(0, offset + 68); // flags
  offset += 72;

  // LC_MAIN: 24 bytes
  buf.writeUInt32LE(0x80000028, offset);
  buf.writeUInt32LE(24, offset + 4);
  buf.writeBigUInt64LE(0x1234n, offset + 8); // entryoff
  buf.writeBigUInt64LE(0n, offset + 16); // stacksize
  offset += 24;

  // LC_CODE_SIGNATURE: 16 bytes
  buf.writeUInt32LE(0x1d, offset);
  buf.writeUInt32LE(16, offset + 4);
  buf.writeUInt32LE(0x2000, offset + 8); // dataoff
  buf.writeUInt32LE(0x100, offset + 12); // datasize
  offset += 16;

  // LC_UUID: 24 bytes
  buf.writeUInt32LE(0x1b, offset);
  buf.writeUInt32LE(24, offset + 4);
  Buffer.from("00112233445566778899aabbccddeeff", "hex").copy(buf, offset + 8);

  return new Uint8Array(buf);
}

describe("parseMachO", () => {
  it("parses header, segments, encryption and signature markers", () => {
    const macho = parseMachO(makeMacho64());
    expect(macho.bitness).toBe(64);
    expect(macho.cpuName).toBe("arm64");
    expect(macho.fileTypeName).toBe("execute");
    expect(macho.segments).toHaveLength(1);
    expect(macho.segments[0]!.name).toBe("__TEXT");
    expect(macho.hasEntryPoint).toBe(true);
    expect(macho.hasCodeSignature).toBe(true);
    expect(macho.encrypted).toBe(false);
    expect(macho.flags).toContain("pie");
    expect(macho.uuid).toBe("00112233-4455-6677-8899-aabbccddeeff");
  });

  it("parses fat universal binaries and every slice", () => {
    const slice = makeMacho64();
    const headerLength = 8 + 20 * 2;
    const buf = Buffer.alloc(headerLength + slice.length * 2);
    buf.writeUInt32BE(0xcafebabe, 0);
    buf.writeUInt32BE(2, 4); // nfat_arch
    const cpus = [7, 16777228];
    let offset = headerLength;
    for (let i = 0; i < 2; i++) {
      const entry = 8 + i * 20;
      buf.writeUInt32BE(cpus[i]!, entry);
      buf.writeUInt32BE(3, entry + 4); // cpusubtype
      buf.writeUInt32BE(offset, entry + 8);
      buf.writeUInt32BE(slice.length, entry + 12);
      buf.writeUInt32BE(12, entry + 16); // align
      Buffer.from(slice).copy(buf, offset);
      offset += slice.length;
    }
    const macho = parseMachO(new Uint8Array(buf));
    expect(macho.isFat).toBe(true);
    expect(macho.fatArchitectures).toEqual(cpus);
    expect(macho.fatSlices).toHaveLength(2);
    expect(macho.fatSlices[0]).toMatchObject({
      cpuType: 7,
      bitness: 64,
      fileType: "execute",
      segments: ["__TEXT"],
      uuid: "00112233-4455-6677-8899-aabbccddeeff",
      error: null,
    });
  });
});

describe("hardeningReport (Mach-O)", () => {
  it("reports signature and PIE as info/pass", () => {
    const report = hardeningReport(makeMacho64(), "macho64");
    const byName = new Map(report.checks.map((c) => [c.name, c.status]));
    expect(byName.get("Code signature")).toBe("pass");
    expect(byName.get("Encryption (FairPlay)")).toBe("info");
  });
});
