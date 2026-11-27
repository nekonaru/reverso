import { describe, it, expect } from "vitest";
import { parseDotNet } from "../src/inspect/dotnet.js";

function makeDotNetPe(): Uint8Array {
  const buf = Buffer.alloc(0x400);
  buf.write("MZ", 0, "ascii");
  buf.writeUInt32LE(0x80, 0x3c);
  buf.writeUInt32LE(0x00004550, 0x80);
  buf.writeUInt16LE(0x14c, 0x84); // x86
  buf.writeUInt16LE(1, 0x86); // one section
  buf.writeUInt16LE(224, 0x94); // optional header size
  const opt = 0x98;
  buf.writeUInt16LE(0x10b, opt);
  buf.writeUInt32LE(16, opt + 92); // numberOfRvaAndSizes
  const dataDir = opt + 96;
  buf.writeUInt32LE(0x2000, dataDir + 14 * 8); // CLR directory RVA
  buf.writeUInt32LE(72, dataDir + 14 * 8 + 4);
  const section = opt + 224;
  buf.write(".text\0", section, "ascii");
  buf.writeUInt32LE(0x400, section + 8); // virtual size
  buf.writeUInt32LE(0x2000, section + 12); // virtual address
  buf.writeUInt32LE(0x400, section + 16); // raw size
  buf.writeUInt32LE(0x200, section + 20); // raw pointer
  buf.writeUInt32LE(0x60000020, section + 36);

  // CLI header at 0x200
  buf.writeUInt32LE(72, 0x200);
  buf.writeUInt16LE(2, 0x204);
  buf.writeUInt16LE(5, 0x206);
  buf.writeUInt32LE(0x2100, 0x208); // metadata RVA
  buf.writeUInt32LE(64, 0x20c);

  // Metadata root at 0x300
  buf.write("BSJB", 0x300, "ascii");
  buf.writeUInt32LE(12, 0x304);
  buf.write("v4.0.30319\0", 0x30c, "ascii");
  buf.writeUInt16LE(0, 0x318); // flags
  buf.writeUInt16LE(1, 0x31a); // one stream
  buf.writeUInt32LE(0x40, 0x31c); // #Strings offset relative to metadata
  buf.writeUInt32LE(0x20, 0x320); // size
  buf.write("#Strings\0\0\0\0", 0x324, "ascii");
  buf.write("\0HelloAssembly\0Type1\0", 0x300 + 0x40, "ascii");

  return new Uint8Array(buf);
}

describe("parseDotNet", () => {
  it("reads CLI metadata streams and string samples", () => {
    const info = parseDotNet(makeDotNetPe());
    expect(info.metadataVersion).toBe("v4.0.30319");
    expect(info.streams.map((s) => s.name)).toContain("#Strings");
    expect(info.stringSamples).toContain("HelloAssembly");
    expect(info.stringSamples).toContain("Type1");
  });

  it("rejects native PE files without a CLR directory", () => {
    const buf = Buffer.alloc(0x200);
    buf.write("MZ", 0, "ascii");
    buf.writeUInt32LE(0x80, 0x3c);
    buf.writeUInt32LE(0x00004550, 0x80);
    buf.writeUInt16LE(224, 0x94);
    expect(() => parseDotNet(new Uint8Array(buf))).toThrow(/Not a .NET assembly/);
  });
});
