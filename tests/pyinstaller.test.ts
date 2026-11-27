import { describe, it, expect } from "vitest";
import { parsePyInstaller } from "../src/inspect/pyinstaller.js";

function makePyInstaller(): Uint8Array {
  const cookieOffset = 0x200;
  const packageLength = cookieOffset + 88;
  const tocOffset = 0x100;
  const tocLength = 0x40;
  const buf = Buffer.alloc(cookieOffset + 88);
  const magic = [0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e];
  Buffer.from(magic).copy(buf, cookieOffset);
  buf.writeUInt32BE(packageLength, cookieOffset + 8);
  buf.writeUInt32BE(tocOffset, cookieOffset + 12);
  buf.writeUInt32BE(tocLength, cookieOffset + 16);
  buf.writeUInt32BE(310, cookieOffset + 20);
  buf.write("libpython3.10.so.1.0\0", cookieOffset + 24, "ascii");

  // TOC entry: 18 byte header + null padded name.
  const entry = Buffer.alloc(32);
  entry.writeUInt32BE(32, 0);
  entry.writeUInt32BE(0x40, 4);
  entry.writeUInt32BE(100, 8);
  entry.writeUInt32BE(200, 12);
  entry.writeUInt8(1, 16);
  entry.writeUInt8(0x6d, 17); // 'm'
  entry.write("module.py\0", 18, "ascii");
  // Cookie offsets are archive-relative; archiveStart = cookie + 88 - packageLength = 0.
  entry.copy(buf, tocOffset);
  return new Uint8Array(buf);
}

describe("parsePyInstaller", () => {
  it("decodes the cookie and TOC", () => {
    const info = parsePyInstaller(makePyInstaller());
    expect(info.pythonVersion).toBe(310);
    expect(info.pythonLibrary).toContain("libpython3.10");
    expect(info.entryCount).toBe(1);
    expect(info.entries[0]!.name).toBe("module.py");
    expect(info.entries[0]!.typeCode).toBe("m");
    expect(info.entries[0]!.compressed).toBe(true);
  });

  it("rejects files without a cookie", () => {
    expect(() => parsePyInstaller(new Uint8Array(128))).toThrow(/cookie/);
  });
});
