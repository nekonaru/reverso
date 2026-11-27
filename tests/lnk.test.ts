import { describe, it, expect } from "vitest";
import { parseLnk } from "../src/inspect/lnk.js";

function utf16(value: string): Buffer {
  const buf = Buffer.alloc(value.length * 2);
  for (let i = 0; i < value.length; i++) buf.writeUInt16LE(value.charCodeAt(i), i * 2);
  return buf;
}

function makeLnk(): Uint8Array {
  const buf = Buffer.alloc(76 + 128);
  buf.writeUInt32LE(76, 0);
  Buffer.from("0114020000000000c000000000000046", "hex").copy(buf, 4); // shortcut CLSID bytes
  const flags = 0x00000001 | 0x00000008 | 0x00000020 | 0x00000004; // name, args, unicode, working dir
  buf.writeUInt32LE(flags, 20);
  buf.writeUInt32LE(0x00000020, 24); // archive attribute
  buf.writeBigUInt64LE(132854688000000000n, 28); // 2022-01-01 in FILETIME
  buf.writeUInt32LE(1024, 52);
  buf.writeInt32LE(3, 56);
  buf.writeUInt32LE(1, 60); // SW_SHOWNORMAL

  let pos = 76;
  for (const value of ["Target name", "C:\\work", "--flag value"]) {
    buf.writeUInt16LE(value.length, pos);
    pos += 2;
    utf16(value).copy(buf, pos);
    pos += value.length * 2;
  }
  return new Uint8Array(buf);
}

describe("parseLnk", () => {
  it("parses flags, timestamps and string data", () => {
    const info = parseLnk(makeLnk());
    expect(info.flags).toContain("unicode");
    expect(info.flags).toContain("has-arguments");
    expect(info.attributes).toContain("archive");
    expect(info.nameString).toBe("Target name");
    expect(info.workingDirectory).toBe("C:\\work");
    expect(info.commandLine).toBe("--flag value");
    expect(info.creation).toContain("2022-01-01");
    expect(info.targetSize).toBe(1024);
  });

  it("rejects non-shortcut files", () => {
    expect(() => parseLnk(new Uint8Array(100))).toThrow(/shortcut/);
  });
});
