import { describe, it, expect } from "vitest";
import { detectFormat } from "../src/core/format.js";

function buf(...bytes: number[]): Uint8Array {
  return new Uint8Array(bytes);
}

describe("detectFormat", () => {
  it("detects ELF32 and ELF64", () => {
    expect(detectFormat(buf(0x7f, 0x45, 0x4c, 0x46, 1)).format).toBe("elf32");
    expect(detectFormat(buf(0x7f, 0x45, 0x4c, 0x46, 2)).format).toBe("elf64");
  });

  it("detects PE via the e_lfanew pointer", () => {
    const pe = new Uint8Array(0x100);
    pe.set([0x4d, 0x5a], 0);
    const view = new DataView(pe.buffer);
    view.setUint32(0x3c, 0x80, true);
    pe.set([0x50, 0x45, 0x00, 0x00], 0x80);
    expect(detectFormat(pe).format).toBe("pe");
  });

  it("detects zip, wasm, dex and pcap", () => {
    expect(detectFormat(buf(0x50, 0x4b, 0x03, 0x04)).format).toBe("zip");
    expect(detectFormat(buf(0x00, 0x61, 0x73, 0x6d)).format).toBe("wasm");
    expect(detectFormat(new TextEncoder().encode("dex\n035\0")).format).toBe("dex");
    expect(detectFormat(buf(0xd4, 0xc3, 0xb2, 0xa1)).format).toBe("pcap");
  });

  it("detects Mach-O and fat binaries", () => {
    expect(detectFormat(buf(0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0)).format).toBe("macho64");
    expect(detectFormat(buf(0xce, 0xfa, 0xed, 0xfe, 0, 0, 0, 0)).format).toBe("macho32");
    expect(detectFormat(buf(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0)).format).toBe("macho-fat");
  });

  it("detects PDF and gzip", () => {
    expect(detectFormat(new TextEncoder().encode("%PDF-1.7\n")).format).toBe("pdf");
    expect(detectFormat(buf(0x1f, 0x8b, 0x08, 0x00)).format).toBe("gzip");
  });

  it("returns unknown for noise", () => {
    expect(detectFormat(buf(0x01, 0x02, 0x03, 0x04)).format).toBe("unknown");
  });
});
