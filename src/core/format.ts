export type FormatConfidence = "high" | "medium" | "low";

export interface FormatDetection {
  format: string;
  confidence: FormatConfidence;
  description: string;
}

function hasBytes(buf: Uint8Array, offset: number, bytes: number[]): boolean {
  if (offset + bytes.length > buf.length) return false;
  for (let i = 0; i < bytes.length; i++) {
    if (buf[offset + i]! !== bytes[i]) return false;
  }
  return true;
}

function asciiAt(buf: Uint8Array, offset: number, length: number): string {
  let s = "";
  for (let i = offset; i < offset + length && i < buf.length; i++) s += String.fromCharCode(buf[i]!);
  return s;
}

function readU32LE(buf: Uint8Array, offset: number): number {
  return (buf[offset]! | (buf[offset + 1]! << 8) | (buf[offset + 2]! << 16) | (buf[offset + 3]! << 24)) >>> 0;
}

/** Detect the container/format of a buffer from magic bytes. */
export function detectFormat(buf: Uint8Array): FormatDetection {
  if (buf.length < 4) return { format: "unknown", confidence: "low", description: "File too small to identify" };

  if (hasBytes(buf, 0, [0x7f, 0x45, 0x4c, 0x46])) {
    const is64 = buf[4] === 2;
    return { format: is64 ? "elf64" : "elf32", confidence: "high", description: "ELF executable (Executable and Linkable Format)" };
  }

  if (hasBytes(buf, 0, [0x4d, 0x5a])) {
    const peOffset = beSafeU32(buf, 0x3c);
    if (peOffset !== null && hasBytes(buf, peOffset, [0x50, 0x45, 0x00, 0x00])) {
      return { format: "pe", confidence: "high", description: "PE executable (Portable Executable, Windows)" };
    }
    return { format: "dos-mz", confidence: "medium", description: "DOS MZ executable (no PE signature found)" };
  }

  const macho = detectMachO(buf);
  if (macho) return macho;

  if (hasBytes(buf, 0, [0x50, 0x4b, 0x03, 0x04]) || hasBytes(buf, 0, [0x50, 0x4b, 0x05, 0x06]) || hasBytes(buf, 0, [0x50, 0x4b, 0x07, 0x08])) {
    return { format: "zip", confidence: "high", description: "ZIP archive (also APK, IPA, JAR, XPI, ZIPX)" };
  }
  if (hasBytes(buf, 0, [0x1f, 0x8b])) return { format: "gzip", confidence: "high", description: "gzip compressed data" };
  if (hasBytes(buf, 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { format: "7z", confidence: "high", description: "7-Zip archive" };
  if (hasBytes(buf, 0, [0x52, 0x61, 0x72, 0x21])) return { format: "rar", confidence: "high", description: "RAR archive" };
  if (hasBytes(buf, 0, [0x25, 0x50, 0x44, 0x46])) return { format: "pdf", confidence: "high", description: "PDF document" };
  if (hasBytes(buf, 0, [0x00, 0x61, 0x73, 0x6d])) return { format: "wasm", confidence: "high", description: "WebAssembly module" };
  if (asciiAt(buf, 0, 8).startsWith("dex\n")) return { format: "dex", confidence: "high", description: "Dalvik Executable (Android bytecode)" };
  if (hasBytes(buf, 0, [0x7f, 0x00, 0x00, 0x00])) return { format: "bplist?", confidence: "low", description: "Apple plist magic or false positive" };
  if (asciiAt(buf, 0, 6) === "bplist") return { format: "bplist", confidence: "high", description: "Apple binary property list" };
  if (hasBytes(buf, 0, [0xd4, 0xc3, 0xb2, 0xa1]) || hasBytes(buf, 0, [0xa1, 0xb2, 0xc3, 0xd4]) || hasBytes(buf, 0, [0x4d, 0x3c, 0xb2, 0xa1])) {
    return { format: "pcap", confidence: "high", description: "PCAP network capture" };
  }
  if (hasBytes(buf, 0, [0x89, 0x50, 0x4e, 0x47])) return { format: "png", confidence: "high", description: "PNG image" };
  if (hasBytes(buf, 0, [0xff, 0xd8, 0xff])) return { format: "jpeg", confidence: "high", description: "JPEG image" };
  if (hasBytes(buf, 0, [0x47, 0x49, 0x46, 0x38])) return { format: "gif", confidence: "high", description: "GIF image" };
  if (hasBytes(buf, 0, [0x42, 0x4d])) return { format: "bmp", confidence: "medium", description: "BMP image" };

  const textSample = asciiAt(buf, 0, Math.min(buf.length, 4096));
  if (looksLikeText(buf)) {
    if (/^\s*#!/.test(textSample)) return { format: "script", confidence: "medium", description: "Script with shebang" };
    if (/^\s*(?:<!DOCTYPE html|<html)/i.test(textSample)) return { format: "html", confidence: "medium", description: "HTML document" };
    if (/^\s*\{[\s\S]*\}\s*$/.test(textSampleAsString(buf))) return { format: "json", confidence: "low", description: "JSON-like document" };
    return { format: "text", confidence: "low", description: "Plain text content" };
  }

  return { format: "unknown", confidence: "low", description: "Unrecognized binary format" };
}

function beSafeU32(buf: Uint8Array, offset: number): number | null {
  if (offset + 4 > buf.length) return null;
  return readU32LE(buf, offset);
}

function detectMachO(buf: Uint8Array): FormatDetection | null {
  if (buf.length < 8) return null;
  const b0 = buf[0]!, b1 = buf[1]!, b2 = buf[2]!, b3 = buf[3]!;
  const be32 = b0 === 0xfe && b1 === 0xed && b2 === 0xfa && b3 === 0xce;
  const be64 = b0 === 0xfe && b1 === 0xed && b2 === 0xfa && b3 === 0xcf;
  const le32 = b0 === 0xce && b1 === 0xfa && b2 === 0xed && b3 === 0xfe;
  const le64 = b0 === 0xcf && b1 === 0xfa && b2 === 0xed && b3 === 0xfe;
  const fatBe = b0 === 0xca && b1 === 0xfe && b2 === 0xba && b3 === 0xbe;
  const fatLe = b0 === 0xbe && b1 === 0xba && b2 === 0xfe && b3 === 0xca;
  const fat64Be = b0 === 0xca && b1 === 0xfe && b2 === 0xba && b3 === 0xc0;
  if (be32 || be64 || le32 || le64) {
    const is64 = be64 || le64;
    return { format: is64 ? "macho64" : "macho32", confidence: "high", description: "Mach-O executable (Apple)" };
  }
  if (fatBe || fatLe || fat64Be) {
    return { format: "macho-fat", confidence: "medium", description: "Universal Mach-O binary or Java class file (shared magic)" };
  }
  return null;
}

const TEXT_BYTES = new Set([0x09, 0x0a, 0x0d]);

function looksLikeText(buf: Uint8Array): boolean {
  const sample = buf.subarray(0, Math.min(buf.length, 4096));
  if (sample.length === 0) return false;
  let printable = 0;
  for (const b of sample) {
    if ((b >= 0x20 && b <= 0x7e) || TEXT_BYTES.has(b) || b >= 0xc2) printable++;
  }
  return printable / sample.length > 0.95;
}

function textSampleAsString(buf: Uint8Array): string {
  const sample = buf.subarray(0, Math.min(buf.length, 4096));
  let s = "";
  for (const b of sample) s += String.fromCharCode(b);
  return s.trim();
}
