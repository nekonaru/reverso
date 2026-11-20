import { createHash } from "node:crypto";
import { shannonEntropy, round3 } from "../core/entropy.js";

export interface PeSection {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  characteristics: string;
  entropy: number;
}

export interface PeImport {
  dll: string;
  functions: string[];
}

export interface PeRichInfo {
  key: number;
  compilers: Array<{ productId: number; buildNumber: number; count: number }>;
  richHash: string | null;
}

export interface PeOverlay {
  size: number;
  sha256: string;
}

export interface PeInfo {
  bitness: 32 | 64;
  machine: number;
  machineName: string;
  timestamp: number;
  subsystem: number;
  subsystemName: string;
  imageBase: number;
  entryPoint: number;
  numberOfSections: number;
  characteristics: string[];
  dllCharacteristics: string[];
  sections: PeSection[];
  imports: PeImport[];
  exports: string[];
  imphash: string | null;
  authenticode: { sha1: string; sha256: string };
  rich: PeRichInfo | null;
  overlay: PeOverlay | null;
  hasCertificate: boolean;
  isDotNet: boolean;
  aslr: boolean;
  nxCompat: boolean;
  cfg: boolean;
  highEntropyVa: boolean;
  noSeh: boolean;
}

const MACHINE_NAMES: Record<number, string> = {
  0x014c: "x86",
  0x0162: "MIPS",
  0x01c0: "ARM",
  0x01c4: "ARM Thumb-2",
  0xaa64: "ARM64",
  0x8664: "x86-64",
  0x0200: "IA-64",
};

const SUBSYSTEM_NAMES: Record<number, string> = {
  1: "native",
  2: "windows-gui",
  3: "windows-console",
  9: "windows-ce-gui",
  10: "efi-application",
  11: "efi-boot-service-driver",
  12: "efi-runtime-driver",
  14: "xbox",
  16: "windows-boot-application",
};

const CHARACTERISTICS: Array<[number, string]> = [
  [0x0002, "executable"],
  [0x0008, "line-nums-stripped"],
  [0x0020, "large-address-aware"],
  [0x0080, "bytes-reversed-lo"],
  [0x0100, "32bit-machine"],
  [0x0200, "debug-stripped"],
  [0x1000, "system"],
  [0x2000, "dll"],
];

const DLL_CHARACTERISTICS: Array<[number, string]> = [
  [0x0020, "high-entropy-va"],
  [0x0040, "dynamic-base"],
  [0x0080, "force-integrity"],
  [0x0100, "nx-compat"],
  [0x0200, "no-isolation"],
  [0x0400, "no-seh"],
  [0x0800, "no-bind"],
  [0x1000, "appcontainer"],
  [0x4000, "guard-cf"],
  [0x8000, "terminal-server-aware"],
];

const SECTION_CHARACTERISTICS: Array<[number, string]> = [
  [0x00000020, "code"],
  [0x00000040, "initialized-data"],
  [0x00000080, "uninitialized-data"],
  [0x02000000, "discardable"],
  [0x04000000, "not-cached"],
  [0x08000000, "not-paged"],
  [0x10000000, "shared"],
  [0x20000000, "execute"],
  [0x40000000, "read"],
  [0x80000000, "write"],
];

const MAX_IMPORTS_PER_DLL = 300;
const MAX_DLLS = 100;
const MAX_EXPORTS = 1000;
const MAX_SECTIONS = 96;

const sectionEntropy = (buf: Uint8Array, pointerToRawData: number, sizeOfRawData: number): number => {
  if (sizeOfRawData === 0) return 0;
  const start = Math.min(pointerToRawData, buf.length);
  const end = Math.min(pointerToRawData + sizeOfRawData, buf.length);
  if (end <= start) return 0;
  return round3(shannonEntropy(buf.subarray(start, end)));
};

export function parsePe(buf: Uint8Array): PeInfo {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o: number) => dv.getUint16(o, true);
  const u32 = (o: number) => dv.getUint32(o, true) >>> 0;

  if (buf.length < 0x40 || buf[0] !== 0x4d || buf[1] !== 0x5a) {
    throw new Error("Not a PE file: missing DOS signature");
  }
  const peOffset = u32(0x3c);
  if (peOffset + 24 > buf.length || u32(peOffset) !== 0x00004550) {
    throw new Error("Not a PE file: missing PE signature");
  }

  const coff = peOffset + 4;
  const machine = u16(coff);
  const numberOfSections = Math.min(u16(coff + 2), MAX_SECTIONS);
  const timestamp = u32(coff + 4);
  const sizeOfOptionalHeader = u16(coff + 16);
  const characteristicsRaw = u16(coff + 18);

  const opt = coff + 20;
  const magic = u16(opt);
  const bitness: 32 | 64 = magic === 0x20b ? 64 : 32;
  const isPePlus = magic === 0x20b;
  const isRomImage = magic === 0x107;

  const entryPoint = u32(opt + 16);
  const imageBase = isPePlus
    ? Number(dv.getBigUint64(opt + 24, true))
    : u32(opt + 28);
  const subsystem = u16(opt + 68);
  const dllCharacteristicsRaw = u16(opt + 70);

  const numberOfRvaAndSizesOffset = isPePlus ? opt + 108 : opt + 92;
  const dataDirectoriesOffset = isPePlus ? opt + 112 : opt + 96;
  const numberOfRvaAndSizes = numberOfRvaAndSizesOffset + 4 <= buf.length ? u32(numberOfRvaAndSizesOffset) : 0;
  const dataDirectory = (index: number): { rva: number; size: number } | null => {
    if (index >= numberOfRvaAndSizes) return null;
    const o = dataDirectoriesOffset + index * 8;
    if (o + 8 > buf.length) return null;
    return { rva: u32(o), size: u32(o + 4) };
  };

  const sectionsOffset = opt + sizeOfOptionalHeader;
  const sections: PeSection[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const o = sectionsOffset + i * 40;
    if (o + 40 > buf.length) break;
    let name = "";
    for (let j = 0; j < 8; j++) {
      const b = buf[o + j]!;
      if (b === 0) break;
      name += String.fromCharCode(b >= 0x20 && b <= 0x7e ? b : 0x2e);
    }
    const characteristicsBits = u32(o + 36);
    sections.push({
      name,
      virtualSize: u32(o + 8),
      virtualAddress: u32(o + 12),
      sizeOfRawData: u32(o + 16),
      pointerToRawData: u32(o + 20),
      characteristics: pickFlags(characteristicsBits, SECTION_CHARACTERISTICS).join(" "),
      entropy: sectionEntropy(buf, u32(o + 20), u32(o + 16)),
    });
  }

  const rvaToOffset = (rva: number): number | null => {
    for (const section of sections) {
      const extent = Math.max(section.virtualSize, section.sizeOfRawData);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + extent) {
        const delta = section.pointerToRawData - section.virtualAddress;
        const offset = rva + delta;
        return offset >= 0 && offset < buf.length ? offset : null;
      }
    }
    return null;
  };

  const readCStringAtRva = (rva: number, maxLength = 256): string | null => {
    const offset = rvaToOffset(rva);
    if (offset === null) return null;
    let s = "";
    for (let i = offset; i < Math.min(offset + maxLength, buf.length); i++) {
      const b = buf[i]!;
      if (b === 0) return s;
      if (b < 0x20 || b > 0x7e) return s.length > 0 ? s : null;
      s += String.fromCharCode(b);
    }
    return s.length > 0 ? s : null;
  };

  // Import directory (data directory index 1).
  const imports: PeImport[] = [];
  const importDir = dataDirectory(1);
  if (importDir && importDir.rva !== 0) {
    const ordinalFlag = isPePlus ? 0x8000000000000000n : 0x80000000n;
    const thunkSize = isPePlus ? 8 : 4;
    for (let i = 0; i < MAX_DLLS; i++) {
      const descOffset = rvaToOffset(importDir.rva + i * 20);
      if (descOffset === null || descOffset + 20 > buf.length) break;
      const originalFirstThunk = u32(descOffset);
      const nameRva = u32(descOffset + 12);
      const firstThunk = u32(descOffset + 16);
      if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;
      const dll = readCStringAtRva(nameRva) ?? `unknown-${i}.dll`;
      const functions: string[] = [];
      const thunkRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
      const thunkOffset = rvaToOffset(thunkRva);
      if (thunkOffset !== null) {
        for (let j = 0; j < MAX_IMPORTS_PER_DLL; j++) {
          const o = thunkOffset + j * thunkSize;
          if (o + thunkSize > buf.length) break;
          const value = isPePlus ? dv.getBigUint64(o, true)! : BigInt(u32(o));
          if (value === 0n) break;
          if ((value & ordinalFlag) !== 0n) {
            functions.push(`ordinal-${Number(value & 0xffffn)}`);
            continue;
          }
          const hintNameOffset = rvaToOffset(Number(value & 0x7fffffffn) >>> 0);
          if (hintNameOffset === null) continue;
          let s = "";
          for (let k = hintNameOffset + 2; k < Math.min(hintNameOffset + 2 + 128, buf.length); k++) {
            const b = buf[k]!;
            if (b === 0) break;
            if (b < 0x20 || b > 0x7e) break;
            s += String.fromCharCode(b);
          }
          if (s) functions.push(s);
        }
      }
      imports.push({ dll, functions });
    }
  }

  // Export directory (data directory index 0).
  const exports: string[] = [];
  const exportDir = dataDirectory(0);
  if (exportDir && exportDir.rva !== 0) {
    const base = rvaToOffset(exportDir.rva);
    if (base !== null && base + 40 <= buf.length) {
      const numberOfNames = u32(base + 24);
      const addressOfNames = u32(base + 32);
      const namesOffset = rvaToOffset(addressOfNames);
      if (namesOffset !== null) {
        for (let i = 0; i < Math.min(numberOfNames, MAX_EXPORTS); i++) {
          const o = namesOffset + i * 4;
          if (o + 4 > buf.length) break;
          const nameRva = u32(o);
          const name = readCStringAtRva(nameRva);
          if (name) exports.push(name);
        }
      }
    }
  }

  const certificateDir = dataDirectory(4);
  const clrDir = dataDirectory(14);

  // Import hash in the style popularised by malware clustering: md5 of
  // comma-joined, lowercased "dll.function" pairs in order of appearance.
  // Ordinal imports are encoded as "dll.ordN".
  const imphash = computeImphash(imports);

  // Authenticode digest: the file hash excluding the certificate table, with
  // the checksum field and the certificate directory entry zeroed.
  const csOff = opt + 64;
  const certDirOff = dataDirectoriesOffset + 4 * 8;
  const certDirEntry = certDirOff + 8 <= buf.length ? { rva: u32(certDirOff), size: u32(certDirOff + 4) } : null;
  const authenticode = {
    sha1: authenticodeDigest(buf, csOff, certDirOff, certDirEntry, "sha1"),
    sha256: authenticodeDigest(buf, csOff, certDirOff, certDirEntry, "sha256"),
  };

  // Rich header (compile-toolchain fingerprint from the DOS stub).
  const rich = parseRichHeader(buf, peOffset, u32);

  // Overlay: bytes appended after the last section's raw data.
  let lastRawEnd = 0;
  for (const section of sections) {
    const end = section.pointerToRawData + section.sizeOfRawData;
    if (end > lastRawEnd) lastRawEnd = end;
  }
  const overlay = lastRawEnd > 0 && lastRawEnd < buf.length
    ? { size: buf.length - lastRawEnd, sha256: createHash("sha256").update(buf.subarray(lastRawEnd)).digest("hex") }
    : null;

  return {
    bitness,
    machine,
    machineName: MACHINE_NAMES[machine] ?? `machine-0x${machine.toString(16)}`,
    timestamp,
    subsystem,
    subsystemName: SUBSYSTEM_NAMES[subsystem] ?? `subsystem-${subsystem}`,
    imageBase,
    entryPoint,
    numberOfSections,
    characteristics: pickFlags(characteristicsRaw, CHARACTERISTICS),
    dllCharacteristics: pickFlags(dllCharacteristicsRaw, DLL_CHARACTERISTICS),
    sections,
    imports,
    exports,
    imphash,
    authenticode,
    rich,
    overlay,
    hasCertificate: !isRomImage && certificateDir !== null && certificateDir.size > 0,
    isDotNet: !isRomImage && clrDir !== null && clrDir.rva !== 0,
    aslr: (dllCharacteristicsRaw & 0x0040) !== 0,
    nxCompat: (dllCharacteristicsRaw & 0x0100) !== 0,
    cfg: (dllCharacteristicsRaw & 0x4000) !== 0,
    highEntropyVa: (dllCharacteristicsRaw & 0x0020) !== 0,
    noSeh: (dllCharacteristicsRaw & 0x0400) !== 0,
  };
}

function pickFlags(value: number, table: Array<[number, string]>): string[] {
  const out: string[] = [];
  for (const [bit, name] of table) {
    if ((value & bit) !== 0) out.push(name);
  }
  return out;
}

/** Hash of the file with the checksum and certificate directory entry zeroed. */
function authenticodeDigest(
  buf: Uint8Array,
  csOff: number,
  certDirOff: number,
  certDirEntry: { rva: number; size: number } | null,
  algorithm: "sha1" | "sha256",
): string {
  const zero4 = new Uint8Array(4);
  const zero8 = new Uint8Array(8);
  const hash = createHash(algorithm);
  if (!certDirEntry || certDirEntry.size === 0 || certDirEntry.rva + certDirEntry.size > buf.length) {
    hash.update(buf.subarray(0, csOff));
    hash.update(zero4);
    hash.update(buf.subarray(csOff + 4));
    return hash.digest("hex");
  }
  const certOff = certDirEntry.rva;
  hash.update(buf.subarray(0, csOff));
  hash.update(zero4);
  hash.update(buf.subarray(csOff + 4, certDirOff));
  hash.update(zero8);
  hash.update(buf.subarray(certDirOff + 8, certOff));
  hash.update(buf.subarray(certOff + certDirEntry.size));
  return hash.digest("hex");
}

/** Decodes the Rich header from the DOS stub. Returns null when absent or malformed. */
function parseRichHeader(
  buf: Uint8Array,
  peOffset: number,
  u32: (offset: number) => number,
): PeRichInfo | null {
  let richOffset = -1;
  for (let offset = 0; offset + 8 <= peOffset; offset++) {
    if (buf[offset] === 0x52 && buf[offset + 1] === 0x69 && buf[offset + 2] === 0x63 && buf[offset + 3] === 0x68) {
      richOffset = offset;
      break;
    }
  }
  if (richOffset === -1) return null;
  const key = u32(richOffset + 4);

  let dansOffset = -1;
  for (let offset = richOffset - 4; offset >= 0; offset -= 4) {
    if (((u32(offset) ^ key) >>> 0) === 0x536e6144) {
      dansOffset = offset;
      break;
    }
  }
  if (dansOffset === -1) return null;

  // Three padding dwords after DanS must decode to zero.
  for (let i = 1; i <= 3; i++) {
    if (((u32(dansOffset + i * 4) ^ key) >>> 0) !== 0) return null;
  }

  const compilers: Array<{ productId: number; buildNumber: number; count: number }> = [];
  let pos = dansOffset + 16;
  while (pos + 8 <= richOffset) {
    const compId = (u32(pos) ^ key) >>> 0;
    const count = (u32(pos + 4) ^ key) >>> 0;
    compilers.push({ productId: compId >>> 16, buildNumber: compId & 0xffff, count });
    pos += 8;
  }
  if (compilers.length === 0) return null;
  const richHash = createHash("md5")
    .update(compilers.map((c) => `${c.productId}.${c.buildNumber}.${c.count}`).join(","), "utf8")
    .digest("hex");
  return { key, compilers, richHash };
}

function computeImphash(imports: PeImport[]): string | null {
  const parts: string[] = [];
  for (const entry of imports) {
    const dll = entry.dll.toLowerCase().replace(/\.(dll|ocx|sys|drv|exe)$/i, "");
    for (const fn of entry.functions) {
      const normalized = fn.toLowerCase().replace(/^ordinal-(\d+)$/, "ord$1");
      parts.push(`${dll}.${normalized}`);
    }
  }
  if (parts.length === 0) return null;
  return createHash("md5").update(parts.join(","), "utf8").digest("hex");
}
