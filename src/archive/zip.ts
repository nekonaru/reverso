export interface ArchiveEntry {
  name: string;
  compressionMethod: number;
  compressedSize: number;
  uncompressedSize: number;
  encrypted: boolean;
  directory: boolean;
}

export type ArchiveKind = "apk" | "ipa" | "jar" | "zip";

export interface ArchiveListing {
  kind: ArchiveKind;
  entries: ArchiveEntry[];
  totalEntries: number;
  totalUncompressedSize: number;
  truncated: boolean;
  suspiciousEntries: string[];
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const MAX_ENTRIES = 5000;
const EOCD_SEARCH_WINDOW = 65558;

const SUSPICIOUS_EXTENSIONS = [
  ".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".hta", ".msi",
  ".jar", ".apk", ".dll", ".so", ".dylib", ".sh", ".mjs",
];

export function listArchive(buf: Uint8Array, maxEntries = MAX_ENTRIES): ArchiveListing | null {
  const eocdOffset = findEocd(buf);
  if (eocdOffset === null || eocdOffset + 22 > buf.length) return null;

  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o: number) => dv.getUint16(o, true);
  const u32 = (o: number) => dv.getUint32(o, true) >>> 0;

  const totalEntries = u16(eocdOffset + 10);
  const cdOffset = u32(eocdOffset + 16);
  if (cdOffset >= buf.length) return null;

  const entries: ArchiveEntry[] = [];
  let totalUncompressedSize = 0;
  let offset = cdOffset;
  let listed = 0;

  while (offset + 46 <= buf.length && listed < Math.min(totalEntries, maxEntries)) {
    if (u32(offset) !== CENTRAL_SIGNATURE) break;
    const flags = u16(offset + 8);
    const method = u16(offset + 10);
    const compressedSize = u32(offset + 20);
    const uncompressedSize = u32(offset + 24);
    const nameLength = u16(offset + 28);
    const extraLength = u16(offset + 30);
    const commentLength = u16(offset + 32);
    const nameStart = offset + 46;
    if (nameStart + nameLength > buf.length) break;
    const nameBytes = buf.subarray(nameStart, nameStart + nameLength);
    const name = decodeName(nameBytes, (flags & 0x800) !== 0);
    entries.push({
      name,
      compressionMethod: method,
      compressedSize,
      uncompressedSize,
      encrypted: (flags & 0x1) !== 0,
      directory: name.endsWith("/"),
    });
    totalUncompressedSize += uncompressedSize;
    offset = nameStart + nameLength + extraLength + commentLength;
    listed++;
  }

  const names = entries.map((e) => e.name.toLowerCase());
  const kind = detectKind(names);
  const suspiciousEntries = entries
    .filter((e) => SUSPICIOUS_EXTENSIONS.some((ext) => e.name.toLowerCase().endsWith(ext)))
    .map((e) => e.name)
    .slice(0, 50);

  return {
    kind,
    entries,
    totalEntries,
    totalUncompressedSize,
    truncated: totalEntries > entries.length,
    suspiciousEntries,
  };
}

function findEocd(buf: Uint8Array): number | null {
  const min = Math.max(0, buf.length - EOCD_SEARCH_WINDOW);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) {
      return i;
    }
  }
  return null;
}

function decodeName(bytes: Uint8Array, utf8: boolean): string {
  try {
    return new TextDecoder(utf8 ? "utf-8" : "latin1").decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes);
  }
}

function detectKind(names: string[]): ArchiveKind {
  const hasAndroidManifest = names.some((n) => n === "androidmanifest.xml");
  const hasDex = names.some((n) => /^classes\d*\.dex$/.test(n));
  if (hasAndroidManifest && hasDex) return "apk";
  if (names.some((n) => n.startsWith("payload/") && n.endsWith(".app/info.plist")) ||
      (names.some((n) => n.startsWith("payload/")) && names.some((n) => n.endsWith(".app/")))) {
    return "ipa";
  }
  if (names.some((n) => n === "meta-inf/manifest.mf" || n.startsWith("meta-inf/")) ||
      names.some((n) => n.endsWith(".class"))) {
    return "jar";
  }
  return "zip";
}
