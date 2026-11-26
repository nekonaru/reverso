export interface MachOSegment {
  name: string;
  vmaddr: number;
  vmsize: number;
  fileOffset: number;
  fileSize: number;
  flags: string;
}

export interface MachOInfo {
  bitness: 32 | 64;
  endianness: "LE" | "BE";
  cpuType: number;
  cpuName: string;
  fileType: number;
  fileTypeName: string;
  flags: string[];
  isFat: boolean;
  fatArchitectures: number[];
  segments: MachOSegment[];
  encrypted: boolean;
  hasCodeSignature: boolean;
  hasEntryPoint: boolean;
  uuid: string | null;
  dylibs: string[];
  rpaths: string[];
  fatSlices: Array<{
    cpuType: number;
    cpuSubtype: number;
    offset: number;
    size: number;
    bitness: 32 | 64 | null;
    fileType: string | null;
    segments: string[];
    uuid: string | null;
    error: string | null;
  }>;
}

const CPU_TYPE_NAMES: Record<number, string> = {
  6: "mc680x0",
  7: "x86",
  12: "arm",
  18: "powerpc",
  16777223: "x86-64",
  16777228: "arm64",
  16777234: "powerpc64",
};

const FILE_TYPE_NAMES: Record<number, string> = {
  1: "object",
  2: "execute",
  3: "fixed-vm-shared-lib",
  4: "core",
  5: "preloaded-executable",
  6: "dynamically-bound-shared-lib",
  7: "dynamic-linker",
  8: "bundle",
  9: "static-framework",
  10: "dynamic-interface-library? fat",
  11: "dsym",
  12: "kext-bundle",
};

const LC_MAIN = 0x80000028;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_CODE_SIGNATURE = 0x1d;
const LC_UUID = 0x1b;
const LC_RPATH = 0x8000001c;
const DYLIB_COMMANDS = new Set([0x0c, 0x18, 0x20, 0x80000018, 0x8000001f, 0x80000023]);
const LC_SEGMENT = 0x1;
const LC_SEGMENT_64 = 0x19;

const FAT_MAGIC = 0xcafebabe;
const FAT_CIGAM = 0xbebafeca;
const FAT_MAGIC_64 = 0xcafebabf;

export function parseMachO(buf: Uint8Array, depth = 0): MachOInfo {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const b0 = buf[0]!, b1 = buf[1]!, b2 = buf[2]!, b3 = buf[3]!;

  if (b0 === 0xca && b1 === 0xfe && b2 === 0xba && (b3 === 0xbe || b3 === 0xc0)) {
    // Fat binary: read every architecture slice and parse the thin Mach-O it holds.
    const isFat64 = b3 === 0xc0;
    const nfat = dv.getUint32(4, false);
    const entrySize = isFat64 ? 32 : 20;
    const fatSlices: MachOInfo["fatSlices"] = [];
    for (let i = 0; i < Math.min(nfat, 32); i++) {
      const o = 8 + i * entrySize;
      if (o + entrySize > buf.length) break;
      const cpuType = dv.getInt32(o, false);
      const cpuSubtype = dv.getInt32(o + 4, false);
      const offset = isFat64 ? Number(dv.getBigUint64(o + 8, false)) : dv.getUint32(o + 8, false);
      const size = isFat64 ? Number(dv.getBigUint64(o + 16, false)) : dv.getUint32(o + 12, false);
      const base = { cpuType, cpuSubtype, offset, size };
      if (offset >= buf.length || size === 0) {
        fatSlices.push({ ...base, bitness: null, fileType: null, segments: [], uuid: null, error: "slice out of bounds" });
        continue;
      }
      const slice = buf.subarray(offset, Math.min(offset + size, buf.length));
      try {
        const info = depth >= 1
          ? { bitness: 64 as const, fileTypeName: "nested-fat", segments: [], uuid: null }
          : parseMachO(slice, depth + 1);
        fatSlices.push({
          ...base,
          bitness: info.bitness,
          fileType: info.fileTypeName,
          segments: info.segments.map((s) => s.name),
          uuid: info.uuid,
          error: null,
        });
      } catch (error) {
        fatSlices.push({ ...base, bitness: null, fileType: null, segments: [], uuid: null, error: (error as Error).message });
      }
    }
    return {
      bitness: 64,
      endianness: "BE",
      cpuType: 0,
      cpuName: "universal",
      fileType: 0,
      fileTypeName: "fat",
      flags: [],
      isFat: true,
      fatArchitectures: fatSlices.map((s) => s.cpuType),
      fatSlices,
      segments: [],
      encrypted: false,
      hasCodeSignature: false,
      hasEntryPoint: false,
      uuid: null,
      dylibs: [],
      rpaths: [],
    };
  }

  const le = b0 === 0xce || b0 === 0xcf;
  const is64 = le ? b0 === 0xcf : b3 === 0xcf;
  const actualBitness: 32 | 64 = is64 ? 64 : 32;
  const u32 = (o: number) => dv.getUint32(o, le) >>> 0;
  const u64 = (o: number) => Number(dv.getBigUint64(o, le));
  const word = actualBitness === 64 ? u64 : u32;

  const cpuType = u32(4);
  const cpuSubtype = u32(8);
  void cpuSubtype;
  const fileType = u32(12);
  const ncmds = u32(16);
  const flags = u32(24);

  const segments: MachOSegment[] = [];
  let offset = actualBitness === 64 ? 32 : 28;
  let encrypted = false;
  let hasCodeSignature = false;
  let hasEntryPoint = false;
  let uuid: string | null = null;
  const dylibs: string[] = [];
  const rpaths: string[] = [];
  for (let i = 0; i < Math.min(ncmds, 256); i++) {
    if (offset + 8 > buf.length) break;
    const cmd = u32(offset);
    const cmdsize = u32(offset + 4);
    if (cmdsize < 8) break;
    if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
      const segName = readFixedString(buf, offset + 8, 16);
      const base = offset + 8 + 16;
      if (cmd === LC_SEGMENT_64 && base + 48 <= buf.length) {
        segments.push({
          name: segName,
          vmaddr: u64(base),
          vmsize: u64(base + 8),
          fileOffset: u64(base + 16),
          fileSize: u64(base + 24),
          flags: `initprot=${(dv.getUint32(base + 36, le) & 0x7).toString(2)}`,
        });
      } else if (cmd === LC_SEGMENT && base + 36 <= buf.length) {
        segments.push({
          name: segName,
          vmaddr: u32(base),
          vmsize: u32(base + 4),
          fileOffset: u32(base + 8),
          fileSize: u32(base + 12),
          flags: `initprot=${(dv.getUint32(base + 20, le) & 0x7).toString(2)}`,
        });
      }
    } else if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      const cryptidOffset = offset + (cmd === LC_ENCRYPTION_INFO_64 ? 20 : 16);
      if (cryptidOffset + 4 <= buf.length) encrypted = u32(cryptidOffset) !== 0;
    } else if (cmd === LC_CODE_SIGNATURE) {
      hasCodeSignature = true;
    } else if (cmd === LC_UUID) {
      if (offset + 24 <= buf.length) {
        const bytes = [...buf.subarray(offset + 8, offset + 24)];
        uuid = formatUuid(bytes);
      }
    } else if (DYLIB_COMMANDS.has(cmd) || cmd === LC_RPATH) {
      const strOffset = u32(offset + 8);
      const start = offset + strOffset;
      if (strOffset >= 8 && start < buf.length) {
        let value = "";
        for (let i = start; i < Math.min(start + 1024, buf.length); i++) {
          const b = buf[i]!;
          if (b === 0) break;
          value += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
        }
        if (value) {
          if (cmd === LC_RPATH) rpaths.push(value);
          else dylibs.push(value);
        }
      }
    } else if (cmd === LC_MAIN) {
      hasEntryPoint = true;
    }
    offset += cmdsize;
  }

  const flagNames: string[] = [];
  if (flags & 0x1) flagNames.push("noundefs");
  if (flags & 0x2) flagNames.push("incrlink");
  if (flags & 0x200000) flagNames.push("pie");
  if (flags & 0x100000) flagNames.push("dead-strippable-dylib");

  return {
    bitness: actualBitness,
    endianness: le ? "LE" : "BE",
    cpuType,
    cpuName: CPU_TYPE_NAMES[cpuType] ?? `cpu-${cpuType}`,
    fileType,
    fileTypeName: FILE_TYPE_NAMES[fileType] ?? `type-${fileType}`,
    flags: flagNames,
    isFat: false,
    fatArchitectures: [],
    segments,
    encrypted,
    hasCodeSignature,
    hasEntryPoint,
    uuid,
    dylibs,
    rpaths,
    fatSlices: [],
  };
}

function readFixedString(buf: Uint8Array, offset: number, length: number): string {
  let s = "";
  for (let i = offset; i < offset + length && i < buf.length; i++) {
    const b = buf[i]!;
    if (b === 0) break;
    s += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
  }
  return s;
}

function formatUuid(bytes: number[]): string {
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10, 16).join(""),
  ].join("-");
}
