import { shannonEntropy, round3 } from "../core/entropy.js";
import { createHash } from "node:crypto";

export interface ElfSection {
  name: string;
  type: number;
  typeName: string;
  flags: string;
  address: number;
  offset: number;
  size: number;
  entrySize: number;
  entropy: number;
}

export interface ElfProgramHeader {
  type: number;
  typeName: string;
  flags: string;
  offset: number;
  address: number;
  fileSize: number;
  memorySize: number;
}

export interface ElfSymbol {
  name: string;
  defined: boolean;
}

export interface ElfOverlay {
  size: number;
  sha256: string;
}

export interface ElfInfo {
  bitness: 32 | 64;
  endianness: "LE" | "BE";
  osAbi: number;
  type: number;
  typeName: string;
  machine: number;
  machineName: string;
  entry: number;
  sections: ElfSection[];
  programHeaders: ElfProgramHeader[];
  definedSymbols: string[];
  undefinedSymbols: string[];
  buildId: string | null;
  overlay: ElfOverlay | null;
  needed: string[];
  rpath: string | null;
  runpath: string | null;
  relocations: { rel: number; rela: number };
  stripped: boolean;
  pie: boolean;
  nxStack: boolean;
  relro: boolean;
  bindNow: boolean;
  stackCanary: boolean;
  fortifiedFunctions: number;
}

const SHN_UNDEF = 0;
const SHN_XINDEX = 0xffff;
const SHT_SYMTAB = 2;
const SHT_DYNAMIC = 6;
const SHT_NOTE = 7;
const SHT_RELA = 4;
const SHT_REL = 9;
const SHT_DYNSYM = 11;
const SHT_NOBITS = 8;

const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

const DT_BIND_NOW = 24;
const DT_NEEDED = 1;
const DT_STRTAB = 5;
const DT_RPATH = 15;
const DT_RUNPATH = 29;
const PT_LOAD = 1;
const DT_FLAGS = 30;
const DT_FLAGS_1 = 0x6ffffffb;
const DF_BIND_NOW = 0x8;
const DF_1_NOW = 0x1;

const PF_X = 1;
const PF_W = 2;
const PF_R = 4;

const SHF_WRITE = 0x1n;
const SHF_ALLOC = 0x2n;
const SHF_EXECINSTR = 0x4n;

const SECTION_TYPE_NAMES: Record<number, string> = {
  0: "NULL",
  1: "PROGBITS",
  2: "SYMTAB",
  3: "STRTAB",
  4: "RELA",
  5: "HASH",
  6: "DYNAMIC",
  7: "NOTE",
  8: "NOBITS",
  9: "REL",
  10: "SHLIB",
  11: "DYNSYM",
  14: "INIT_ARRAY",
  15: "FINI_ARRAY",
  16: "PREINIT_ARRAY",
  17: "GROUP",
  18: "SYMTAB_SHNDX",
  0x6ffffff6: "GNU_HASH",
  0x6ffffffd: "GNU_VERSYM",
  0x6ffffffe: "GNU_VERNEED",
};

const PROGRAM_TYPE_NAMES: Record<number, string> = {
  0: "NULL",
  1: "LOAD",
  2: "DYNAMIC",
  3: "INTERP",
  4: "NOTE",
  6: "PHDR",
  0x6474e550: "GNU_EH_FRAME",
  0x6474e551: "GNU_STACK",
  0x6474e552: "GNU_RELRO",
  0x6474e553: "GNU_PROPERTY",
  0x6464e552: "GCC_EXCEPT_TABLE",
};

const MACHINE_NAMES: Record<number, string> = {
  3: "x86",
  8: "MIPS",
  16: "PowerPC",
  20: "PowerPC64",
  22: "S390",
  40: "ARM",
  50: "IA-64",
  62: "x86-64",
  183: "AArch64",
  243: "RISC-V",
  247: "BPF",
  252: "LoongArch",
};

const TYPE_NAMES: Record<number, string> = {
  0: "NONE",
  1: "REL",
  2: "EXEC",
  3: "DYN",
  4: "CORE",
};

const MAX_SYMBOLS = 2000;
const MAX_SECTIONS = 1024;

export function parseElf(buf: Uint8Array): ElfInfo {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const eiClass = buf[4]!;
  const eiData = buf[5]!;
  if (eiClass !== 1 && eiClass !== 2) {
    throw new Error(`Not an ELF file: invalid EI_CLASS ${eiClass}`);
  }
  if (eiData !== 1 && eiData !== 2) {
    throw new Error(`Not an ELF file: invalid EI_DATA ${eiData}`);
  }
  const bitness = eiClass === 2 ? 64 : 32;
  const le = eiData === 1; // EI_DATA: 1 = LE, 2 = BE
  const osAbi = buf[7] ?? 0;
  const u16 = (o: number) => dv.getUint16(o, le);
  const u32 = (o: number) => dv.getUint32(o, le) >>> 0;
  const u64 = (o: number) => Number(dv.getBigUint64(o, le));
  const word = bitness === 64 ? u64 : u32;

  const type = u16(16);
  const machine = u16(18);
  const entry = word(24); // e_entry: 24 in both ELF32 and ELF64

  let phoff: number, shoff: number, phnum: number, shnum: number, shstrndx: number, phentsize: number, shentsize: number;
  if (bitness === 64) {
    phoff = u64(32);
    shoff = u64(40);
    phnum = u16(56);
    shnum = u16(60);
    shstrndx = u16(62);
    phentsize = u16(54);
    shentsize = u16(58);
  } else {
    phoff = u32(28);
    shoff = u32(32);
    phnum = u16(44);
    shnum = u16(48);
    shstrndx = u16(50);
    phentsize = u16(42);
    shentsize = u16(46);
  }

  // Extended section numbering via section header 0.
  if (phoff + phentsize > buf.length) phoff = 0, phnum = 0;
  const shOffset = (i: number) => shoff + i * shentsize;
  if (shnum === 0 && shoff !== 0 && shoff + shentsize <= buf.length) {
    shnum = Number(bitness === 64 ? dv.getBigUint64(shOffset(0) + 32, le) : BigInt(u32(shOffset(0) + 20)));
  }
  if (shstrndx === SHN_XINDEX && shoff + shentsize <= buf.length) {
    shstrndx = bitness === 64 ? u32(shOffset(0) + 40) : u32(shOffset(0) + 24);
  }
  shnum = Math.min(shnum, MAX_SECTIONS);

  const readCString = (offset: number, limit: number): string => {
    let s = "";
    for (let i = offset; i < Math.min(offset + limit, buf.length); i++) {
      const b = buf[i]!;
      if (b === 0) break;
      s += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
    }
    return s;
  };

  // Raw section headers first, then resolve names through the shstrtab.
  interface RawSection {
    nameOffset: number;
    type: number;
    flags: bigint;
    address: number;
    offset: number;
    size: number;
    link: number;
    info: number;
    entrySize: number;
  }
  const rawSections: RawSection[] = [];
  for (let i = 0; i < shnum; i++) {
    const o = shOffset(i);
    if (o + shentsize > buf.length) break;
    if (bitness === 64) {
      rawSections.push({
        nameOffset: u32(o),
        type: u32(o + 4),
        flags: dv.getBigUint64(o + 8, le),
        address: u64(o + 16),
        offset: u64(o + 24),
        size: u64(o + 32),
        link: u32(o + 40),
        info: u32(o + 44),
        entrySize: Number(dv.getBigUint64(o + 56, le)),
      });
    } else {
      rawSections.push({
        nameOffset: u32(o),
        type: u32(o + 4),
        flags: BigInt(u32(o + 8)),
        address: u32(o + 12),
        offset: u32(o + 16),
        size: u32(o + 20),
        link: u32(o + 24),
        info: u32(o + 28),
        entrySize: u32(o + 36),
      });
    }
  }

  const shstrtab = shstrndx < rawSections.length ? rawSections[shstrndx]! : null;
  const sectionEntropy = (offset: number, size: number): number => {
    if (size <= 0) return 0;
    const start = Math.min(offset, buf.length);
    const end = Math.min(offset + size, buf.length);
    if (end <= start) return 0;
    return round3(shannonEntropy(buf.subarray(start, end)));
  };
  const sections: ElfSection[] = rawSections.map((s) => {
    const name = shstrtab && shstrtab.size > 0 && s.nameOffset < shstrtab.size
      ? readCString(shstrtab.offset + s.nameOffset, shstrtab.size - s.nameOffset)
      : "";
    const flagBits: string[] = [];
    if (s.flags & SHF_WRITE) flagBits.push("W");
    if (s.flags & SHF_ALLOC) flagBits.push("A");
    if (s.flags & SHF_EXECINSTR) flagBits.push("X");
    return {
      name,
      type: s.type,
      typeName: SECTION_TYPE_NAMES[s.type] ?? `0x${s.type.toString(16)}`,
      flags: flagBits.join(""),
      address: s.address,
      offset: s.offset,
      size: s.type === SHT_NOBITS ? 0 : s.size,
      entrySize: s.entrySize,
      entropy: s.type === SHT_NOBITS ? 0 : sectionEntropy(s.offset, s.size),
    };
  });

  const programHeaders: ElfProgramHeader[] = [];
  for (let i = 0; i < Math.min(phnum, MAX_SECTIONS); i++) {
    const o = phoff + i * phentsize;
    if (o + phentsize > buf.length) break;
    let pType: number, pFlags: number, pOffset: number, pVaddr: number, pFilesz: number, pMemsz: number;
    if (bitness === 64) {
      pType = u32(o);
      pFlags = u32(o + 4);
      pOffset = u64(o + 8);
      pVaddr = u64(o + 16);
      pFilesz = u64(o + 32);
      pMemsz = u64(o + 40);
    } else {
      pType = u32(o);
      pOffset = u32(o + 4);
      pVaddr = u32(o + 8);
      pFilesz = u32(o + 16);
      pMemsz = u32(o + 20);
      pFlags = u32(o + 24);
    }
    const flagBits: string[] = [];
    if (pFlags & PF_R) flagBits.push("R");
    if (pFlags & PF_W) flagBits.push("W");
    if (pFlags & PF_X) flagBits.push("X");
    programHeaders.push({
      type: pType,
      typeName: PROGRAM_TYPE_NAMES[pType] ?? `0x${pType.toString(16)}`,
      flags: flagBits.join(""),
      offset: pOffset,
      address: pVaddr,
      fileSize: pFilesz,
      memorySize: pMemsz,
    });
  }

  // Dynamic symbols.
  const definedSymbols = new Set<string>();
  const undefinedSymbols = new Set<string>();
  const dynsym = rawSections.find((s) => s.type === SHT_DYNSYM);
  if (dynsym && dynsym.entrySize > 0) {
    const strtab = rawSections[dynsym.link];
    if (strtab && strtab.size > 0) {
      const count = Math.min(Math.floor(dynsym.size / dynsym.entrySize), MAX_SYMBOLS);
      const symSize = bitness === 64 ? 24 : 16;
      for (let i = 0; i < count; i++) {
        const o = dynsym.offset + i * symSize;
        if (o + symSize > buf.length) break;
        const nameOffset = u32(o);
        if (nameOffset >= strtab.size) continue;
        const name = readCString(strtab.offset + nameOffset, strtab.size - nameOffset);
        if (!name) continue;
        const shndx = bitness === 64 ? u16(o + 6) : u16(o + 14);
        if (shndx === SHN_UNDEF) undefinedSymbols.add(name);
        else definedSymbols.add(name);
      }
    }
  }

  const hasSymtab = rawSections.some((s) => s.type === SHT_SYMTAB);

  // Hardening-relevant dynamic entries, plus shared-library dependencies.
  let bindNow = false;
  let strtabAddr: number | null = null;
  const neededOffsets: number[] = [];
  let rpathOffset: number | null = null;
  let runpathOffset: number | null = null;
  const dynamic = rawSections.find((s) => s.type === SHT_DYNAMIC);
  if (dynamic) {
    const tagSize = bitness === 64 ? 16 : 8;
    const count = Math.floor(dynamic.size / tagSize);
    for (let i = 0; i < count; i++) {
      const o = dynamic.offset + i * tagSize;
      if (o + tagSize > buf.length) break;
      const tag = bitness === 64 ? Number(dv.getBigInt64(o, le)) : dv.getInt32(o, le);
      const value = word(o + (bitness === 64 ? 8 : 4));
      if (tag === DT_BIND_NOW) bindNow = true;
      if (tag === DT_FLAGS && (value & DF_BIND_NOW) !== 0) bindNow = true;
      if (tag === DT_FLAGS_1 && (value & DF_1_NOW) !== 0) bindNow = true;
      if (tag === DT_STRTAB) strtabAddr = value;
      if (tag === DT_NEEDED && neededOffsets.length < 256) neededOffsets.push(value);
      if (tag === DT_RPATH) rpathOffset = value;
      if (tag === DT_RUNPATH) runpathOffset = value;
    }
  }

  const vaddrToOffset = (address: number): number | null => {
    for (const header of programHeaders) {
      if (header.type !== PT_LOAD) continue;
      if (address >= header.address && address < header.address + header.fileSize) {
        return header.offset + (address - header.address);
      }
    }
    const section = rawSections.find((s) => s.address === address);
    return section ? section.offset : null;
  };

  const dynamicString = (nameOffset: number | null): string | null => {
    if (nameOffset === null || strtabAddr === null) return null;
    const strtabOffset = vaddrToOffset(strtabAddr);
    if (strtabOffset === null) return null;
    const start = strtabOffset + nameOffset;
    if (start >= buf.length) return null;
    return readCString(start, buf.length - start) || null;
  };

  const needed = neededOffsets
    .map((offset) => dynamicString(offset))
    .filter((name): name is string => name !== null);
  const rpath = dynamicString(rpathOffset);
  const runpath = dynamicString(runpathOffset);
  let rel = 0;
  let rela = 0;
  for (const section of rawSections) {
    if (section.entrySize <= 0) continue;
    const count = Math.floor(section.size / section.entrySize);
    if (section.type === SHT_REL) rel += count;
    if (section.type === SHT_RELA) rela += count;
  }

  const nxStack = (() => {
    const stack = programHeaders.find((p) => p.type === PT_GNU_STACK);
    if (!stack) return true; // Absent PT_GNU_STACK implies the older non-executable default on modern linkers.
    return !stack.flags.includes("X");
  })();

  const buildId = parseBuildId(buf, rawSections, le);

  // Overlay: bytes appended after the last section's raw data.
  let lastRawEnd = 0;
  for (const s of rawSections) {
    if (s.type === SHT_NOBITS) continue;
    const end = s.offset + s.size;
    if (end > lastRawEnd) lastRawEnd = end;
  }
  const overlay = lastRawEnd > 0 && lastRawEnd < buf.length
    ? { size: buf.length - lastRawEnd, sha256: createHash("sha256").update(buf.subarray(lastRawEnd)).digest("hex") }
    : null;

  const fortified = [...definedSymbols, ...undefinedSymbols].filter((n) => n.endsWith("_chk")).length;

  return {
    bitness,
    endianness: le ? "LE" : "BE",
    osAbi,
    type,
    typeName: TYPE_NAMES[type] ?? `0x${type.toString(16)}`,
    machine,
    machineName: MACHINE_NAMES[machine] ?? `machine-${machine}`,
    entry,
    sections,
    programHeaders,
    definedSymbols: [...definedSymbols].slice(0, MAX_SYMBOLS),
    undefinedSymbols: [...undefinedSymbols].slice(0, MAX_SYMBOLS),
    buildId,
    overlay,
    needed,
    rpath,
    runpath,
    relocations: { rel, rela },
    stripped: !hasSymtab,
    pie: type === 3,
    nxStack,
    relro: programHeaders.some((p) => p.type === PT_GNU_RELRO),
    bindNow,
    stackCanary: undefinedSymbols.has("__stack_chk_fail") || definedSymbols.has("__stack_chk_fail"),
    fortifiedFunctions: fortified,
  };
}

interface RawNoteSection {
  type: number;
  offset: number;
  size: number;
}

function parseBuildId(buf: Uint8Array, rawSections: RawNoteSection[], le: boolean): string | null {
  const u32 = (o: number) => {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    return dv.getUint32(o, le) >>> 0;
  };
  const align4 = (n: number) => (n + 3) & ~3;

  for (const section of rawSections) {
    if (section.type !== SHT_NOTE) continue;
    if (section.size === 0 || section.offset + section.size > buf.length) continue;
    let pos = section.offset;
    const end = section.offset + section.size;

    while (pos + 12 <= end) {
      const namesz = u32(pos);
      const descsz = u32(pos + 4);
      const ntype = u32(pos + 8);
      if (namesz > 1024 || descsz > 4096) break;

      const nameStart = pos + 12;
      const nameEnd = nameStart + namesz;
      // Note field alignment is relative to the start of the note record.
      const descStart = pos + 12 + align4(namesz);
      const descEnd = descStart + descsz;
      if (nameEnd > descStart || descEnd > end) break;

      let name = "";
      for (let i = nameStart; i < nameEnd; i++) {
        const b = buf[i]!;
        if (b === 0) continue;
        name += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
      }
      if (name === "GNU" && ntype === 3) {
        return [...buf.subarray(descStart, descEnd)]
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      }
      pos = descStart + align4(descsz);
    }
  }
  return null;
}
