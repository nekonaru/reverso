/** Native DEX (Android Dalvik Executable) inspector. Parses the header and string table. */

export interface DexStringCategory {
  category: string;
  count: number;
  samples: string[];
}

export interface DexInfo {
  version: string;
  fileSize: number;
  headerSize: number;
  checksum: string;
  signature: string;
  counts: {
    stringIds: number;
    typeIds: number;
    protoIds: number;
    fieldIds: number;
    methodIds: number;
    classDefs: number;
    dataSize: number;
  };
  strings: {
    total: number;
    truncated: boolean;
    categories: DexStringCategory[];
  };
  classes: string[];
}

const MAX_STRING_IDS = 5000;
const MAX_STRING_BYTES = 4096;
const MAX_CLASSES = 300;
const ULEB_MAX_SHIFT = 28;

/** Resolves class_defs through type_ids and string_ids to readable descriptors. */
function readClassNames(buf: Uint8Array, strings: Array<{ offset: number; value: string }>, dv: DataView): string[] {
  const typeIdsSize = dv.getUint32(64, true) >>> 0;
  const typeIdsOff = dv.getUint32(68, true) >>> 0;
  const classDefsSize = dv.getUint32(96, true) >>> 0;
  const classDefsOff = dv.getUint32(100, true) >>> 0;

  if (typeIdsOff + typeIdsSize * 4 > buf.length || classDefsOff + classDefsSize * 32 > buf.length) return [];

  const typeIds: string[] = [];
  for (let i = 0; i < Math.min(typeIdsSize, strings.length); i++) {
    const stringIndex = dv.getUint32(typeIdsOff + i * 4, true) >>> 0;
    typeIds.push(strings[stringIndex]?.value ?? "");
  }

  const out: string[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < Math.min(classDefsSize, MAX_CLASSES); i++) {
    const classIndex = dv.getUint32(classDefsOff + i * 32, true) >>> 0;
    const descriptor = typeIds[classIndex];
    if (!descriptor || seen.has(descriptor)) continue;
    seen.add(descriptor);
    out.push(descriptor);
  }
  return out;
}

export function parseDex(buf: Uint8Array): DexInfo {
  if (buf.length < 0x70) throw new Error("Not a DEX file: too small");
  if (buf[0] !== 0x64 || buf[1] !== 0x65 || buf[2] !== 0x78 || buf[3] !== 0x0a || buf[7] !== 0x00) {
    throw new Error("Not a DEX file: missing dex magic");
  }
  if (!/^[0-9]{3}$/.test(String.fromCharCode(buf[4]!, buf[5]!, buf[6]!))) {
    throw new Error("Not a DEX file: malformed version in magic");
  }

  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u32 = (offset: number) => dv.getUint32(offset, true);

  const fileSize = u32(32);
  const headerSize = u32(36);
  const endianTag = u32(40);
  if (headerSize !== 0x70) throw new Error(`Unexpected DEX header size: ${headerSize}`);
  if (endianTag !== 0x12345678) throw new Error("Not a native-endian DEX file (reverse-endian is not supported)");
  if (fileSize > buf.length) throw new Error("Truncated DEX file");

  const dataSize = u32(104);
  const dataOff = u32(108);
  if (dataOff + dataSize > buf.length) throw new Error("DEX data section out of bounds");

  const stringIdsSize = u32(56);
  const stringIdsOff = u32(60);
  if (stringIdsOff + stringIdsSize * 4 > buf.length) throw new Error("DEX string_ids out of bounds");

  const checksum = u32(8).toString(16).padStart(8, "0");
  const signature = [...buf.subarray(12, 32)].map((b) => b.toString(16).padStart(2, "0")).join("");

  const strings = readStringTable(buf, stringIdsSize, stringIdsOff);
  const categorized = categorizeStrings(strings);
  const classes = readClassNames(buf, strings, dv);

  return {
    version: String.fromCharCode(buf[4]!, buf[5]!, buf[6]!),
    fileSize,
    headerSize,
    checksum,
    signature,
    counts: {
      stringIds: stringIdsSize,
      typeIds: u32(64),
      protoIds: u32(72),
      fieldIds: u32(80),
      methodIds: u32(88),
      classDefs: u32(96),
      dataSize,
    },
    strings: {
      total: strings.length,
      truncated: stringIdsSize > strings.length,
      categories: categorized,
    },
    classes,
  };
}

function readStringTable(buf: Uint8Array, stringIdsSize: number, stringIdsOff: number): Array<{ offset: number; value: string }> {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out: Array<{ offset: number; value: string }> = [];
  const limit = Math.min(stringIdsSize, MAX_STRING_IDS);

  for (let i = 0; i < limit; i++) {
    const stringDataOff = dv.getUint32(stringIdsOff + i * 4, true);
    if (stringDataOff >= buf.length) continue;
    try {
      const [, afterLength] = readUleb(buf, stringDataOff);
      let end = afterLength;
      const maxEnd = Math.min(afterLength + MAX_STRING_BYTES, buf.length);
      while (end < maxEnd && buf[end] !== 0x00) end += 1;
      if (end >= maxEnd) continue;
      const value = new TextDecoder("utf-8").decode(buf.subarray(afterLength, end));
      out.push({ offset: stringDataOff, value });
    } catch {
      continue; // Skip corrupt entries instead of failing the whole table.
    }
  }

  return out;
}

const CATEGORY_PATTERNS: Array<{ category: string; pattern: RegExp }> = [
  { category: "url", pattern: /^https?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{3,}$/ },
  { category: "ipv4", pattern: /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$/ },
  { category: "email", pattern: /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/ },
  { category: "filepath", pattern: /^\/(?:[\w.-]+\/)*[\w.-]+$|^[A-Za-z]:\\/ },
  { category: "class-descriptor", pattern: /^L[\w/$]+;$/ },
  { category: "package", pattern: /^[a-z][\w]*(\.[a-z][\w]*){2,}$/ },
  { category: "jwt", pattern: /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}$/ },
  { category: "aws-key", pattern: /^(?:AKIA|ASIA)[0-9A-Z]{16}$/ },
  { category: "private-key", pattern: /PRIVATE KEY/ },
];

function categorizeStrings(strings: Array<{ offset: number; value: string }>): DexStringCategory[] {
  const buckets = new Map<string, { count: number; samples: string[] }>();
  for (const { value } of strings) {
    for (const { category, pattern } of CATEGORY_PATTERNS) {
      if (!pattern.test(value)) continue;
      let bucket = buckets.get(category);
      if (!bucket) {
        bucket = { count: 0, samples: [] };
        buckets.set(category, bucket);
      }
      bucket.count += 1;
      if (bucket.samples.length < 25 && !bucket.samples.includes(value)) {
        bucket.samples.push(value);
      }
    }
  }
  return [...buckets.entries()]
    .map(([category, { count, samples }]) => ({ category, count, samples }))
    .sort((a, b) => b.count - a.count);
}

function readUleb(buf: Uint8Array, offset: number): [number, number] {
  let result = 0;
  let shift = 0;
  let pos = offset;
  for (;;) {
    if (pos >= buf.length) throw new Error("Truncated ULEB128");
    const byte = buf[pos]!;
    pos += 1;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift > ULEB_MAX_SHIFT) throw new Error("ULEB128 too large");
  }
  return [result >>> 0, pos];
}
