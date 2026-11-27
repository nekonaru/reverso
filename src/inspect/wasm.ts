/** Native WebAssembly (.wasm) module inspector. Parses the binary format. */

export interface WasmType {
  params: string[];
  results: string[];
}

export interface WasmImport {
  module: string;
  name: string;
  kind: string;
}

export interface WasmExport {
  name: string;
  kind: string;
  index: number;
}

export interface WasmMemory {
  min: number;
  max: number | null;
}

export interface WasmInfo {
  version: number;
  sections: Array<{ id: number; name: string; size: number }>;
  types: { count: number; functions: WasmType[] };
  imports: WasmImport[];
  exports: WasmExport[];
  counts: {
    functions: number;
    tables: number;
    memories: number;
    globals: number;
    dataSegments: number;
    elementSegments: number;
  };
  memories: WasmMemory[];
  names: { module: string | null; functions: Array<{ index: number; name: string }> };
  producers: Record<string, string[]>;
}

const SECTION_NAMES: Record<number, string> = {
  0: "custom",
  1: "type",
  2: "import",
  3: "function",
  4: "table",
  5: "memory",
  6: "global",
  7: "export",
  8: "start",
  9: "element",
  10: "code",
  11: "data",
  12: "datacount",
  13: "tag",
};

const VALTYPE_NAMES: Record<number, string> = {
  0x7f: "i32",
  0x7e: "i64",
  0x7d: "f32",
  0x7c: "f64",
  0x7b: "v128",
  0x70: "funcref",
  0x6f: "externref",
};

const IMPORT_EXPORT_KIND_NAMES: Record<number, string> = {
  0x00: "func",
  0x01: "table",
  0x02: "memory",
  0x03: "global",
  0x04: "tag",
};

const MAX_ITEMS = 1000;
const MAX_FUNCTION_NAMES = 500;
const MAX_NAME_BYTES = 1024;

export function parseWasm(buf: Uint8Array): WasmInfo {
  if (buf.length < 8 || buf[0] !== 0x00 || buf[1] !== 0x61 || buf[2] !== 0x73 || buf[3] !== 0x6d) {
    throw new Error("Not a WebAssembly module: missing \\0asm magic");
  }
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const version = dv.getUint32(4, true);

  const info: WasmInfo = {
    version,
    sections: [],
    types: { count: 0, functions: [] },
    imports: [],
    exports: [],
    counts: { functions: 0, tables: 0, memories: 0, globals: 0, dataSegments: 0, elementSegments: 0 },
    memories: [],
    names: { module: null, functions: [] },
    producers: {},
  };

  let pos = 8;
  while (pos < buf.length) {
    const id = buf[pos]!;
    pos += 1;
    const [sectionSize, afterSize] = readUleb(buf, pos);
    pos = afterSize;
    const sectionEnd = pos + sectionSize;
    if (sectionEnd > buf.length) throw new Error(`Truncated wasm section ${id}`);
    info.sections.push({ id, name: SECTION_NAMES[id] ?? `unknown-${id}`, size: sectionSize });
    parseSection(id, buf, pos, sectionEnd, info);
    pos = sectionEnd;
  }

  return info;
}

function parseSection(id: number, buf: Uint8Array, start: number, end: number, info: WasmInfo): void {
  let pos = start;
  const readUlebHere = (): number => {
    const [value, next] = readUleb(buf, pos);
    pos = next;
    return value;
  };
  const readNameHere = (): string => {
    const [value, next] = readName(buf, pos);
    pos = next;
    return value;
  };
  const readValtype = (): string => {
    const byte = buf[pos]!;
    pos += 1;
    return VALTYPE_NAMES[byte] ?? `0x${byte.toString(16)}`;
  };
  const readLimits = (): WasmMemory => {
    const flags = buf[pos]!;
    pos += 1;
    const min = readUlebHere();
    const max = (flags & 0x01) !== 0 ? readUlebHere() : null;
    return { min, max };
  };

  switch (id) {
    case 0: { // custom: name section and producers metadata
      const name = readNameHere();
      if (name === "name") parseNameSection(buf, pos, end, info);
      else if (name === "producers") parseProducers(buf, pos, end, info);
      return;
    }
    case 1: { // type
      const count = readUlebHere();
      info.types.count = count;
      for (let i = 0; i < Math.min(count, MAX_ITEMS); i++) {
        const form = buf[pos]!;
        pos += 1;
        if (form !== 0x60) throw new Error(`Unsupported wasm type form: 0x${form.toString(16)}`);
        const paramCount = readUlebHere();
        const params: string[] = [];
        for (let j = 0; j < paramCount; j++) params.push(readValtype());
        const resultCount = readUlebHere();
        const results: string[] = [];
        for (let j = 0; j < resultCount; j++) results.push(readValtype());
        info.types.functions.push({ params, results });
      }
      return;
    }
    case 2: { // import
      const count = readUlebHere();
      for (let i = 0; i < Math.min(count, MAX_ITEMS); i++) {
        const module = readNameHere();
        const name = readNameHere();
        const kindByte = buf[pos]!;
        pos += 1;
        const kind = IMPORT_EXPORT_KIND_NAMES[kindByte] ?? `kind-${kindByte}`;
        if (kindByte === 0x00) { readUlebHere(); /* type index */ }
        else if (kindByte === 0x01) { pos += 1; /* reftype */ readLimits(); }
        else if (kindByte === 0x02) { info.memories.push(readLimits()); }
        else if (kindByte === 0x03) { pos += 2; /* valtype + mutability */ }
        else if (kindByte === 0x04) { pos += 1; readUlebHere(); /* attribute + type index */ }
        info.imports.push({ module, name, kind });
      }
      return;
    }
    case 3: { // function: type indices only
      const count = readUlebHere();
      info.counts.functions = count;
      return;
    }
    case 4: { // table
      const count = readUlebHere();
      info.counts.tables = count;
      for (let i = 0; i < count; i++) { pos += 1; /* reftype */ readLimits(); }
      return;
    }
    case 5: { // memory
      const count = readUlebHere();
      info.counts.memories += count;
      for (let i = 0; i < count; i++) info.memories.push(readLimits());
      return;
    }
    case 6: { // global
      const count = readUlebHere();
      info.counts.globals = count;
      for (let i = 0; i < count; i++) { readValtype(); pos += 1; /* mutability */ }
      return;
    }
    case 7: { // export
      const count = readUlebHere();
      for (let i = 0; i < Math.min(count, MAX_ITEMS); i++) {
        const name = readNameHere();
        const kindByte = buf[pos]!;
        pos += 1;
        const index = readUlebHere();
        info.exports.push({ name, kind: IMPORT_EXPORT_KIND_NAMES[kindByte] ?? `kind-${kindByte}`, index });
      }
      return;
    }
    case 9: { // element
      const count = readUlebHere();
      info.counts.elementSegments = count;
      return;
    }
    case 10: { // code
      const count = readUlebHere();
      info.counts.functions = count; // code section overrides the function section count by construction
      return;
    }
    case 11: { // data
      const count = readUlebHere();
      info.counts.dataSegments = count;
      return;
    }
    default:
      return; // start, datacount, tag, future sections: size is already known, skip.
  }
}

function parseProducers(buf: Uint8Array, start: number, end: number, info: WasmInfo): void {
  let pos = start;
  while (pos < end) {
    const subsectionId = buf[pos]!;
    pos += 1;
    const [size, afterSize] = readUleb(buf, pos);
    pos = afterSize;
    const subEnd = pos + size;
    if (subEnd > end) break;
    const [count, afterCount] = readUleb(buf, pos);
    pos = afterCount;
    const key = subsectionId === 0 ? "languages" : subsectionId === 1 ? "tools" : `subsection-${subsectionId}`;
    const values: string[] = [];
    for (let i = 0; i < Math.min(count, 50); i++) {
      const [name, afterName] = readName(buf, pos);
      const [version, afterVersion] = readName(buf, afterName);
      values.push(version ? `${name}@${version}` : name);
      pos = afterVersion;
    }
    info.producers[key] = values;
    pos = subEnd;
  }
}

function parseNameSection(buf: Uint8Array, start: number, end: number, info: WasmInfo): void {
  let pos = start;
  while (pos < end) {
    const subsectionId = buf[pos]!;
    pos += 1;
    const [size, afterSize] = readUleb(buf, pos);
    pos = afterSize;
    const subEnd = pos + size;
    if (subEnd > end) break;
    if (subsectionId === 0) {
      const [name, next] = readName(buf, pos);
      info.names.module = name;
      pos = next;
    } else if (subsectionId === 1) {
      const [count, afterCount] = readUleb(buf, pos);
      pos = afterCount;
      for (let i = 0; i < Math.min(count, MAX_FUNCTION_NAMES); i++) {
        const [index, afterIndex] = readUleb(buf, pos);
        const [name, afterName] = readName(buf, afterIndex);
        info.names.functions.push({ index, name });
        pos = afterName;
      }
    }
    pos = subEnd;
  }
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
    if (shift > 28) throw new Error("ULEB128 too large");
  }
  return [result >>> 0, pos];
}

function readName(buf: Uint8Array, offset: number): [string, number] {
  const [length, afterLength] = readUleb(buf, offset);
  const start = afterLength;
  const end = Math.min(start + Math.min(length, MAX_NAME_BYTES), buf.length);
  const value = new TextDecoder("utf-8").decode(buf.subarray(start, end));
  return [value, start + length > buf.length ? buf.length : start + length];
}
