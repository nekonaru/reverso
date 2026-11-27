/** Minimal WebAssembly module builder for tests. */

function leb(value: number): number[] {
  const bytes: number[] = [];
  let n = value;
  while (true) {
    let byte = n & 0x7f;
    n >>>= 7;
    if (n !== 0) byte |= 0x80;
    bytes.push(byte);
    if (n === 0) break;
  }
  return bytes;
}

function nameBytes(value: string): number[] {
  const raw = [...Buffer.from(value, "utf8")];
  return [...leb(raw.length), ...raw];
}

function section(id: number, payload: number[]): number[] {
  return [id, ...leb(payload.length), ...payload];
}

/** Builds a module with one i32->i32 function, one import, one export and a name section. */
export function makeWasm(): Uint8Array {
  const typeSection = section(1, [...leb(1), 0x60, ...leb(1), 0x7f, ...leb(1), 0x7f]);
  const importSection = section(2, [...leb(1), ...nameBytes("env"), ...nameBytes("mul"), 0x00, ...leb(0)]);
  const functionSection = section(3, [...leb(1), ...leb(0)]);
  const exportSection = section(7, [...leb(1), ...nameBytes("main"), 0x00, ...leb(0)]);
  const codeSection = section(10, [...leb(1), ...leb(4), ...leb(0), 0x00, 0x0b]);
  const namePayload = [...nameBytes("name"), 1, ...leb(7), ...leb(1), ...leb(0), ...nameBytes("main")];
  const nameSection = section(0, namePayload);
  const producersPayload = [
    ...nameBytes("producers"),
    0, ...leb(11), ...leb(1), ...nameBytes("Rust"), ...nameBytes("1.75"),
  ];
  const producersSection = section(0, producersPayload);
  const bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...typeSection, ...importSection, ...functionSection, ...exportSection, ...codeSection, ...nameSection, ...producersSection];
  return new Uint8Array(bytes);
}
