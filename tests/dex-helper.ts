/** Minimal DEX file builder for tests. */

function leb(value: number): number[] {
  const bytes: number[] = [];
  let n = value;
  for (;;) {
    let byte = n & 0x7f;
    n >>>= 7;
    if (n !== 0) byte |= 0x80;
    bytes.push(byte);
    if (n === 0) break;
  }
  return bytes;
}

const STRINGS = [
  "Lcom/example/app/MainActivity;",
  "Ljava/lang/String;",
  "https://updates-malicious.example.com/beacon",
  "AKIAIOSFODNN7EXAMPLE",
  "plain literal string",
];

/** Builds a DEX file with five strings in the string table. */
export function makeDex(): Uint8Array {
  const headerSize = 0x70;
  const stringIdsOff = headerSize;
  const stringIdsSize = STRINGS.length;
  const stringIdsBytes = stringIdsSize * 4;
  const dataOff = stringIdsOff + stringIdsBytes;

  const stringDataItems = STRINGS.map((value) => {
    const raw = [...Buffer.from(value, "utf8")];
    return [...leb(value.length), ...raw, 0x00];
  });
  const dataBytes = stringDataItems.reduce((sum, item) => sum + item.length, 0);
  const fileSize = dataOff + dataBytes;

  const buf = Buffer.alloc(fileSize);
  buf.write("dex\n035\0", 0, 8, "ascii");
  buf.writeUInt32LE(0xdeadbeef, 8); // checksum
  for (let i = 0; i < 20; i++) buf.writeUInt8(i + 1, 12 + i); // signature
  buf.writeUInt32LE(fileSize, 32);
  buf.writeUInt32LE(headerSize, 36);
  buf.writeUInt32LE(0x12345678, 40); // endian tag
  buf.writeUInt32LE(0, 44); // link_size
  buf.writeUInt32LE(0, 48); // link_off
  buf.writeUInt32LE(dataOff, 52); // map_off
  buf.writeUInt32LE(stringIdsSize, 56);
  buf.writeUInt32LE(stringIdsOff, 60);
  buf.writeUInt32LE(4, 64); // type_ids_size
  buf.writeUInt32LE(0, 68); // type_ids_off (unused by the inspector)
  buf.writeUInt32LE(6, 72); // proto_ids_size
  buf.writeUInt32LE(0, 76);
  buf.writeUInt32LE(7, 80); // field_ids_size
  buf.writeUInt32LE(0, 84);
  buf.writeUInt32LE(27, 88); // method_ids_size
  buf.writeUInt32LE(0, 92);
  buf.writeUInt32LE(3, 96); // class_defs_size
  buf.writeUInt32LE(0, 100);
  buf.writeUInt32LE(dataBytes, 104);
  buf.writeUInt32LE(dataOff, 108);

  let offset = dataOff;
  for (let i = 0; i < stringIdsSize; i++) {
    buf.writeUInt32LE(offset, stringIdsOff + i * 4);
    offset += stringDataItems[i]!.length;
  }
  let writeAt = dataOff;
  for (const item of stringDataItems) {
    Buffer.from(item).copy(buf, writeAt);
    writeAt += item.length;
  }

  return new Uint8Array(buf);
}
