/** Test helpers to build synthetic binary buffers. */

export function makeElf64(options: { pie?: boolean; withCanaryImport?: boolean; withCode?: boolean; buildId?: string } = {}): Uint8Array {
  const pie = options.pie ?? false;
  const withCanary = options.withCanaryImport ?? true;

  const encoder = new TextEncoder();
  const dynstr = Buffer.concat([
    Buffer.from([0]),
    encoder.encode("__stack_chk_fail\0"),
    encoder.encode("libc.so.6\0"),
  ]);
  const shstrtab = options.buildId
    ? encoder.encode("\0.dynsym\0.dynstr\0.shstrtab\0.note\0")
    : encoder.encode("\0.dynsym\0.dynstr\0.shstrtab\0");
  const shstrDynsym = 1;
  const shstrDynstr = 9;
  const shstrShstrtab = 17;

  const symCount = withCanary ? 1 : 1;
  const dynsymSize = symCount * 24;

  const ehsize = 64;
  const shoff = ehsize;
  const shnum = options.buildId ? 5 : 4;
  const shentsize = 64;
  const dataOffset = shoff + shnum * shentsize;

  const dynsymOffset = dataOffset;
  const dynstrOffset = dynsymOffset + dynsymSize;
  const shstrOffset = dynstrOffset + dynstr.length;
  const noteOffset = shstrOffset + shstrtab.length;
  let buildIdBytes = Buffer.alloc(0);
  if (options.buildId) {
    const desc = Buffer.from(options.buildId, "hex");
    buildIdBytes = Buffer.alloc(16 + desc.length);
    buildIdBytes.writeUInt32LE(4, 0); // namesz
    buildIdBytes.writeUInt32LE(desc.length, 4); // descsz
    buildIdBytes.writeUInt32LE(3, 8); // NT_GNU_BUILD_ID
    Buffer.from("GNU\0", "ascii").copy(buildIdBytes, 12);
    desc.copy(buildIdBytes, 16);
  }
  const totalSize = options.buildId ? noteOffset + buildIdBytes.length : noteOffset;

  const buf = Buffer.alloc(totalSize);
  // e_ident
  buf.writeUInt8(0x7f, 0);
  buf.write("ELF", 1, "ascii");
  buf.writeUInt8(2, 4); // 64-bit
  buf.writeUInt8(1, 5); // little endian
  buf.writeUInt8(1, 6); // version
  buf.writeUInt8(3, 7); // Linux OS ABI

  buf.writeUInt16LE(pie ? 3 : 2, 16); // e_type: DYN (PIE) or EXEC
  buf.writeUInt16LE(62, 18); // x86-64
  buf.writeUInt32LE(1, 20); // version
  buf.writeBigUInt64LE(0x1000n, 24); // entry
  buf.writeBigUInt64LE(0n, 32); // phoff
  buf.writeBigUInt64LE(BigInt(shoff), 40); // shoff
  buf.writeUInt32LE(0, 48); // flags
  buf.writeUInt16LE(ehsize, 52);
  buf.writeUInt16LE(0, 54); // phentsize
  buf.writeUInt16LE(0, 56); // phnum
  buf.writeUInt16LE(shentsize, 58);
  buf.writeUInt16LE(shnum, 60);
  buf.writeUInt16LE(3, 62); // shstrndx

  const writeShdr = (index: number, name: number, type: number, flags: bigint, addr: number, offset: number, size: number, link: number, info: number, entsize: number) => {
    const o = shoff + index * shentsize;
    buf.writeUInt32LE(name, o);
    buf.writeUInt32LE(type, o + 4);
    buf.writeBigUInt64LE(flags, o + 8);
    buf.writeBigUInt64LE(BigInt(addr), o + 16);
    buf.writeBigUInt64LE(BigInt(offset), o + 24);
    buf.writeBigUInt64LE(BigInt(size), o + 32);
    buf.writeUInt32LE(link, o + 40);
    buf.writeUInt32LE(info, o + 44);
    buf.writeBigUInt64LE(8n, o + 48); // addralign
    buf.writeBigUInt64LE(BigInt(entsize), o + 56);
  };

  writeShdr(0, 0, 0, 0n, 0, 0, 0, 0, 0, 0); // NULL
  writeShdr(1, shstrDynsym, 11, 0x2n, 0x4000, dynsymOffset, dynsymSize, 2, 1, 24); // DYNSYM
  writeShdr(2, shstrDynstr, 3, 0x2n, 0x5000, dynstrOffset, dynstr.length, 0, 0, 0); // STRTAB
  writeShdr(3, shstrShstrtab, 3, 0n, 0, shstrOffset, shstrtab.length, 0, 0, 0); // SHSTRTAB
  if (options.buildId) writeShdr(4, 27, 7, 0x2n, 0, noteOffset, buildIdBytes.length, 0, 0, 0); // SHT_NOTE

  // One undefined symbol: __stack_chk_fail
  const symO = dynsymOffset;
  buf.writeUInt32LE(1, symO); // st_name -> offset 1 in dynstr
  buf.writeUInt8(0x12, symO + 4); // STB_GLOBAL | STT_FUNC
  buf.writeUInt8(0, symO + 5); // other
  buf.writeUInt16LE(0, symO + 6); // SHN_UNDEF
  buf.writeBigUInt64LE(0n, symO + 8);
  buf.writeBigUInt64LE(0n, symO + 16);

  dynstr.copy(buf, dynstrOffset);
  Buffer.from(shstrtab).copy(buf, shstrOffset);
  buildIdBytes.copy(buf, noteOffset);

  return new Uint8Array(buf);
}

export function makeZip(files: Array<{ name: string; content: string | Uint8Array; method?: number }>): Uint8Array {
  const crcTable = makeCrcTable();
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  for (const file of files) {
    const nameBuf = Buffer.from(file.name, "utf8");
    const data = typeof file.content === "string" ? Buffer.from(file.content, "utf8") : Buffer.from(file.content);
    const crc = crc32(data, crcTable);
    const method = file.method ?? 0; // 0 = stored

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x800, 6); // UTF-8 flag
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(0, 10); // time
    local.writeUInt16LE(0, 12); // date
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed
    local.writeUInt32LE(data.length, 22); // uncompressed
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra
    localParts.push(local, nameBuf, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0x800, 8); // UTF-8 flag
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk number
    central.writeUInt16LE(0, 36); // internal attrs
    central.writeUInt32LE(0, 38); // external attrs
    central.writeUInt32LE(offset, 42); // local header offset
    centralParts.push(Buffer.concat([central, nameBuf]));

    offset += 30 + nameBuf.length + data.length;
  }

  const centralStart = offset;
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4); // disk
  eocd.writeUInt16LE(0, 6); // central dir disk
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralStart, 16);
  eocd.writeUInt16LE(0, 20); // comment

  return new Uint8Array(Buffer.concat([...localParts, ...centralParts, eocd]));
}

function makeCrcTable(): Uint32Array {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
}

function crc32(data: Buffer, table: Uint32Array): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc = (table[(crc ^ byte) & 0xff]! ^ (crc >>> 8)) >>> 0;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
