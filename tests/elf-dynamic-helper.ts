/** Minimal ELF64 with a dynamic section and DT_NEEDED entries. */
export function makeElfWithDynamic(): Uint8Array {
  const encoder = new TextEncoder();
  const shstrtab = Buffer.from(encoder.encode("\0.dynstr\0.dynamic\0.shstrtab\0.rela.dyn\0"));
  const strtab = Buffer.from(encoder.encode("\0libc.so.6\0libm.so.6\0/usr/lib\0"));
  const libc = 1;
  const libm = 11;
  const rpath = 21;

  const shoff = 64;
  const shnum = 5;
  const shentsize = 64;
  const strtabOffset = shoff + shnum * shentsize;
  const shstrOffset = strtabOffset + strtab.length;

  const entries: Array<[number, number]> = [
    [5, 0x1000], // DT_STRTAB -> vaddr of .dynstr
    [1, libc],
    [1, libm],
    [15, rpath], // DT_RPATH
    [24, 0], // DT_BIND_NOW
    [0, 0], // DT_NULL
  ];
  const dynamicSize = entries.length * 16;
  const dynamicOffset = shstrOffset + shstrtab.length;
  const relaOffset = dynamicOffset + dynamicSize;
  const buf = Buffer.alloc(relaOffset + 48);

  buf.writeUInt8(0x7f, 0);
  buf.write("ELF", 1, "ascii");
  buf.writeUInt8(2, 4); // ELF64
  buf.writeUInt8(1, 5); // little endian
  buf.writeUInt8(1, 6);
  buf.writeUInt16LE(3, 16); // ET_DYN
  buf.writeUInt16LE(62, 18); // x86-64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(BigInt(shoff), 40);
  buf.writeUInt16LE(64, 52); // e_ehsize
  buf.writeUInt16LE(shentsize, 58);
  buf.writeUInt16LE(shnum, 60);
  buf.writeUInt16LE(3, 62); // shstrndx

  const writeShdr = (index: number, name: number, type: number, flags: bigint, addr: number, offset: number, size: number, link: number) => {
    const o = shoff + index * shentsize;
    buf.writeUInt32LE(name, o);
    buf.writeUInt32LE(type, o + 4);
    buf.writeBigUInt64LE(flags, o + 8);
    buf.writeBigUInt64LE(BigInt(addr), o + 16);
    buf.writeBigUInt64LE(BigInt(offset), o + 24);
    buf.writeBigUInt64LE(BigInt(size), o + 32);
    buf.writeUInt32LE(link, o + 40);
    buf.writeBigUInt64LE(8n, o + 48);
  };
  writeShdr(0, 0, 0, 0n, 0, 0, 0, 0);
  writeShdr(1, 1, 3, 0x2n, 0x1000, strtabOffset, strtab.length, 0); // .dynstr
  writeShdr(2, 9, 6, 0x3n, 0x2000, dynamicOffset, dynamicSize, 1); // .dynamic
  writeShdr(3, 18, 3, 0n, 0, shstrOffset, shstrtab.length, 0); // .shstrtab
  const rela = shoff + 4 * shentsize;
  buf.writeUInt32LE(27, rela); // name ".rela.dyn"
  buf.writeUInt32LE(4, rela + 4); // SHT_RELA
  buf.writeBigUInt64LE(0x2n, rela + 8);
  buf.writeBigUInt64LE(0x3000n, rela + 16);
  buf.writeBigUInt64LE(BigInt(relaOffset), rela + 24);
  buf.writeBigUInt64LE(48n, rela + 32);
  buf.writeBigUInt64LE(24n, rela + 56); // entsize

  strtab.copy(buf, strtabOffset);
  Buffer.from(shstrtab).copy(buf, shstrOffset);
  for (let i = 0; i < entries.length; i++) {
    const [tag, value] = entries[i]!;
    buf.writeBigInt64LE(BigInt(tag), dynamicOffset + i * 16);
    buf.writeBigUInt64LE(BigInt(value), dynamicOffset + i * 16 + 8);
  }

  return new Uint8Array(buf);
}
