/** PyInstaller onefile CArchive inspector, based on the public cookie format. */
export interface PyInstallerEntry {
  name: string;
  offset: number;
  compressedSize: number;
  uncompressedSize: number;
  compressed: boolean;
  typeCode: string;
}

export interface PyInstallerInfo {
  magic: string;
  packageLength: number;
  tocOffset: number;
  tocLength: number;
  pythonVersion: number | null;
  pythonLibrary: string;
  entries: PyInstallerEntry[];
  entryCount: number;
  truncated: boolean;
}

const MAGIC = [0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e];
const COOKIE_SIZE = 88;
const MAX_ENTRIES = 300;

export function parsePyInstaller(buf: Uint8Array): PyInstallerInfo {
  let cookie = -1;
  const start = Math.max(0, buf.length - 1024 * 1024);
  outer: for (let i = buf.length - COOKIE_SIZE; i >= start; i--) {
    for (let j = 0; j < MAGIC.length; j++) {
      if (buf[i + j] !== MAGIC[j]) continue outer;
    }
    cookie = i;
    break;
  }
  if (cookie === -1) throw new Error("Not a PyInstaller archive: cookie not found");
  if (cookie + COOKIE_SIZE > buf.length) throw new Error("PyInstaller cookie is truncated");

  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u32be = (offset: number) => dv.getUint32(offset, false) >>> 0;
  const packageLength = u32be(cookie + 8);
  const tocOffsetRelative = u32be(cookie + 12);
  const tocLength = u32be(cookie + 16);
  const pythonVersion = u32be(cookie + 20);
  let libName = "";
  for (let i = cookie + 24; i < cookie + COOKIE_SIZE; i++) {
    const b = buf[i]!;
    if (b === 0) break;
    libName += String.fromCharCode(b);
  }

  // TOC offsets in the cookie are relative to the start of the archive.
  const archiveStart = cookie + COOKIE_SIZE - packageLength;
  const tocStart = archiveStart + tocOffsetRelative;
  const entries: PyInstallerEntry[] = [];
  let pos = tocStart;
  const tocEnd = Math.min(tocStart + tocLength, buf.length);
  while (pos + 18 <= tocEnd && entries.length < MAX_ENTRIES) {
    const structLength = u32be(pos);
    if (structLength < 18 || pos + structLength > buf.length) break;
    const offset = u32be(pos + 4);
    const compressedSize = u32be(pos + 8);
    const uncompressedSize = u32be(pos + 12);
    const compressed = buf[pos + 16] !== 0;
    const typeCode = String.fromCharCode(buf[pos + 17]!);
    let name = "";
    for (let i = pos + 18; i < pos + structLength; i++) {
      const b = buf[i]!;
      if (b === 0) break;
      name += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
    }
    if (name) entries.push({ name, offset, compressedSize, uncompressedSize, compressed, typeCode });
    pos += structLength;
  }

  return {
    magic: "MEI cookie",
    packageLength,
    tocOffset: tocOffsetRelative,
    tocLength,
    pythonVersion: pythonVersion === 0 ? null : pythonVersion,
    pythonLibrary: libName,
    entries,
    entryCount: entries.length,
    truncated: entries.length >= MAX_ENTRIES || pos < tocEnd,
  };
}
