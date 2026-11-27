/** Native .NET metadata stream inspector (limited, read-only). */
import { parsePe } from "../binary/pe.js";

const asciiDecoder = new TextDecoder("ascii");
const utf8Decoder = new TextDecoder("utf8");

export interface DotNetStream {
  name: string;
  offset: number;
  size: number;
}

export interface DotNetInfo {
  runtimeVersion: string;
  metadataVersion: string;
  streams: DotNetStream[];
  stringSamples: string[];
}

export function parseDotNet(buf: Uint8Array): DotNetInfo {
  const pe = parsePe(buf);
  if (!pe.isDotNet) throw new Error("Not a .NET assembly: no CLR data directory");

  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const peOffset = dv.getUint32(0x3c, true);
  const opt = peOffset + 24;
  const isPlus = dv.getUint16(opt, true) === 0x20b;
  const dirBase = opt + (isPlus ? 112 : 96);
  const clrRva = dv.getUint32(dirBase + 14 * 8, true) >>> 0;
  const toOffset = (rva: number): number | null => {
    for (const section of pe.sections) {
      const extent = Math.max(section.virtualSize, section.sizeOfRawData);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + extent) {
        const offset = rva + (section.pointerToRawData - section.virtualAddress);
        return offset >= 0 && offset < buf.length ? offset : null;
      }
    }
    return null;
  };

  const cliOffset = toOffset(clrRva);
  if (cliOffset === null || cliOffset + 16 > buf.length) throw new Error(".NET CLI header out of bounds");
  const metadataRva = dv.getUint32(cliOffset + 8, true) >>> 0;
  const metadataOffset = toOffset(metadataRva);
  if (metadataOffset === null || metadataOffset + 20 > buf.length) throw new Error(".NET metadata root out of bounds");

  const signature = asciiDecoder.decode(buf.subarray(metadataOffset, metadataOffset + 4));
  if (signature !== "BSJB") throw new Error("Not a .NET assembly: invalid metadata signature");
  const versionLength = dv.getUint32(metadataOffset + 4, true) >>> 0;
  if (versionLength > 512) throw new Error(".NET metadata version string too long");
  const versionStart = metadataOffset + 12;
  const metadataVersion = utf8Decoder.decode(buf.subarray(versionStart, versionStart + versionLength - 1)).replace(/\0+$/, "");
  let pos = versionStart + versionLength;
  pos += 2; // flags
  const streamCount = dv.getUint16(pos, true);
  pos += 2;

  const streams: DotNetStream[] = [];
  for (let i = 0; i < Math.min(streamCount, 32); i++) {
    if (pos + 8 > buf.length) break;
    const offset = dv.getUint32(pos, true) >>> 0;
    const size = dv.getUint32(pos + 4, true) >>> 0;
    pos += 8;
    let name = "";
    for (let j = 0; j < 32; j++) {
      const b = buf[pos + j]!;
      if (b === 0) break;
      name += String.fromCharCode(b);
    }
    while (pos < buf.length && buf[pos] !== 0) pos += 1;
    pos = (pos + 4) & ~3;
    if (name) streams.push({ name, offset, size });
  }

  const stringSamples: string[] = [];
  const strings = streams.find((stream) => stream.name === "#Strings");
  if (strings) {
    const start = metadataOffset + strings.offset;
    const end = Math.min(start + strings.size, buf.length);
    let current = "";
    for (let i = start; i < end; i++) {
      const b = buf[i]!;
      if (b === 0) {
        if (current && stringSamples.length < 30) stringSamples.push(current);
        current = "";
      } else {
        current += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
      }
    }
  }

  return { runtimeVersion: pe.machineName, metadataVersion, streams, stringSamples };
}
