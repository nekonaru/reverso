/** OOXML (docx/xlsx/pptx) inspector. Node-only: uses zlib for deflated ZIP entries. */
import { inflateRawSync } from "node:zlib";
import { listArchive } from "../archive/zip.js";

export interface OoxmlInfo {
  kind: "docx" | "xlsx" | "pptx" | "unknown";
  entries: number;
  hasVba: boolean;
  externalTargets: string[];
  strings: string[];
}

const MAX_ENTRY_BYTES = 8 * 1024 * 1024;

export function parseOoxml(buf: Uint8Array): OoxmlInfo {
  const listing = listArchive(buf);
  if (!listing) throw new Error("Not an OOXML file: ZIP central directory not found");
  const names = new Set(listing.entries.map((entry) => entry.name));
  const kind = names.has("word/document.xml") ? "docx"
    : names.has("xl/workbook.xml") ? "xlsx"
      : names.has("ppt/presentation.xml") ? "pptx" : "unknown";

  const hasVba = [...names].some((name) => name.toLowerCase().endsWith("vbaproject.bin"));
  const targets: string[] = [];
  const strings: string[] = [];

  const targetsToRead = [
    ...[...names].filter((name) => name.endsWith(".rels")),
    ...[...names].filter((name) => /document\.xml$|workbook\.xml$|presentation\.xml$|core\.xml$/.test(name)),
  ].slice(0, 20);

  for (const name of targetsToRead) {
    const entry = readZipEntry(buf, name);
    if (!entry) continue;
    const xml = new TextDecoder("utf8").decode(entry);
    for (const match of xml.matchAll(/Target="([^"]+)"[^>]*TargetMode="External"/g)) {
      if (targets.length < 50) targets.push(match[1]!);
    }
    for (const match of xml.matchAll(/TargetMode="External"[^>]*Target="([^"]+)"/g)) {
      if (targets.length < 50) targets.push(match[1]!);
    }
    const text = xml.replace(/<[^>]*>/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/\s+/g, " ").trim();
    if (text && strings.length < 100) strings.push(text.slice(0, 512));
  }

  return { kind, entries: listing.totalEntries, hasVba, externalTargets: [...new Set(targets)], strings };
}

/** Extracts one ZIP entry by name, supporting stored and deflated entries. */
export function readZipEntry(buf: Uint8Array, name: string): Uint8Array | null {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (offset: number) => dv.getUint16(offset, true) >>> 0;
  const u32 = (offset: number) => dv.getUint32(offset, true) >>> 0;

  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65558); i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) return null;
  let pos = u32(eocd + 16);
  const count = u16(eocd + 10);

  for (let i = 0; i < count; i++) {
    if (pos + 46 > buf.length || u32(pos) !== 0x02014b50) return null;
    const method = u16(pos + 10);
    const compressedSize = u32(pos + 20);
    const nameLength = u16(pos + 28);
    const extraLength = u16(pos + 30);
    const commentLength = u16(pos + 32);
    const localOffset = u32(pos + 42);
    const entryName = new TextDecoder("utf8").decode(buf.subarray(pos + 46, pos + 46 + nameLength));
    pos += 46 + nameLength + extraLength + commentLength;
    if (entryName !== name || compressedSize > MAX_ENTRY_BYTES) continue;
    if (localOffset + 30 > buf.length || u32(localOffset) !== 0x04034b50) return null;
    const dataStart = localOffset + 30 + u16(localOffset + 26) + u16(localOffset + 28);
    const compressed = buf.subarray(dataStart, dataStart + compressedSize);
    if (method === 0) return compressed;
    if (method === 8) return new Uint8Array(inflateRawSync(compressed));
    return null;
  }
  return null;
}
