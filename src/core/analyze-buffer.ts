/** Platform-neutral analysis engine. No filesystem or network dependencies. */
import { hashBuffer } from "./hashes.js";
import { shannonEntropy, highEntropyWindows, round3 } from "./entropy.js";
import { extractStrings, summarizeCategories, type ExtractedString } from "./strings.js";
import { detectFormat, type FormatDetection } from "./format.js";
import { parseElf, type ElfInfo } from "../binary/elf.js";
import { parsePe, type PeInfo } from "../binary/pe.js";
import { parseMachO, type MachOInfo } from "../binary/macho.js";
import { hardeningReport, type HardeningReport } from "../binary/hardening.js";
import { listArchive, type ArchiveListing } from "../archive/zip.js";
import { analyzeJavaScript, type JsAnalysis } from "../js/jsanal.js";
import { assessRisk, type RiskAssessment } from "../inspect/risk.js";

export const MAX_INPUT_BYTES = 256 * 1024 * 1024;

export interface AnalysisReport {
  schemaVersion: "2.0";
  file: string;
  sizeBytes: number;
  hashes: { md5: string; sha1: string; sha256: string };
  entropy: number;
  entropyInterpretation: string;
  highEntropyRegions: Array<{ offset: number; size: number; entropy: number }>;
  format: FormatDetection;
  hardening: HardeningReport | null;
  layout: { elf?: ElfInfo; pe?: PeInfo; macho?: MachOInfo } | null;
  strings: {
    total: number;
    categories: ReturnType<typeof summarizeCategories>;
  };
  archive: ArchiveListing | null;
  javascript: JsAnalysis | null;
  packerSignals: string[];
  risk: RiskAssessment;
}

const utf8Decoder = new TextDecoder("utf8");

export function analyzeBuffer(buf: Uint8Array, label: string): AnalysisReport {
  const hashes = hashBuffer(buf);
  const entropy = round3(shannonEntropy(buf));
  const format = detectFormat(buf);
  const highEntropyRegions = highEntropyWindows(buf);

  const layout: AnalysisReport["layout"] = {};
  let layoutSet = false;
  try {
    if (format.format === "elf32" || format.format === "elf64") {
      layout.elf = parseElf(buf);
      layoutSet = true;
    } else if (format.format === "pe") {
      layout.pe = parsePe(buf);
      layoutSet = true;
    } else if (format.format === "macho32" || format.format === "macho64" || format.format === "macho-fat") {
      layout.macho = parseMachO(buf);
      layoutSet = true;
    }
  } catch {
    // Layout parsing failed; the format detection result still stands.
  }

  const hardening = format.format.startsWith("elf") || format.format === "pe" || format.format.startsWith("macho")
    ? hardeningReport(buf, format.format)
    : null;

  let archive: ArchiveListing | null = null;
  if (format.format === "zip") {
    try {
      archive = listArchive(buf);
    } catch {
      archive = null; // Malformed archive; the rest of the report still stands.
    }
  }

  const javascript = maybeAnalyzeJavaScript(buf, label);
  const strings = analyzeStrings(buf);
  const packerSignals = detectPackers(buf, format.format, strings.all, highEntropyRegions.length);

  const report: AnalysisReport = {
    schemaVersion: "2.0",
    file: label,
    sizeBytes: buf.length,
    hashes,
    entropy,
    entropyInterpretation: interpretEntropy(entropy),
    highEntropyRegions,
    format,
    hardening,
    layout: layoutSet ? layout : null,
    strings: { total: strings.all.length, categories: summarizeCategories(strings.all) },
    archive,
    javascript,
    packerSignals,
    risk: { score: 0, reasons: [] },
  };
  return { ...report, risk: assessRisk(report) };
}

function analyzeStrings(buf: Uint8Array): { all: ExtractedString[] } {
  if (buf.length > 64 * 1024 * 1024) return { all: [] };
  return { all: extractStrings(buf) };
}

function interpretEntropy(entropy: number): string {
  if (entropy < 1) return "near-zero entropy: mostly repeated bytes";
  if (entropy < 4) return "low entropy: likely structured or padded data";
  if (entropy < 6.5) return "typical entropy: mixed code and data";
  if (entropy < 7.5) return "high entropy: possibly compressed or encrypted content";
  return "very high entropy: likely encrypted or packed content";
}

const PACKER_SIGNATURES: Array<{ name: string; bytes: number[] }> = [
  { name: "UPX", bytes: [0x55, 0x50, 0x58, 0x30] }, // UPX0 / UPX1 / UPX!
];

function detectPackers(
  buf: Uint8Array,
  format: string,
  strings: ExtractedString[],
  highEntropyRegionCount: number,
): string[] {
  const signals: string[] = [];
  const scanRegion = buf.subarray(0, Math.min(buf.length, 8 * 1024 * 1024));
  for (const { name, bytes } of PACKER_SIGNATURES) {
    if (indexOf(scanRegion, bytes) !== -1) signals.push(`${name} signature found`);
  }
  const joined = strings.slice(0, 2000).map((s) => s.value).join("\n");
  if (strings.some((s) => s.value.includes("UPX!"))) signals.push("UPX stub string found");
  if (strings.some((s) => /^\.upx\d?/i.test(s.value))) signals.push("UPX section name found");
  if (highEntropyRegionCount >= 3) signals.push("multiple high-entropy regions (possible packing or encryption)");
  if (/aspack|petite|themida|vmprotect|enigma/i.test(joined)) signals.push("packer or protector name string found");
  void format;
  return [...new Set(signals)];
}

function indexOf(haystack: Uint8Array, needle: number[]): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j]! !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

const JS_EXTENSIONS = new Set([".js", ".mjs", ".cjs"]);
const JS_SNIFF_BYTES = 4096;

function fileExtension(label: string): string {
  const slash = Math.max(label.lastIndexOf("/"), label.lastIndexOf("\\"));
  const base = label.slice(slash + 1);
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? "" : base.slice(dot).toLowerCase();
}

function maybeAnalyzeJavaScript(buf: Uint8Array, label: string): JsAnalysis | null {
  const extension = fileExtension(label);
  if (!JS_EXTENSIONS.has(extension)) {
    const sample = utf8Decoder.decode(buf.subarray(0, JS_SNIFF_BYTES));
    const looksLikeJs = /^\s*(?:\/\*|\/\/|import |export |const |let |var |function |"use strict")/m.test(sample);
    if (!looksLikeJs || buf.length > 32 * 1024 * 1024) return null;
  }
  if (buf.length > 32 * 1024 * 1024) return null;
  return analyzeJavaScript(utf8Decoder.decode(buf));
}
