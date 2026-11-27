/** Browser entry point: the analyzers exposed to the local web UI. */
import { analyzeBuffer } from "../core/analyze-buffer.js";
import { detectFormat } from "../core/format.js";
import { shannonEntropy, highEntropyWindows, round3 } from "../core/entropy.js";
import { extractStrings, summarizeCategories } from "../core/strings.js";
import { hardeningReport } from "../binary/hardening.js";
import { parseElf } from "../binary/elf.js";
import { parsePe } from "../binary/pe.js";
import { parseMachO } from "../binary/macho.js";
import { listArchive } from "../archive/zip.js";
import { analyzeJavaScript } from "../js/jsanal.js";
import { parseWasm } from "../inspect/wasm.js";
import { parseDex } from "../inspect/dex.js";
import { parsePcap } from "../inspect/pcap.js";
import { decodeJwt } from "../inspect/jwt.js";
import { findPattern, hexDump } from "../inspect/bytes.js";
import { diffBuffers } from "../inspect/diff.js";
import { DEFAULT_RULES } from "../rules/defaults.js";
import { parseRulePack, matchRules } from "../rules/engine.js";
import { fuzzyHash, fuzzySimilarity } from "../inspect/fuzzy.js";
import { parsePdf } from "../inspect/pdf.js";
import { parsePyInstaller } from "../inspect/pyinstaller.js";
import { parseLnk } from "../inspect/lnk.js";
import { parseEvm } from "../inspect/evm.js";
import { parseDotNet } from "../inspect/dotnet.js";

const utf8Decoder = new TextDecoder("utf8");

export type BrowserTool =
  | "analyze" | "format" | "entropy" | "strings" | "layout" | "hardening" | "archive"
  | "js" | "wasm" | "dex" | "pcap" | "jwt" | "find-bytes" | "hex" | "diff" | "match" | "fuzzy"
  | "pdf" | "pyinstaller" | "lnk" | "evm" | "dotnet";

export interface BrowserRequest {
  tool: BrowserTool;
  bytes: Uint8Array;
  label: string;
  arg?: string | undefined;
  otherBytes?: Uint8Array | undefined;
  otherLabel?: string | undefined;
}

export function runBrowserTool(request: BrowserRequest): unknown {
  const { bytes, label, arg } = request;
  switch (request.tool) {
    case "analyze": return analyzeBuffer(bytes, label);
    case "format": return detectFormat(bytes);
    case "entropy": return { entropy: round3(shannonEntropy(bytes)), highEntropyRegions: highEntropyWindows(bytes) };
    case "strings": {
      const strings = extractStrings(bytes, { minLength: 4 });
      return { total: strings.length, categories: summarizeCategories(strings), strings };
    }
    case "layout": {
      const format = detectFormat(bytes).format;
      if (format === "elf32" || format === "elf64") return { format, elf: parseElf(bytes) };
      if (format === "pe") return { format, pe: parsePe(bytes) };
      if (format.startsWith("macho")) return { format, macho: parseMachO(bytes) };
      throw new Error(`Unsupported format for layout: ${format}`);
    }
    case "hardening": return hardeningReport(bytes, detectFormat(bytes).format);
    case "archive": {
      const listing = listArchive(bytes);
      if (!listing) throw new Error("Not a readable ZIP archive");
      return listing;
    }
    case "js": return analyzeJavaScript(utf8Decoder.decode(bytes));
    case "wasm": return parseWasm(bytes);
    case "dex": return parseDex(bytes);
    case "pcap": return parsePcap(bytes);
    case "jwt": return decodeJwt(arg ?? utf8Decoder.decode(bytes));
    case "find-bytes": {
      if (!arg) throw new Error("Enter a hex pattern, for example 4d 5a ?? 60");
      return findPattern(bytes, arg, 100);
    }
    case "hex": return { dump: hexDump(bytes, 0, Math.min(bytes.length, 4096), 16) };
    case "diff": {
      if (!request.otherBytes) throw new Error("Choose a second file to compare");
      return diffBuffers(bytes, request.otherBytes, label, request.otherLabel ?? "b");
    }
    case "match": {
      const rules = arg ? parseRulePack(JSON.parse(arg)) : DEFAULT_RULES;
      const matches = matchRules(rules, bytes);
      return { total: matches.length, matched: matches.filter((match) => match.matched).map((match) => match.id), matches };
    }
    case "fuzzy": {
      const left = fuzzyHash(bytes);
      if (!request.otherBytes) return left;
      const right = fuzzyHash(request.otherBytes);
      return { ...left, otherHash: right.hash, similarity: fuzzySimilarity(left.hash, right.hash) };
    }
    case "pdf": return parsePdf(bytes);
    case "pyinstaller": return parsePyInstaller(bytes);
    case "lnk": return parseLnk(bytes);
    case "evm": return parseEvm(arg ?? bytes);
    case "dotnet": return parseDotNet(bytes);
    default:
      throw new Error(`Unknown tool: ${request.tool as string}`);
  }
}
