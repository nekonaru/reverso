#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { analyzeFile } from "./core/analyze.js";
import { reportToMarkdown } from "./core/report.js";
import { detectFormat } from "./core/format.js";
import { shannonEntropy, highEntropyWindows, round3 } from "./core/entropy.js";
import { extractStrings, summarizeCategories } from "./core/strings.js";
import { parseElf } from "./binary/elf.js";
import { parsePe } from "./binary/pe.js";
import { parseMachO } from "./binary/macho.js";
import { hardeningReport } from "./binary/hardening.js";
import { listArchive } from "./archive/zip.js";
import { analyzeJavaScript } from "./js/jsanal.js";
import { mirrorSite } from "./web/mirror.js";
import { runDoctor } from "./doctor.js";
import { startStdioServer } from "./mcp/server.js";

export const VERSION = "1.0.0";

const USAGE = `reverso ${VERSION}
Native-first reverse engineering toolkit.

Usage:
  reverso <command> [arguments] [options]

Commands:
  analyze <file...>   Full static analysis report
  layout <file>       ELF/PE/Mach-O structure (sections, imports, exports)
  hardening <file>    Hardening checks (PIE, NX, ASLR, RELRO, CFG, ...)
  strings <file>      Printable strings with categories
  entropy <file>      Shannon entropy and high-entropy regions
  format <file>       Magic-byte format detection
  archive <file>      ZIP/APK/IPA/JAR entry listing
  js <file>           JavaScript bundle analysis
  site <url>          Mirror a website locally (same origin)
  mcp                 Start the MCP stdio server
  capabilities        List all analyzers and MCP tools
  doctor              Check the runtime environment
  help                Show this help
  version             Show the version

Options (analyze):
  --format <json|md>  Output format (default: json)
  --out <file>        Write the report to a file instead of stdout

Options (strings):
  --min-length <n>    Minimum string length (default: 4)

Options (site):
  --out <dir>         Output directory (default: ./reverso-site)
  --max-pages <n>     Maximum pages/assets to save (default: 100)
  --max-depth <n>     Maximum link depth (default: 5)
  --allow-private     Allow loopback/private addresses (off by default)

Exit codes:
  0 success, 1 error, 2 usage error, 3 unsupported format
`;

interface ParsedArgs {
  positional: string[];
  flags: Map<string, string | true>;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      if (eq !== -1) {
        flags.set(arg.slice(2, eq), arg.slice(eq + 1));
        continue;
      }
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(arg.slice(2), next);
        i++;
      } else {
        flags.set(arg.slice(2), true);
      }
      continue;
    }
    positional.push(arg);
  }
  return { positional, flags };
}

function flagString(flags: Map<string, string | true>, name: string, fallback?: string): string | undefined {
  const value = flags.get(name);
  if (value === true) return fallback ?? "";
  return value ?? fallback;
}

function flagNumber(flags: Map<string, string | true>, name: string, fallback: number): number {
  const value = flagString(flags, name);
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`Invalid number for --${name}: ${value}`);
  return parsed;
}

function printJson(value: unknown): void {
  process.stdout.write(JSON.stringify(value, (_key, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
}

async function readCapped(file: string): Promise<Uint8Array> {
  const buf = await readFile(file);
  if (buf.length > 256 * 1024 * 1024) throw new Error(`File too large: ${file}`);
  return buf;
}

export async function run(argv: string[]): Promise<number> {
  const { positional, flags } = parseArgs(argv);
  const command = positional[0];

  try {
    switch (command) {
      case undefined:
      case "help":
      case "--help":
      case "-h":
        process.stdout.write(USAGE);
        return 0;

      case "version":
      case "--version":
      case "-v":
        process.stdout.write(`${VERSION}\n`);
        return 0;

      case "analyze": {
        const files = positional.slice(1);
        if (files.length === 0) throw new UsageError("analyze requires at least one file");
        const format = flagString(flags, "format", "json");
        const out = flagString(flags, "out");
        const reports = [];
        for (const file of files) reports.push(await analyzeFile(file));
        const payload = reports.length === 1 ? reports[0]! : reports;
        const rendered = format === "md" || format === "markdown"
          ? reports.map(reportToMarkdown).join("\n\n---\n\n")
          : JSON.stringify(payload, (_key, v) => (typeof v === "bigint" ? v.toString() : v), 2);
        if (out) {
          await writeFile(out, rendered);
          process.stdout.write(`Report written to ${out}\n`);
        } else {
          process.stdout.write(rendered + "\n");
        }
        return 0;
      }

      case "layout": {
        const file = positional[1];
        if (!file) throw new UsageError("layout requires a file");
        const buf = await readCapped(file);
        const format = detectFormat(buf).format;
        if (format === "elf32" || format === "elf64") printJson({ format, elf: parseElf(buf) });
        else if (format === "pe") printJson({ format, pe: parsePe(buf) });
        else if (format.startsWith("macho")) printJson({ format, macho: parseMachO(buf) });
        else {
          process.stderr.write(`Unsupported format for layout: ${format}\n`);
          return 3;
        }
        return 0;
      }

      case "hardening": {
        const file = positional[1];
        if (!file) throw new UsageError("hardening requires a file");
        const buf = await readCapped(file);
        printJson(hardeningReport(buf, detectFormat(buf).format));
        return 0;
      }

      case "strings": {
        const file = positional[1];
        if (!file) throw new UsageError("strings requires a file");
        const minLength = flagNumber(flags, "min-length", 4);
        const buf = await readCapped(file);
        const strings = extractStrings(buf, { minLength });
        printJson({ total: strings.length, categories: summarizeCategories(strings), strings });
        return 0;
      }

      case "entropy": {
        const file = positional[1];
        if (!file) throw new UsageError("entropy requires a file");
        const buf = await readCapped(file);
        printJson({ file, sizeBytes: buf.length, entropy: round3(shannonEntropy(buf)), highEntropyRegions: highEntropyWindows(buf) });
        return 0;
      }

      case "format": {
        const file = positional[1];
        if (!file) throw new UsageError("format requires a file");
        const buf = await readCapped(file);
        printJson(detectFormat(buf));
        return 0;
      }

      case "archive": {
        const file = positional[1];
        if (!file) throw new UsageError("archive requires a file");
        const buf = await readCapped(file);
        const listing = listArchive(buf);
        if (!listing) {
          process.stderr.write("Not a readable ZIP archive\n");
          return 3;
        }
        printJson(listing);
        return 0;
      }

      case "js": {
        const file = positional[1];
        if (!file) throw new UsageError("js requires a file");
        const buf = await readCapped(file);
        printJson(analyzeJavaScript(Buffer.from(buf).toString("utf8")));
        return 0;
      }

      case "site": {
        const url = positional[1];
        if (!url) throw new UsageError("site requires a URL");
        const outDir = flagString(flags, "out", "reverso-site")!;
        const report = await mirrorSite(url, {
          outDir,
          maxPages: flagNumber(flags, "max-pages", 100),
          maxDepth: flagNumber(flags, "max-depth", 5),
          allowPrivate: flags.get("allow-private") === true,
        });
        printJson({
          startUrl: report.startUrl,
          outDir: report.outDir,
          pagesSaved: report.pages.length,
          totalBytes: report.totalBytes,
          skipped: report.skipped.length,
          errors: report.errors.length,
          reportFile: `${outDir}/reverso-mirror-report.json`,
        });
        return report.errors.length > 0 && report.pages.length === 0 ? 1 : 0;
      }

      case "mcp":
        await startStdioServer();
        return 0;

      case "capabilities":
        printJson({
          analyzers: ["analyze", "layout", "hardening", "strings", "entropy", "format", "archive", "js"],
          commands: ["analyze", "layout", "hardening", "strings", "entropy", "format", "archive", "js", "site", "mcp", "doctor"],
          mcpTools: [
            "reverso_analyze",
            "reverso_strings",
            "reverso_entropy",
            "reverso_format",
            "reverso_layout",
            "reverso_hardening",
            "reverso_archive_list",
            "reverso_js_analyze",
          ],
          formats: ["elf32", "elf64", "pe", "macho32", "macho64", "macho-fat", "zip", "apk", "ipa", "jar", "wasm", "dex", "pcap"],
        });
        return 0;

      case "doctor": {
        const report = await runDoctor();
        printJson(report);
        return report.healthy ? 0 : 1;
      }

      default:
        process.stderr.write(`Unknown command: ${command}\n\n${USAGE}`);
        return 2;
    }
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`Usage error: ${error.message}\n\n${USAGE}`);
      return 2;
    }
    process.stderr.write(`Error: ${(error as Error).message}\n`);
    return 1;
  }
}

class UsageError extends Error {}

// Run when executed directly (not imported by tests).
const invokedAsScript = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/").split("/").slice(-2).join("/"));
if (invokedAsScript || process.argv[1]?.endsWith("cli.js") || process.argv[1]?.endsWith("cli.ts")) {
  run(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      process.stderr.write(`Fatal: ${(error as Error).message}\n`);
      process.exit(1);
    },
  );
}
