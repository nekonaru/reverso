#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeFile, MAX_INPUT_BYTES } from "./core/analyze.js";
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
import { startStdioServer, TOOL_DEFINITIONS } from "./mcp/server.js";
import { VERSION } from "./version.js";
import { scanDirectory, scanReportToMarkdown } from "./inspect/scan.js";
import { diffBuffers, diffReportToMarkdown } from "./inspect/diff.js";
import { findPattern, hexDump } from "./inspect/bytes.js";
import { parseWasm } from "./inspect/wasm.js";
import { parseDex } from "./inspect/dex.js";
import { parsePcap } from "./inspect/pcap.js";
import { decodeJwt } from "./inspect/jwt.js";
import { DEFAULT_RULES } from "./rules/defaults.js";
import { parseRulePack, matchRules } from "./rules/engine.js";
import { fuzzyHash, fuzzySimilarity } from "./inspect/fuzzy.js";
import { createBaseline, verifyBaseline, baselineDiffToMarkdown } from "./inspect/baseline.js";
import { createCase, addEvidence, caseToMarkdown, type Case } from "./inspect/case.js";
import { toSarif, toHtml, scanToCsv } from "./inspect/exports.js";
import { parsePdf } from "./inspect/pdf.js";
import { parsePyInstaller } from "./inspect/pyinstaller.js";
import { parseLnk } from "./inspect/lnk.js";
import { parseEvm } from "./inspect/evm.js";
import { parseDotNet } from "./inspect/dotnet.js";
import { parseOoxml } from "./node/ooxml.js";
import { clusterScan, clusterToMarkdown } from "./inspect/cluster.js";
import { loadConfig } from "./config.js";
import { redactReport } from "./inspect/redact.js";

export { VERSION };

const ANALYZERS = ["analyze", "layout", "hardening", "strings", "entropy", "format", "archive", "js", "scan", "diff", "find-bytes", "wasm", "dex", "pcap", "jwt", "match", "rules", "fuzzy", "baseline", "case", "cluster", "risk", "pdf", "pyinstaller", "lnk", "evm", "dotnet", "ooxml", "hex"] as const;
const COMMANDS = [...ANALYZERS, "site", "mcp", "doctor", "capabilities", "help", "version"] as const;

const USAGE = `reverso ${VERSION}
Native-first reverse engineering toolkit.

Usage:
  reverso <command> [arguments] [options]

Commands:
  scan <dir>          Recursively triage every file in a directory
  diff <a> <b>        Structural diff of two files
  find-bytes <f> <hex> Search a file for a hex byte pattern (?? wildcard)
  hex <file>          Hex dump of a file region (--offset, --length, --width)
  wasm <file>         Inspect a WebAssembly module
  dex <file>          Inspect an Android DEX file
  pcap <file>         Inspect a classic PCAP capture (protocol stats)
  jwt <token|file>    Decode a JWT (header, payload, expiry; signature NOT verified)
  match <file>        Apply the built-in rule pack (or --rules <file>) to a file
  rules list          List the built-in rules
  fuzzy <file>        Fuzzy hash a file (--compare <file> for similarity)
  baseline <action>   create|verify a directory baseline (integrity check)
  case <action>       create|add|report an investigation case
  cluster <dir>       Group files by shared fingerprints
  risk <file>         Explainable 0-100 risk score for a file
  completion <shell>  Generate shell completion (bash, zsh, powershell)
  explain <field>     Explain a report field
  watch <dir>         Watch a directory and report baseline changes
  pdf <file>          Static PDF structure and embedded content inventory
  pyinstaller <file>  PyInstaller CArchive cookie and table of contents
  lnk <file>          Windows shortcut target, arguments and timestamps
  evm <hex|file>      EVM bytecode disassembler and PUSH4 candidates
  dotnet <file>       DotNet metadata streams and strings
  ooxml <file>        DOCX/XLSX/PPTX structure, external links and text
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
  --format <json|md|sarif|html>  Output format (default: json)
  --out <file>        Write the report to a file instead of stdout
  --redact            Mask secret-looking values before output

Options (scan):
  --format <json|md|csv>  Output format (default: json)
  --cache <file>      Cache file hashes and reuse unchanged results

Options (baseline):
  --out <file>        Where to write a new baseline
  --baseline <file>   Baseline file for verification
  --format <json|md>  Verification output format (default: json)

Options (case):
  --out <file>        Where to write a new case
  --notes <text>      Notes attached to the added evidence

Options (watch):
  --interval <seconds>  Poll interval (default: 5)

Options (strings):
  --min-length <n>    Minimum string length (default: 4)

Options (scan):
  --max-files <n>     Stop after n analyzed files (default: 200, max 1000)

Options (find-bytes):
  --max-results <n>   Maximum offsets returned (default: 32)

Options (hex):
  --offset <n>        Byte offset to start from (default: 0)
  --length <n>        Bytes to dump (default: 256, max 65536)
  --width <n>         Bytes per line (default: 16, max 32)

Options (match):
  --rules <file>      Use a custom rule pack (JSON array or {rules: [...]})
  --format <json|md>  Output format (default: json)

Options (fuzzy):
  --compare <file>    Compare against another file and report similarity

Options (jwt):
  --file <path>       Read the token from a file instead of the argument

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

/** Accepts --flag, --flag=true/false/1/0/yes/no as boolean values. */
function booleanFlag(flags: Map<string, string | true>, name: string): boolean {
  const value = flags.get(name);
  if (value === true || value === undefined) return value === true;
  const normalized = value.trim().toLowerCase();
  return normalized === "true" || normalized === "1" || normalized === "yes" || normalized === "on";
}

function flagNumber(flags: Map<string, string | true>, name: string, fallback: number, min?: number, max?: number): number {
  const value = flagString(flags, name);
  if (value === undefined || value === "") return clamp(fallback, min, max);
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`Invalid number for --${name}: ${value}`);
  return clamp(parsed, min, max);
}

function clamp(value: number, min?: number, max?: number): number {
  let out = value;
  if (min !== undefined && out < min) out = min;
  if (max !== undefined && out > max) out = max;
  return out;
}

function printJson(value: unknown): void {
  process.stdout.write(JSON.stringify(value, (_key, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
}

async function readCapped(file: string): Promise<Uint8Array> {
  const buf = await readFile(file);
  if (buf.length > MAX_INPUT_BYTES) throw new Error(`File too large: ${file}`);
  return buf;
}

export async function run(argv: string[]): Promise<number> {
  const { positional, flags } = parseArgs(argv);
  const config = await loadConfig();
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
        const shared = flags.get("redact") === true ? reports.map(redactReport) : reports;
        const payload = shared.length === 1 ? shared[0]! : shared;
        const rendered = format === "md" || format === "markdown"
          ? shared.map(reportToMarkdown).join("\n\n---\n\n")
          : format === "sarif"
            ? JSON.stringify({ $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: shared.map((report) => (toSarif(report) as { runs: unknown[] }).runs[0]) }, null, 2)
            : format === "html"
              ? shared.map(toHtml).join("\n")
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
        try {
          if (format === "elf32" || format === "elf64") printJson({ format, elf: parseElf(buf) });
          else if (format === "pe") printJson({ format, pe: parsePe(buf) });
          else if (format.startsWith("macho")) printJson({ format, macho: parseMachO(buf) });
          else {
            process.stderr.write(`Unsupported format for layout: ${format}\n`);
            return 3;
          }
        } catch (error) {
          process.stderr.write(`Could not parse ${format} binary: ${(error as Error).message}\n`);
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
        const minLength = flagNumber(flags, "min-length", config.strings?.minLength ?? 4, 2, 64);
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

      case "scan": {
        const target = positional[1];
        if (!target) throw new UsageError("scan requires a directory");
        const report = await scanDirectory(
          target,
          flagNumber(flags, "max-files", config.scan?.maxFiles ?? 200, 1, 1000),
          flagString(flags, "cache"),
        );
        const format = flagString(flags, "format", "json");
        const rendered = format === "md" || format === "markdown"
          ? scanReportToMarkdown(report)
          : format === "csv"
            ? scanToCsv(report)
            : JSON.stringify(report, null, 2);
        const out = flagString(flags, "out");
        if (out) {
          await writeFile(out, rendered);
          process.stdout.write(`Report written to ${out}\n`);
        } else {
          process.stdout.write(rendered + "\n");
        }
        return report.errors.length > 0 && report.filesScanned === 0 ? 1 : 0;
      }

      case "diff": {
        const a = positional[1];
        const b = positional[2];
        if (!a || !b) throw new UsageError("diff requires two files");
        const [bufA, bufB] = await Promise.all([readCapped(a), readCapped(b)]);
        const report = diffBuffers(bufA, bufB, a, b);
        const format = flagString(flags, "format", "json");
        const out = flagString(flags, "out");
        const rendered = format === "md" || format === "markdown" ? diffReportToMarkdown(report) : JSON.stringify(report, null, 2);
        if (out) {
          await writeFile(out, rendered);
          process.stdout.write(`Report written to ${out}\n`);
        } else {
          process.stdout.write(rendered + "\n");
        }
        return 0;
      }

      case "find-bytes": {
        const file = positional[1];
        const pattern = positional[2];
        if (!file || !pattern) throw new UsageError("find-bytes requires a file and a hex pattern");
        printJson(findPattern(await readCapped(file), pattern, flagNumber(flags, "max-results", 32, 1, 1000)));
        return 0;
      }

      case "hex": {
        const file = positional[1];
        if (!file) throw new UsageError("hex requires a file");
        const buf = await readCapped(file);
        const offset = flagNumber(flags, "offset", 0, 0);
        const length = flagNumber(flags, "length", 256, 1, 65536);
        const width = flagNumber(flags, "width", 16, 1, 32);
        process.stdout.write(hexDump(buf, offset, length, width) + "\n");
        return 0;
      }

      case "match": {
        const file = positional[1];
        if (!file) throw new UsageError("match requires a file");
        const rulesPath = flagString(flags, "rules");
        const rules = rulesPath ? parseRulePack(JSON.parse(await readFile(rulesPath, "utf8"))) : DEFAULT_RULES;
        const matches = matchRules(rules, await readCapped(file));
        const format = flagString(flags, "format", "json");
        const body = format === "md" || format === "markdown"
          ? `# Rule matches: ${file}\n\n` + matches.map((match) => `- **${match.name}** (${match.severity}): ${match.matched ? "matched" : "no match"}${match.error ? ` - ${match.error}` : ""}`).join("\n") + "\n"
          : JSON.stringify({ file, matches, matched: matches.filter((match) => match.matched).map((match) => match.id) }, null, 2);
        process.stdout.write(body + "\n");
        return 0;
      }

      case "rules": {
        if (positional[1] !== "list") throw new UsageError("usage: reverso rules list");
        printJson(DEFAULT_RULES.map((rule) => ({ id: rule.id, name: rule.name, severity: rule.severity, tags: rule.tags ?? [], condition: rule.condition })));
        return 0;
      }

      case "fuzzy": {
        const file = positional[1];
        if (!file) throw new UsageError("fuzzy requires a file");
        const left = fuzzyHash(await readCapped(file));
        const compare = flagString(flags, "compare");
        const right = compare ? fuzzyHash(await readCapped(compare)) : null;
        printJson({
          file,
          hash: left.hash,
          ...(compare ? { compare, otherHash: right!.hash, similarity: fuzzySimilarity(left.hash, right!.hash) } : {}),
        });
        return 0;
      }

      case "baseline": {
        const action = positional[1];
        const target = positional[2];
        if (!target) throw new UsageError("baseline requires create|verify and a directory");
        if (action === "create") {
          const out = flagString(flags, "out");
          if (!out) throw new UsageError("baseline create requires --out <file>");
          const scan = await scanDirectory(target, flagNumber(flags, "max-files", config.scan?.maxFiles ?? 200, 1, 1000));
          const baseline = createBaseline(target, scan.entries);
          await writeFile(out, JSON.stringify(baseline, null, 2));
          process.stdout.write(`Baseline written to ${out} (${scan.entries.length} files)\n`);
          return 0;
        }
        if (action === "verify") {
          const baselinePath = flagString(flags, "baseline");
          if (!baselinePath) throw new UsageError("baseline verify requires --baseline <file>");
          const baseline = JSON.parse(await readFile(baselinePath, "utf8")) as Parameters<typeof verifyBaseline>[0];
          const scan = await scanDirectory(target, flagNumber(flags, "max-files", config.scan?.maxFiles ?? 200, 1, 1000));
          const diff = verifyBaseline(baseline, scan.entries);
          const format = flagString(flags, "format", "json");
          const rendered = format === "md" || format === "markdown" ? baselineDiffToMarkdown(diff) : JSON.stringify(diff, null, 2);
          process.stdout.write(rendered + "\n");
          return diff.added.length + diff.removed.length + diff.changed.length > 0 ? 1 : 0;
        }
        throw new UsageError("usage: reverso baseline create|verify <dir>");
      }

      case "case": {
        const action = positional[1];
        if (action === "create") {
          const name = positional[2];
          if (!name) throw new UsageError("case create requires a name");
          const out = flagString(flags, "out", "case.json")!;
          const current = createCase(name);
          await writeFile(out, JSON.stringify(current, null, 2));
          process.stdout.write(`Case written to ${out}\n`);
          return 0;
        }
        if (action === "add" || action === "report") {
          const casePath = positional[2];
          if (!casePath) throw new UsageError("case add/report requires a case file");
          let current = JSON.parse(await readFile(casePath, "utf8")) as Case;
          if (action === "add") {
            const target = positional[3];
            if (!target) throw new UsageError("case add requires a target file");
            current = await addEvidence(current, target, flagString(flags, "notes"));
            await writeFile(casePath, JSON.stringify(current, null, 2));
            process.stdout.write(`Evidence added: ${target}\n`);
            return 0;
          }
          const format = flagString(flags, "format", "json");
          process.stdout.write((format === "md" || format === "markdown" ? caseToMarkdown(current) : JSON.stringify(current, null, 2)) + "\n");
          return 0;
        }
        throw new UsageError("usage: reverso case create|add|report ...");
      }

      case "cluster": {
        const target = positional[1];
        if (!target) throw new UsageError("cluster requires a directory");
        const scan = await scanDirectory(target, flagNumber(flags, "max-files", config.scan?.maxFiles ?? 200, 1, 1000));
        const clusters = clusterScan(scan);
        const format = flagString(flags, "format", config.format ?? "json");
        const rendered = format === "md" || format === "markdown" ? clusterToMarkdown(clusters) : JSON.stringify({ root: target, clusters }, null, 2);
        process.stdout.write(rendered + "\n");
        return 0;
      }

      case "risk": {
        const file = positional[1];
        if (!file) throw new UsageError("risk requires a file");
        const { analyzeBuffer } = await import("./core/analyze-buffer.js");
        const { readFile: readFileAsync } = await import("node:fs/promises");
        const report = analyzeBuffer(await readFileAsync(file), file);
        printJson({ file, ...report.risk });
        return 0;
      }

      case "completion": {
        const shell = positional[1];
        if (!shell) throw new UsageError("completion requires bash, zsh or powershell");
        const names = COMMANDS.join(" ");
        if (shell === "bash") {
          process.stdout.write(`_reverso() { COMPREPLY=( $(compgen -W "${names}" -- "\${COMP_WORDS[COMP_CWORD]}") ); }\ncomplete -F _reverso reverso\n`);
        } else if (shell === "zsh") {
          process.stdout.write(`#compdef reverso\n_arguments '1:command:(${names})'\n`);
        } else if (shell === "powershell") {
          process.stdout.write(`Register-ArgumentCompleter -Native -CommandName reverso -ScriptBlock { param($wordToComplete) @(${COMMANDS.map((name) => `'${name}'`).join(", ")}) | Where-Object { $_ -like "$wordToComplete*" } }\n`);
        } else {
          throw new UsageError("unsupported shell: use bash, zsh or powershell");
        }
        return 0;
      }

      case "explain": {
        const field = positional[1];
        if (!field) throw new UsageError("explain requires a field name");
        const explanations: Record<string, string> = {
          sha256: "Full-file SHA-256 fingerprint used for exact identity and baselines.",
          entropy: "Shannon entropy in bits per byte. Values above 7.5 suggest packed or encrypted content.",
          imphash: "MD5 of lowercased dll.function imports in order. Groups related Windows builds.",
          richHash: "Fingerprint of decoded Rich header compiler entries. Groups builds by toolchain.",
          buildId: "GNU build-id from ELF notes. Stable per Linux build.",
          uuid: "Mach-O LC_UUID, a per-build identifier.",
          pdbPath: "Debug PDB path from the PE CodeView entry, often revealing build directories.",
          needed: "Shared libraries required by an ELF binary (DT_NEEDED).",
          hardening: "Binary protection checks such as PIE, NX, canary, RELRO, ASLR and CFG.",
          risk: "Explainable 0 to 100 score derived from hardening, packer, entropy and secret findings.",
          schemaVersion: "Version marker for the report JSON shape. Consumers can ignore unknown fields.",
        };
        process.stdout.write(explanations[field] ?? `No explanation available for ${field}. See README.md and docs/online.md.\n`);
        return 0;
      }

      case "watch": {
        const target = positional[1];
        if (!target) throw new UsageError("watch requires a directory");
        const interval = Math.max(1, flagNumber(flags, "interval", 5, 1, 3600)) * 1000;
        const initial = await scanDirectory(target, config.scan?.maxFiles ?? 200);
        let baseline = createBaseline(target, initial.entries);
        process.stdout.write(`Watching ${target} every ${interval / 1000}s. Press Ctrl+C to stop.\n`);
        const timer = setInterval(() => {
          void scanDirectory(target, config.scan?.maxFiles ?? 200)
            .then((scan) => {
              const diff = verifyBaseline(baseline, scan.entries);
              if (diff.added.length + diff.removed.length + diff.changed.length > 0) {
                process.stdout.write(JSON.stringify({ time: new Date().toISOString(), ...diff }) + "\n");
                baseline = createBaseline(target, scan.entries);
              }
            })
            .catch((error) => process.stderr.write(`Watch error: ${(error as Error).message}\n`));
        }, interval);
        await new Promise<void>((resolvePromise) => {
          process.once("SIGINT", () => { clearInterval(timer); resolvePromise(); });
        });
        return 0;
      }

      case "pdf": {
        const file = positional[1];
        if (!file) throw new UsageError("pdf requires a file");
        printJson(parsePdf(await readCapped(file)));
        return 0;
      }

      case "pyinstaller": {
        const file = positional[1];
        if (!file) throw new UsageError("pyinstaller requires a file");
        try {
          printJson(parsePyInstaller(await readCapped(file)));
        } catch (error) {
          process.stderr.write(`Not a PyInstaller archive: ${(error as Error).message}\n`);
          return 3;
        }
        return 0;
      }

      case "lnk": {
        const file = positional[1];
        if (!file) throw new UsageError("lnk requires a file");
        try {
          printJson(parseLnk(await readCapped(file)));
        } catch (error) {
          process.stderr.write(`Not a shortcut: ${(error as Error).message}\n`);
          return 3;
        }
        return 0;
      }

      case "evm": {
        const input = positional[1];
        if (!input) throw new UsageError("evm requires a hex string or a file path");
        const looksHex = /^0x[0-9a-f]*$/i.test(input) || /^[0-9a-f]+$/i.test(input);
        try {
          printJson(parseEvm(looksHex ? input : (await readCapped(input)).toString()));
        } catch (error) {
          process.stderr.write(`Not EVM bytecode: ${(error as Error).message}\n`);
          return 3;
        }
        return 0;
      }

      case "dotnet": {
        const file = positional[1];
        if (!file) throw new UsageError("dotnet requires a file");
        try {
          printJson(parseDotNet(await readCapped(file)));
        } catch (error) {
          process.stderr.write(`Not a .NET assembly: ${(error as Error).message}\n`);
          return 3;
        }
        return 0;
      }

      case "ooxml": {
        const file = positional[1];
        if (!file) throw new UsageError("ooxml requires a file");
        try {
          printJson(parseOoxml(await readCapped(file)));
        } catch (error) {
          process.stderr.write(`Not an OOXML file: ${(error as Error).message}\n`);
          return 3;
        }
        return 0;
      }

      case "pcap": {
        const file = positional[1];
        if (!file) throw new UsageError("pcap requires a file");
        try {
          printJson(parsePcap(await readCapped(file)));
        } catch (error) {
          process.stderr.write(`Not a PCAP file: ${(error as Error).message}\n`);
          return 3;
        }
        return 0;
      }

      case "jwt": {
        const target = positional[1];
        const file = flagString(flags, "file");
        let token = target ?? "";
        if (file) token = (await readCapped(file)).toString();
        if (!token) throw new UsageError("jwt requires an inline token or --file <path>");
        try {
          printJson(decodeJwt(token));
        } catch (error) {
          process.stderr.write(`Not a JWT: ${(error as Error).message}\n`);
          return 3;
        }
        return 0;
      }

      case "wasm": {
        const file = positional[1];
        if (!file) throw new UsageError("wasm requires a file");
        try {
          printJson(parseWasm(await readCapped(file)));
        } catch (error) {
          process.stderr.write(`Not a WebAssembly module: ${(error as Error).message}\n`);
          return 3;
        }
        return 0;
      }

      case "dex": {
        const file = positional[1];
        if (!file) throw new UsageError("dex requires a file");
        try {
          printJson(parseDex(await readCapped(file)));
        } catch (error) {
          process.stderr.write(`Not a DEX file: ${(error as Error).message}\n`);
          return 3;
        }
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
          maxPages: flagNumber(flags, "max-pages", 100, 1, 10000),
          maxDepth: flagNumber(flags, "max-depth", 5, 0, 32),
          allowPrivate: booleanFlag(flags, "allow-private"),
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
          analyzers: [...ANALYZERS],
          commands: [...COMMANDS],
          mcpTools: TOOL_DEFINITIONS.map((tool) => tool.name),
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

// Run when executed directly (not imported by tests). Symlink-aware so npm bin shims work.
function safeReal(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

const invokedAsScript = process.argv[1] !== undefined
  && safeReal(fileURLToPath(import.meta.url)) === safeReal(process.argv[1]);
if (invokedAsScript) {
  run(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      process.stderr.write(`Fatal: ${(error as Error).message}\n`);
      process.exit(1);
    },
  );
}
