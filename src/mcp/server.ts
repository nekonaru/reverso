import { createInterface } from "node:readline";
import { readFile, stat } from "node:fs/promises";
import { analyzeBuffer } from "../core/analyze.js";
import { extractStrings, summarizeCategories } from "../core/strings.js";
import { shannonEntropy, highEntropyWindows, round3 } from "../core/entropy.js";
import { detectFormat } from "../core/format.js";
import { hardeningReport } from "../binary/hardening.js";
import { parseElf } from "../binary/elf.js";
import { parsePe } from "../binary/pe.js";
import { parseMachO } from "../binary/macho.js";
import { listArchive } from "../archive/zip.js";
import { analyzeJavaScript } from "../js/jsanal.js";
import { VERSION } from "../version.js";
import { findPattern, hexDump } from "../inspect/bytes.js";
import { scanDirectory } from "../inspect/scan.js";
import { diffBuffers } from "../inspect/diff.js";
import { parseWasm } from "../inspect/wasm.js";
import { parseDex } from "../inspect/dex.js";

import { parsePcap } from "../inspect/pcap.js";
import { decodeJwt } from "../inspect/jwt.js";
import { DEFAULT_RULES } from "../rules/defaults.js";
import { parseRulePack, matchRules } from "../rules/engine.js";
import { fuzzyHash, fuzzySimilarity } from "../inspect/fuzzy.js";
import { parsePdf } from "../inspect/pdf.js";
import { parsePyInstaller } from "../inspect/pyinstaller.js";
import { parseLnk } from "../inspect/lnk.js";
import { parseEvm } from "../inspect/evm.js";
import { parseDotNet } from "../inspect/dotnet.js";
import { parseOoxml } from "../node/ooxml.js";

const MCP_PROTOCOL_VERSION = "2025-06-18";
const MAX_MCP_FILE_BYTES = 64 * 1024 * 1024;

export interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: number | string | null;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

function filePathArg(args: Record<string, unknown>): string {
  const value = args["path"];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Missing required string argument: path");
  }
  return value;
}

async function readCapped(path: string): Promise<Uint8Array> {
  const fileStat = await stat(path);
  if (!fileStat.isFile()) throw new Error(`Not a regular file: ${path}`);
  if (fileStat.size > MAX_MCP_FILE_BYTES) {
    throw new Error(`File too large for MCP analysis (${fileStat.size} bytes, limit ${MAX_MCP_FILE_BYTES})`);
  }
  return readFile(path);
}

/**
 * Reads an analysis input from either a local `path` or inline base64 `content`.
 * Remote MCP transports have no filesystem, so base64 is the universal form.
 */
async function readInput(args: Record<string, unknown>): Promise<Uint8Array> {
  const content = args["content"];
  if (typeof content === "string" && content.length > 0) {
    const buf = Buffer.from(content, "base64");
    if (buf.length > MAX_MCP_FILE_BYTES) {
      throw new Error(`File too large for MCP analysis (${buf.length} bytes, limit ${MAX_MCP_FILE_BYTES})`);
    }
    return new Uint8Array(buf);
  }
  return readCapped(filePathArg(args));
}

async function readNamedInput(args: Record<string, unknown>, name: string): Promise<Uint8Array> {
  const content = args[`content${name.charAt(0).toUpperCase()}${name.slice(1)}`];
  if (typeof content === "string" && content.length > 0) {
    const buf = Buffer.from(content, "base64");
    if (buf.length > MAX_MCP_FILE_BYTES) {
      throw new Error(`File too large for MCP analysis (${buf.length} bytes, limit ${MAX_MCP_FILE_BYTES})`);
    }
    return new Uint8Array(buf);
  }
  const path = args[name];
  if (typeof path !== "string" || !path) throw new Error(`Missing required string argument: ${name}`);
  return readCapped(path);
}

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "reverso_analyze",
    description: "Full static analysis of a file: hashes, entropy, format detection, strings with categories, layout, hardening, archive listing and JavaScript analysis. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Absolute path of the file to analyze" } },
      required: ["path"],
    },
    handler: async (args) => analyzeBuffer(await readInput(args), typeof args["label"] === "string" ? args["label"] : typeof args["path"] === "string" ? args["path"] : "input"),
  },
  {
    name: "reverso_strings",
    description: "Extract printable ASCII and UTF-16LE strings, categorized (url, ipv4, email, jwt, private-key, and more). Returns JSON.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        minLength: { type: "number", minimum: 2, maximum: 64, default: 4 },
      },
      required: ["path"],
    },
    handler: async (args) => {
      const minLength = typeof args["minLength"] === "number" ? args["minLength"] : 4;
      const strings = extractStrings(await readInput(args), { minLength });
      return {
        total: strings.length,
        categories: summarizeCategories(strings),
        strings: strings.slice(0, 500).map(({ offset, encoding, value }) => ({ offset, encoding, value })),
      };
    },
  },
  {
    name: "reverso_entropy",
    description: "Shannon entropy of a file in bits per byte, plus any high-entropy regions (likely packed or encrypted). Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => {
      const buf = await readInput(args);
      return {
        entropy: round3(shannonEntropy(buf)),
        highEntropyRegions: highEntropyWindows(buf),
      };
    },
  },
  {
    name: "reverso_format",
    description: "Detect the format of a file from magic bytes (ELF, PE, Mach-O, ZIP, DEX, WASM, and more). Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => detectFormat(await readInput(args)),
  },
  {
    name: "reverso_layout",
    description: "Structural layout of a binary: sections, program headers, imports and exports for ELF, PE and Mach-O. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => {
      const buf = await readInput(args);
      const format = detectFormat(buf).format;
      if (format === "elf32" || format === "elf64") return { format, elf: parseElf(buf) };
      if (format === "pe") return { format, pe: parsePe(buf) };
      if (format === "macho32" || format === "macho64" || format === "macho-fat") return { format, macho: parseMachO(buf) };
      throw new Error(`Unsupported format for layout: ${format}`);
    },
  },
  {
    name: "reverso_hardening",
    description: "Hardening checks for ELF and PE binaries: PIE, NX stack, stack canary, RELRO/FORTIFY, ASLR, NX compat, Control Flow Guard, Authenticode signature. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => {
      const buf = await readInput(args);
      const format = detectFormat(buf).format;
      return hardeningReport(buf, format);
    },
  },
  {
    name: "reverso_archive_list",
    description: "List entries of a ZIP-based archive (ZIP, APK, IPA, JAR) with sizes, compression, encryption flags and type detection. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => {
      const listing = listArchive(await readInput(args));
      if (!listing) throw new Error("Not a readable ZIP archive");
      return listing;
    },
  },
  {
    name: "reverso_pcap",
    description: "Inspect a classic PCAP capture: version, snaplen, link type, packet count, duration, protocol breakdown, top talkers and top destination ports. pcapng is refused with guidance. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => parsePcap(await readInput(args)),
  },
  {
    name: "reverso_jwt",
    description: "Decode a JWT (header, payload, expiry) WITHOUT verifying the signature. Accepts a token or a file path. Returns JSON including warnings.",
    inputSchema: {
      type: "object",
      properties: {
        token: { type: "string", description: "The JWT itself, or a path to a file containing it" },
      },
      required: ["token"],
    },
    handler: async (args) => {
      const token = args["token"];
      if (typeof token !== "string" || token.trim().length === 0) {
        throw new Error("Missing required string argument: token");
      }
      const trimmed = token.trim();
      try {
        const fileStat = await stat(trimmed);
        if (fileStat.isFile()) {
          return decodeJwt((await readCapped(trimmed)).toString());
        }
      } catch {
        // Not a readable file: treat the argument as the token itself.
      }
      return decodeJwt(trimmed);
    },
  },
  {
    name: "reverso_match",
    description: "Apply the built-in YARA-lite rule pack, or a custom rule pack supplied as JSON, to a file. Returns matched rules and pattern labels. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: {
        rulesJson: { type: "string", description: "Optional custom rule pack JSON (array or {rules: [...]})" },
      },
    },
    handler: async (args) => {
      const buf = await readInput(args);
      const rulesJson = args["rulesJson"];
      const rules = typeof rulesJson === "string" && rulesJson.trim()
        ? parseRulePack(JSON.parse(rulesJson))
        : DEFAULT_RULES;
      const matches = matchRules(rules, buf);
      return { total: matches.length, matched: matches.filter((match) => match.matched).map((m) => m.id), matches };
    },
  },
  {
    name: "reverso_fuzzy",
    description: "Compute a native fuzzy hash for a file. Pass contentB (base64) to compare and get a 0-100 similarity score. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { contentB: { type: "string", description: "Optional base64 content of the second file" } },
    },
    handler: async (args) => {
      const a = fuzzyHash(await readInput(args));
      const contentB = args["contentB"];
      if (typeof contentB !== "string" || !contentB) return a;
      const bBytes = Buffer.from(contentB, "base64");
      const b = fuzzyHash(new Uint8Array(bBytes));
      return { ...a, otherHash: b.hash, similarity: fuzzySimilarity(a.hash, b.hash) };
    },
  },
  {
    name: "reverso_pdf",
    description: "Static PDF structure inspection: objects, encryption, JavaScript, OpenAction, embedded files, URIs and metadata. Returns JSON.",
    inputSchema: { type: "object", properties: {} },
    handler: async (args) => parsePdf(await readInput(args)),
  },
  {
    name: "reverso_pyinstaller",
    description: "Inspect a PyInstaller onefile CArchive: cookie, Python version and table of contents. Returns JSON.",
    inputSchema: { type: "object", properties: {} },
    handler: async (args) => parsePyInstaller(await readInput(args)),
  },
  {
    name: "reverso_lnk",
    description: "Inspect a Windows .lnk shortcut: flags, target path, arguments, working directory and timestamps. Returns JSON.",
    inputSchema: { type: "object", properties: {} },
    handler: async (args) => parseLnk(await readInput(args)),
  },
  {
    name: "reverso_evm",
    description: "Disassemble EVM bytecode from inline hex content or a text file. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { token: { type: "string", description: "Hex bytecode, or a path to a file containing it" } },
    },
    handler: async (args) => {
      const token = args["token"];
      if (typeof token !== "string" || !token.trim()) throw new Error("Missing required string argument: token");
      if (/^(0x)?[0-9a-f]+$/i.test(token.trim())) return parseEvm(token);
      return parseEvm((await readCapped(token.trim())).toString());
    },
  },
  {
    name: "reverso_dotnet",
    description: "Inspect a .NET assembly's CLI metadata streams and string samples. Returns JSON.",
    inputSchema: { type: "object", properties: {} },
    handler: async (args) => parseDotNet(await readInput(args)),
  },
  {
    name: "reverso_ooxml",
    description: "Inspect a DOCX, XLSX or PPTX file: kind, external relationships, VBA presence and document text. Returns JSON.",
    inputSchema: { type: "object", properties: {} },
    handler: async (args) => parseOoxml(await readInput(args)),
  },
  {
    name: "reverso_find_bytes",
    description: "Search a file for a hex byte pattern (e.g. \"4d 5a 90 00\", wildcards \"??\" allowed). Returns match offsets. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        pattern: { type: "string", description: "Hex pattern, e.g. '4d 5a ?? 60'" },
        maxResults: { type: "number", minimum: 1, maximum: 1000, default: 32 },
      },
      required: ["path", "pattern"],
    },
    handler: async (args) => {
      const maxResults = typeof args["maxResults"] === "number" ? Math.min(Math.max(Math.floor(args["maxResults"]), 1), 1000) : 32;
      const pattern = args["pattern"];
      if (typeof pattern !== "string" || pattern.trim().length === 0) {
        throw new Error("Missing required string argument: pattern");
      }
      return findPattern(await readInput(args), pattern, maxResults);
    },
  },
  {
    name: "reverso_wasm",
    description: "Inspect a WebAssembly module: sections, types, imports, exports, function/table/memory/global counts, and the name section. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => parseWasm(await readInput(args)),
  },
  {
    name: "reverso_dex",
    description: "Inspect an Android DEX file: header counts, checksum, and the string table with categorized samples (URLs, keys, class descriptors). Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    handler: async (args) => parseDex(await readInput(args)),
  },
  {
    name: "reverso_scan",
    description: "Recursively scan a directory (skipping node_modules, .git, dist) and triage every file. Returns per-file format, entropy, SHA-256 and packer signals plus a format breakdown. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Directory to scan" },
        maxFiles: { type: "number", minimum: 1, maximum: 1000, default: 200 },
      },
      required: ["path"],
    },
    handler: async (args) => {
      const maxFiles = typeof args["maxFiles"] === "number" ? Math.floor(args["maxFiles"]) : 200;
      return scanDirectory(filePathArg(args), maxFiles);
    },
  },
  {
    name: "reverso_diff",
    description: "Compare two files structurally: hashes, size, entropy, format, packer signals, sections, imports, exports and string categories. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: {
        a: { type: "string", description: "Path of the first file (baseline)" },
        b: { type: "string", description: "Path of the second file (candidate)" },
      },
      required: ["a", "b"],
    },
    handler: async (args) => {
      const a = args["a"];
      const b = args["b"];
      const contentA = args["contentA"];
      const contentB = args["contentB"];
      if (typeof contentA === "string" && typeof contentB === "string") {
        return diffBuffers(
          await readNamedInput(args, "a"),
          await readNamedInput(args, "b"),
          typeof a === "string" ? a : "a",
          typeof b === "string" ? b : "b",
        );
      }
      if (typeof a !== "string" || typeof b !== "string" || !a || !b) {
        throw new Error("Provide contentA and contentB (base64) or two local paths a and b");
      }
      return diffBuffers(await readCapped(a), await readCapped(b), a, b);
    },
  },
  {
    name: "reverso_hex",
    description: "Hex dump of a file region with offsets and an ASCII gutter. Returns the dump as text.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        offset: { type: "number", minimum: 0, default: 0 },
        length: { type: "number", minimum: 1, maximum: 4096, default: 256 },
        width: { type: "number", minimum: 1, maximum: 32, default: 16 },
      },
      required: ["path"],
    },
    handler: async (args) => {
      const buf = await readInput(args);
      const offset = typeof args["offset"] === "number" ? Math.max(0, Math.floor(args["offset"])) : 0;
      const length = typeof args["length"] === "number" ? Math.min(Math.max(Math.floor(args["length"]), 1), 4096) : 256;
      const width = typeof args["width"] === "number" ? Math.min(Math.max(Math.floor(args["width"]), 1), 32) : 16;
      return { dump: hexDump(buf, offset, length, width) };
    },
  },
  {
    name: "reverso_js_analyze",
    description: "Analyze a JavaScript file or bundle: minification, obfuscation score, frameworks, source map, URLs, API endpoints and likely secrets. Accepts either a path or inline source. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path of the JavaScript file" },
        source: { type: "string", description: "Inline JavaScript source (used when path is not given)" },
      },
    },
    handler: async (args) => {
      if (typeof args["path"] === "string" && args["path"]) {
        return analyzeJavaScript((await readInput(args)).toString());
      }
      if (typeof args["source"] === "string") {
        if (args["source"].length > 32 * 1024 * 1024) throw new Error("Inline source too large");
        return analyzeJavaScript(args["source"]);
      }
      throw new Error("Provide either path or source");
    },
  },
];

// Remote transports have no shared filesystem. Every file-based tool also
// accepts inline base64 content, advertised in the tool schema.
for (const tool of TOOL_DEFINITIONS) {
  const schema = tool.inputSchema as {
    properties?: Record<string, unknown>;
    required?: string[];
  };
  schema.properties = {
    ...(schema.properties ?? {}),
    content: { type: "string", description: "Base64-encoded file content (remote use instead of a path)" },
  };
  if (Array.isArray(schema.required)) {
    schema.required = schema.required.filter((name) => name !== "path" && name !== "a" && name !== "b");
  }
}
const diffSchema = TOOL_DEFINITIONS.find((tool) => tool.name === "reverso_diff")?.inputSchema as
  | { properties: Record<string, unknown> }
  | undefined;
if (diffSchema) {
  diffSchema.properties["contentA"] = { type: "string", description: "Base64 content of the baseline file" };
  diffSchema.properties["contentB"] = { type: "string", description: "Base64 content of the candidate file" };
}

function toolList(): unknown {
  return {
    tools: TOOL_DEFINITIONS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
  };
}

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const tool = TOOL_DEFINITIONS.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Unknown tool: ${name}`);
  const result = await tool.handler(args);
  return {
    content: [{ type: "text", text: JSON.stringify(result, (_key, value) => typeof value === "bigint" ? value.toString() : value, 2) }],
  };
}

/** Handles one JSON-RPC message. Returns the response message, or null for notifications. */
export async function handleMessage(message: JsonRpcMessage): Promise<JsonRpcMessage | null> {
  if (message.method === "notifications/initialized" || message.method === "notifications/cancelled") {
    return null;
  }
  if (message.method === undefined) {
    return errorResponse(message.id ?? null, -32600, "Invalid request: missing method");
  }
  const id = message.id ?? null;
  try {
    switch (message.method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: { name: "reverso", version: VERSION },
          },
        };
      case "ping":
        return { jsonrpc: "2.0", id, result: {} };
      case "tools/list":
        return { jsonrpc: "2.0", id, result: toolList() };
      case "tools/call": {
        const params = message.params ?? {};
        const name = params["name"];
        if (typeof name !== "string") return errorResponse(id, -32602, "tools/call requires a tool name");
        const args = (typeof params["arguments"] === "object" && params["arguments"] !== null ? params["arguments"] : {}) as Record<string, unknown>;
        try {
          const result = await callTool(name, args);
          return { jsonrpc: "2.0", id, result };
        } catch (error) {
          return {
            jsonrpc: "2.0",
            id,
            result: {
              content: [{ type: "text", text: `Error: ${(error as Error).message}` }],
              isError: true,
            },
          };
        }
      }
      default:
        return errorResponse(id, -32601, `Method not found: ${message.method}`);
    }
  } catch (error) {
    return errorResponse(id, -32603, `Internal error: ${(error as Error).message}`);
  }
}

function errorResponse(id: number | string | null, code: number, message: string): JsonRpcMessage {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

/** Starts the MCP stdio server. Newline-delimited JSON-RPC over stdin/stdout. */
export async function startStdioServer(): Promise<void> {
  const rl = createInterface({ input: process.stdin, terminal: false });
  const write = (message: JsonRpcMessage): void => {
    process.stdout.write(JSON.stringify(message) + "\n");
  };
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let message: JsonRpcMessage;
    try {
      message = JSON.parse(trimmed);
    } catch {
      write(errorResponse(null, -32700, "Parse error"));
      continue;
    }
    const response = await handleMessage(message);
    if (response) write(response);
  }
}
