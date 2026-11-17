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

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "reverso_analyze",
    description: "Full static analysis of a file: hashes, entropy, format detection, strings with categories, layout, hardening, archive listing and JavaScript analysis. Returns JSON.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Absolute path of the file to analyze" } },
      required: ["path"],
    },
    handler: async (args) => analyzeBuffer(await readCapped(filePathArg(args)), filePathArg(args)),
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
      const strings = extractStrings(await readCapped(filePathArg(args)), { minLength });
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
      const buf = await readCapped(filePathArg(args));
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
    handler: async (args) => detectFormat(await readCapped(filePathArg(args))),
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
      const path = filePathArg(args);
      const buf = await readCapped(path);
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
      const buf = await readCapped(filePathArg(args));
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
      const listing = listArchive(await readCapped(filePathArg(args)));
      if (!listing) throw new Error("Not a readable ZIP archive");
      return listing;
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
        return analyzeJavaScript((await readCapped(args["path"])).toString());
      }
      if (typeof args["source"] === "string") {
        if (args["source"].length > 32 * 1024 * 1024) throw new Error("Inline source too large");
        return analyzeJavaScript(args["source"]);
      }
      throw new Error("Provide either path or source");
    },
  },
];

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
