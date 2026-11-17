import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleMessage, type JsonRpcMessage } from "../src/mcp/server.js";

let dir: string;
let file: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "reverso-mcp-"));
  file = join(dir, "sample.bin");
  await writeFile(file, Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.from("hello reverso\x00", "ascii")]));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function rpc(method: string, params?: Record<string, unknown>, id: number | string = 1): Promise<JsonRpcMessage | null> {
  return handleMessage({ jsonrpc: "2.0", id, method, ...(params ? { params } : {}) });
}

describe("MCP server", () => {
  it("answers initialize with protocol version and server info", async () => {
    const response = await rpc("initialize");
    const result = response?.result as { protocolVersion: string; serverInfo: { name: string } };
    expect(result.protocolVersion).toBe("2025-06-18");
    expect(result.serverInfo.name).toBe("reverso");
  });

  it("answers ping", async () => {
    const response = await rpc("ping");
    expect(response?.result).toEqual({});
  });

  it("lists all 14 tools", async () => {
    const response = await rpc("tools/list");
    const result = response?.result as { tools: Array<{ name: string }> };
    const names = result.tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining([
      "reverso_analyze",
      "reverso_strings",
      "reverso_entropy",
      "reverso_format",
      "reverso_layout",
      "reverso_hardening",
      "reverso_archive_list",
      "reverso_js_analyze",
      "reverso_find_bytes",
      "reverso_wasm",
      "reverso_dex",
      "reverso_scan",
      "reverso_diff",
      "reverso_hex",
    ]));
    expect(result.tools).toHaveLength(14);
  });

  it("runs tools/call reverso_format on a file", async () => {
    const response = await rpc("tools/call", { name: "reverso_format", arguments: { path: file } });
    const result = response?.result as { content: Array<{ text: string }> };
    const payload = JSON.parse(result.content[0]!.text);
    expect(payload.format).toBe("elf64");
  });

  it("runs tools/call reverso_js_analyze with inline source", async () => {
    const response = await rpc("tools/call", { name: "reverso_js_analyze", arguments: { source: "eval('x'); // AKIAIOSFODNN7EXAMPLE" } });
    const result = response?.result as { content: Array<{ text: string }> };
    const payload = JSON.parse(result.content[0]!.text);
    expect(payload.suspiciousCalls).toContain("eval");
  });

  it("returns isError for unknown tools", async () => {
    const response = await rpc("tools/call", { name: "reverso_nope", arguments: {} });
    const result = response?.result as { isError: boolean; content: Array<{ text: string }> };
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain("Unknown tool");
  });

  it("returns a JSON-RPC error for unknown methods", async () => {
    const response = await rpc("resources/list");
    expect(response?.error?.code).toBe(-32601);
  });

  it("ignores notifications", async () => {
    expect(await handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" })).toBeNull();
  });

  it("runs tools/call reverso_find_bytes on a file", async () => {
    const response = await rpc("tools/call", { name: "reverso_find_bytes", arguments: { path: file, pattern: "7f 45 4c 46" } });
    const result = response?.result as { content: Array<{ text: string }> };
    const payload = JSON.parse(result.content[0]!.text);
    expect(payload.offsets).toContain(0);
  });

  it("runs tools/call reverso_hex with a small length", async () => {
    const response = await rpc("tools/call", { name: "reverso_hex", arguments: { path: file, length: 16 } });
    const result = response?.result as { content: Array<{ text: string }> };
    expect(JSON.parse(result.content[0]!.text).dump).toContain("00000000");
  });

  it("runs tools/call reverso_diff on two files", async () => {
    const other = join(dir, "other.bin");
    await writeFile(other, Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0]), Buffer.from("different-content\x00", "ascii")]));
    const response = await rpc("tools/call", { name: "reverso_diff", arguments: { a: file, b: other } });
    const result = response?.result as { content: Array<{ text: string }> };
    const payload = JSON.parse(result.content[0]!.text);
    expect(payload.identical).toBe(false);
    expect(payload.differences.length).toBeGreaterThan(0);
  });

  it("runs tools/call reverso_scan on a directory", async () => {
    const response = await rpc("tools/call", { name: "reverso_scan", arguments: { path: dir, maxFiles: 10 } });
    const result = response?.result as { content: Array<{ text: string }> };
    const payload = JSON.parse(result.content[0]!.text);
    expect(payload.filesScanned).toBeGreaterThanOrEqual(1);
  });

  it("reports a tool error for missing files without crashing", async () => {
    const response = await rpc("tools/call", { name: "reverso_format", arguments: { path: join(dir, "does-not-exist.bin") } });
    const result = response?.result as { isError: boolean };
    expect(result.isError).toBe(true);
  });
});
