import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import { analyzeBuffer } from "../src/core/analyze.js";
import { listArchive } from "../src/archive/zip.js";
import { parsePe } from "../src/binary/pe.js";
import { makeElf64 } from "./helpers.js";
import { run, parseArgs } from "../src/cli.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "reverso-audit-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("analyzeBuffer on degenerate input", () => {
  it("handles an empty file without throwing", () => {
    const report = analyzeBuffer(new Uint8Array(0), "empty.bin");
    expect(report.sizeBytes).toBe(0);
    expect(report.format.format).toBe("unknown");
    expect(report.hashes.sha256).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(report.entropy).toBe(0);
  });

  it("handles a three-byte ELF magic without throwing", () => {
    const report = analyzeBuffer(new Uint8Array([0x7f, 0x45, 0x4c]), "tiny.bin");
    expect(report.sizeBytes).toBe(3);
    expect(report.layout).toBeNull();
  });

  it("handles a structurally valid but truncated ELF without throwing", () => {
    const full = makeElf64();
    const truncated = full.subarray(0, 40);
    expect(() => analyzeBuffer(truncated, "trunc.elf")).not.toThrow();
  });

  it("handles a MZ file without PE signature without throwing", () => {
    const buf = new Uint8Array(128);
    buf.set([0x4d, 0x5a], 0);
    const report = analyzeBuffer(buf, "mz.com");
    expect(report.format.format).toBe("dos-mz");
  });
});

describe("ELF strict magic validation", () => {
  it("parseElf throws on invalid EI_CLASS and EI_DATA", async () => {
    const { parseElf } = await import("../src/binary/elf.js");
    const garbage = new Uint8Array(64);
    garbage.set([0x7f, 0x45, 0x4c, 0x46, 3, 1, 1, 0], 0); // EI_CLASS 3
    expect(() => parseElf(garbage)).toThrow(/EI_CLASS/);
    const garbage2 = new Uint8Array(64);
    garbage2.set([0x7f, 0x45, 0x4c, 0x46, 2, 9, 1, 0], 0); // EI_DATA 9
    expect(() => parseElf(garbage2)).toThrow(/EI_DATA/);
  });

  it("parses a zeroed but structurally consistent PE without throwing", () => {
    const buf = new Uint8Array(0x400);
    buf.set([0x4d, 0x5a], 0);
    new DataView(buf.buffer).setUint32(0x3c, 0x80, true);
    new DataView(buf.buffer).setUint32(0x80, 0x00004550, true);
    const pe = parsePe(buf);
    expect(pe.imports).toEqual([]);
    expect(pe.exports).toEqual([]);
  });
});

describe("listArchive on corrupt input", () => {
  it("returns null for an archive whose central directory pointer is out of bounds", () => {
    const buf = new Uint8Array(64);
    buf.set([0x50, 0x4b, 0x05, 0x06], 42);
    new DataView(buf.buffer).setUint32(42 + 16, 0xffffffff, true);
    expect(listArchive(buf)).toBeNull();
  });

  it("returns null for a truncated EOCD", () => {
    const buf = new Uint8Array(8);
    buf.set([0x50, 0x4b, 0x05, 0x06], 0);
    expect(listArchive(buf)).toBeNull();
  });
});

describe("parsePe on truncated input", () => {
  it("throws a controlled error for a truncated PE (never crashes silently)", () => {
    const buf = new Uint8Array(64);
    buf.set([0x4d, 0x5a], 0);
    new DataView(buf.buffer).setUint32(0x3c, 0x40, true);
    expect(() => parsePe(buf)).toThrow(/PE signature|Not a PE/);
  });
});

describe("parseArgs and flag parsing", () => {
  it("does not consume the next flag as a value", () => {
    const { flags } = parseArgs(["site", "https://example.com", "--allow-private", "--max-pages", "10"]);
    expect(flags.get("allow-private")).toBe(true);
    expect(flags.get("max-pages")).toBe("10");
  });

  it("rejects non-numeric --max-pages with a clear error", async () => {
    const code = await run(["site", "https://example.com", "--max-pages", "not-a-number"]);
    expect(code).toBe(1);
  });
});

describe("site mirror boolean flag with string value", () => {
  let server: Server;
  let origin: string;
  let outDir: string;

  beforeEach(async () => {
    outDir = await mkdtemp(join(tmpdir(), "reverso-audit-mirror-"));
    server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
    await rm(outDir, { recursive: true, force: true });
  });

  it("accepts --allow-private=true as truthy", async () => {
    const code = await run(["site", `${origin}/`, "--out", outDir, "--allow-private=true"]);
    expect(code).toBe(0);
  });
});

describe("analyze CLI on degenerate files", () => {
  it("exits 0 and writes a report for an empty file", async () => {
    const empty = join(dir, "empty.bin");
    await writeFile(empty, new Uint8Array(0));
    const code = await run(["analyze", empty]);
    expect(code).toBe(0);
  });
});
