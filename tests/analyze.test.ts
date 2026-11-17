import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeBuffer, analyzeFile } from "../src/core/analyze.js";
import { reportToMarkdown } from "../src/core/report.js";
import { makeElf64, makeZip } from "./helpers.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "reverso-analyze-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("analyzeBuffer", () => {
  it("produces hashes, entropy and format for a synthetic ELF", () => {
    const report = analyzeBuffer(makeElf64(), "sample.elf");
    expect(report.hashes.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(report.hashes.md5).toMatch(/^[0-9a-f]{32}$/);
    expect(report.format.format).toBe("elf64");
    expect(report.entropy).toBeGreaterThan(0);
    expect(report.layout?.elf?.machineName).toBe("x86-64");
    expect(report.hardening).not.toBeNull();
  });

  it("detects archives and JavaScript files", () => {
    const archiveReport = analyzeBuffer(makeZip([{ name: "a.txt", content: "hello" }]), "bundle.zip");
    expect(archiveReport.archive?.kind).toBe("zip");

    const jsReport = analyzeBuffer(new TextEncoder().encode("const key = 'AKIAIOSFODNN7EXAMPLE';\n"), "app.js");
    expect(jsReport.javascript?.secrets.map((s) => s.type)).toContain("aws-access-key");
  });
});

describe("analyzeFile", () => {
  it("reads and analyzes a file from disk", async () => {
    const file = join(dir, "sample.elf");
    await writeFile(file, makeElf64());
    const report = await analyzeFile(file);
    expect(report.file).toBe(file);
    expect(report.sizeBytes).toBeGreaterThan(0);
  });

  it("rejects missing files", async () => {
    await expect(analyzeFile(join(dir, "missing.bin"))).rejects.toThrow();
  });
});

describe("reportToMarkdown", () => {
  it("renders the key sections", () => {
    const report = analyzeBuffer(makeElf64(), "sample.elf");
    const markdown = reportToMarkdown(report);
    expect(markdown).toContain("# Reverso analysis: sample.elf");
    expect(markdown).toContain("SHA-256");
    expect(markdown).toContain("## ELF layout");
    expect(markdown).toContain("## Hardening");
    expect(markdown).toContain("## Strings");
  });
});

describe("analyze + markdown roundtrip for zip", () => {
  it("renders the archive section", () => {
    const report = analyzeBuffer(makeZip([{ name: "payload.exe", content: "MZ" }]), "payload.zip");
    const markdown = reportToMarkdown(report);
    expect(markdown).toContain("## Archive (zip)");
    expect(markdown).toContain("payload.exe");
  });
});

describe("analyzeFile read via fs", () => {
  it("output file can be written", async () => {
    const file = join(dir, "note.txt");
    await writeFile(file, "plain text content with https://example.com inside\n");
    const report = await analyzeFile(file);
    const out = join(dir, "report.md");
    await writeFile(out, reportToMarkdown(report));
    const rendered = await readFile(out, "utf8");
    expect(rendered).toContain("Reverso analysis");
  });
});
