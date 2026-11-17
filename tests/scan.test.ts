import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanDirectory, scanReportToMarkdown } from "../src/inspect/scan.js";
import { makeElf64, makeZip } from "./helpers.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "reverso-scan-"));
  await writeFile(join(dir, "a.elf"), makeElf64());
  await writeFile(join(dir, "notes.txt"), "plain text content for the scan test\n");
  await mkdir(join(dir, "sub"));
  await writeFile(join(dir, "sub", "b.js"), "const token = 'AKIAIOSFODNN7EXAMPLE';\n");
  await writeFile(join(dir, "c.zip"), makeZip([{ name: "inner.txt", content: "zip content" }]));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("scanDirectory", () => {
  it("finds and analyzes all files recursively", async () => {
    const report = await scanDirectory(dir, 100);
    expect(report.filesScanned).toBe(4);
    expect(report.errors).toEqual([]);
    expect(report.byFormat["elf64"]).toBe(1);
    expect(report.byFormat["zip"]).toBe(1);
    const names = report.entries.map((entry) => entry.file);
    expect(names).toContain("sub/b.js");
    for (const entry of report.entries) {
      expect(entry.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("truncates at maxFiles", async () => {
    const report = await scanDirectory(dir, 2);
    expect(report.filesScanned).toBe(2);
    expect(report.truncated).toBe(true);
  });

  it("rejects non-directory paths", async () => {
    await expect(scanDirectory(join(dir, "a.elf"))).rejects.toThrow(/Not a directory/);
  });

  it("renders a markdown report", async () => {
    const report = await scanDirectory(dir, 100);
    const markdown = scanReportToMarkdown(report);
    expect(markdown).toContain("# Reverso scan");
    expect(markdown).toContain("| File | Format | Size | Entropy | Packer signals |");
    expect(markdown).toContain("a.elf");
  });
});
