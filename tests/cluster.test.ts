import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clusterScan, clusterToMarkdown } from "../src/inspect/cluster.js";
import { assessRisk } from "../src/inspect/risk.js";
import { analyzeBuffer } from "../src/core/analyze-buffer.js";
import { scanDirectory } from "../src/inspect/scan.js";

let dir: string;
beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "reverso-cluster-")); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe("clustering", () => {
  it("groups files sharing an imphash and exact duplicates", () => {
    const base = (file: string, sha256: string, imphash: string) => ({
      file, sha256, imphash, sizeBytes: 100, format: "pe", entropy: 6, packerSignals: [],
    });
    const report = {
      root: ".", filesScanned: 4, truncated: false, skipped: [], errors: [], byFormat: {},
      entries: [
        base("a.exe", "aaa", "same-imphash"),
        base("b.exe", "bbb", "same-imphash"),
        base("c.exe", "ccc", "other-imphash"),
        base("d.exe", "aaa", "third-imphash"),
      ],
    };
    const clusters = clusterScan(report);
    expect(clusters.some((c) => c.kind === "imphash" && c.files.length === 2)).toBe(true);
    expect(clusters.some((c) => c.kind === "exact" && c.files.length === 2)).toBe(true);
    expect(clusterToMarkdown(clusters)).toContain("## imphash");
  });
});

describe("risk score", () => {
  it("is explainable and bounded", () => {
    const report = analyzeBuffer(new TextEncoder().encode("UPX! simple file"), "sample.bin");
    const risk = assessRisk(report);
    expect(risk.score).toBeGreaterThanOrEqual(0);
    expect(risk.score).toBeLessThanOrEqual(100);
    expect(risk.reasons.join(" ")).toContain("packer");
    expect(risk.score).toBe(report.risk.score);
  });
});

describe("scan cache", () => {
  it("writes a reusable cache file", async () => {
    await writeFile(join(dir, "a.txt"), "hello cache");
    const cachePath = join(dir, "..", `reverso-cache-${Date.now()}.json`);
    const first = await scanDirectory(dir, 100, cachePath);
    expect(first.filesScanned).toBe(1);
    const second = await scanDirectory(dir, 100, cachePath);
    expect(second.entries[0]!.sha256).toBe(first.entries[0]!.sha256);
    await rm(cachePath, { force: true });
  });
});
