import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBaseline, verifyBaseline, baselineDiffToMarkdown } from "../src/inspect/baseline.js";
import { createCase, addEvidence, caseToMarkdown } from "../src/inspect/case.js";
import { toSarif, toHtml, scanToCsv } from "../src/inspect/exports.js";
import { analyzeBuffer } from "../src/core/analyze-buffer.js";
import { makeElf64 } from "./helpers.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "reverso-workflow-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const entries = (files: Array<[string, string]>) => files.map(([file, sha256]) => ({
  file,
  sha256,
  sizeBytes: 100,
  format: "text",
  entropy: 4,
  packerSignals: [],
}));

describe("baselines", () => {
  it("detects added, removed and changed files", () => {
    const baseline = createBaseline("root", entries([["a.txt", "aaa"], ["b.txt", "bbb"]]), "2026-01-01T00:00:00.000Z");
    expect(baseline.version).toBe(1);
    const diff = verifyBaseline(baseline, entries([["a.txt", "changed"], ["c.txt", "ccc"]]));
    expect(diff.added).toEqual(["c.txt"]);
    expect(diff.removed).toEqual(["b.txt"]);
    expect(diff.changed).toEqual(["a.txt"]);
    expect(diff.unchanged).toBe(0);
    expect(baselineDiffToMarkdown(diff)).toContain("## Changed");
  });

  it("reports no changes for identical input", () => {
    const baseline = createBaseline("root", entries([["a.txt", "aaa"]]));
    const diff = verifyBaseline(baseline, entries([["a.txt", "aaa"]]));
    expect(diff.added).toEqual([]);
    expect(diff.removed).toEqual([]);
    expect(diff.changed).toEqual([]);
    expect(diff.unchanged).toBe(1);
  });
});

describe("cases", () => {
  it("creates, adds evidence and renders a report", async () => {
    const target = join(dir, "sample.elf");
    await writeFile(target, makeElf64());
    const created = createCase("Investigation");
    expect(created.evidence).toEqual([]);
    const withEvidence = await addEvidence(created, target, "first sample");
    expect(withEvidence.evidence).toHaveLength(1);
    expect(withEvidence.evidence[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(caseToMarkdown(withEvidence)).toContain("Investigation");
    expect(caseToMarkdown(withEvidence)).toContain("first sample");
  });
});

describe("report exports", () => {
  it("produces valid SARIF with findings", () => {
    const report = analyzeBuffer(makeElf64(), "sample.elf");
    const sarif = toSarif(report) as { version: string; runs: Array<{ results: unknown[] }> };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]!.results).toBeInstanceOf(Array);
  });

  it("produces a self-contained HTML report", () => {
    const html = toHtml(analyzeBuffer(makeElf64(), "sample.elf"));
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain('id="report-data"');
    expect(html).not.toContain("<script src=");
    expect(html).toContain("Reverso report");
  });

  it("escapes HTML in the embedded JSON", () => {
    const html = toHtml(analyzeBuffer(new TextEncoder().encode("plain bytes"), "</script>bad.js"));
    expect(html).toContain("<\\/script");
  });

  it("produces CSV with a header row", () => {
    const csv = scanToCsv({
      root: ".", filesScanned: 1, truncated: false, skipped: [], errors: [], byFormat: { text: 1 },
      entries: entries([["a.txt", "aaa"]]),
    });
    expect(csv.split("\n")[0]).toBe("file,format,sizeBytes,entropy,sha256,packerSignals");
    expect(csv).toContain("a.txt");
  });
});
