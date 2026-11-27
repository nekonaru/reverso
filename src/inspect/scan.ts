/** Recursive directory triage: analyze every eligible file and summarize. */

import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { analyzeFile, MAX_INPUT_BYTES } from "../core/analyze.js";
import { analyzeBuffer } from "../core/analyze-buffer.js";
import { fuzzyHash } from "./fuzzy.js";

export interface ScanEntry {
  file: string;
  sizeBytes: number;
  format: string;
  entropy: number;
  sha256: string;
  packerSignals: string[];
  imphash?: string;
  richHash?: string;
  buildId?: string;
  pdbPath?: string;
  uuid?: string;
  fuzzy?: string;
}

export interface ScanReport {
  root: string;
  filesScanned: number;
  truncated: boolean;
  skipped: Array<{ file: string; reason: string }>;
  errors: Array<{ file: string; error: string }>;
  byFormat: Record<string, number>;
  entries: ScanEntry[];
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "coverage", ".reverso-cache"]);
const DEFAULT_MAX_FILES = 200;
const HARD_MAX_FILES = 1000;

/** Scans a directory recursively. Unreadable or oversized files are skipped, never fatal. */
export interface ScanCache {
  version: 1;
  files: Record<string, { mtimeMs: number; sizeBytes: number; entry: ScanEntry }>;
}

export async function scanDirectory(root: string, maxFiles = DEFAULT_MAX_FILES, cachePath?: string): Promise<ScanReport> {
  const limit = Math.min(Math.max(Math.floor(maxFiles), 1), HARD_MAX_FILES);
  const rootStat = await stat(root);
  if (!rootStat.isDirectory()) throw new Error(`Not a directory: ${root}`);

  let cache: ScanCache | null = null;
  if (cachePath) {
    try {
      const parsed = JSON.parse(await readFile(cachePath, "utf8")) as ScanCache;
      if (parsed.version === 1 && typeof parsed.files === "object") cache = parsed;
    } catch {
      cache = null;
    }
  }

  const files: string[] = [];
  const skipped: ScanReport["skipped"] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (files.length >= limit * 4 || depth > 16) return;
    let items;
    try {
      items = await readdir(dir, { withFileTypes: true });
    } catch {
      return; // Unreadable directory: skip silently, the caller lists gaps via `skipped` when relevant.
    }
    for (const item of items) {
      if (files.length >= limit * 4) return;
      const full = join(dir, item.name);
      if (item.isDirectory()) {
        if (SKIP_DIRS.has(item.name)) continue;
        await walk(full, depth + 1);
        continue;
      }
      if (!item.isFile()) continue;
      files.push(full);
    }
  };
  await walk(root, 0);

  files.sort();
  const entries: ScanEntry[] = [];
  const errors: ScanReport["errors"] = [];
  const byFormat: Record<string, number> = {};
  let processed = 0;

  for (const file of files) {
    if (processed >= limit) break;
    let fileStat;
    try {
      fileStat = await stat(file);
    } catch {
      errors.push({ file: relative(root, file), error: "stat failed" });
      continue;
    }
    if (fileStat.size > MAX_INPUT_BYTES) {
      skipped.push({ file: relative(root, file), reason: `exceeds ${MAX_INPUT_BYTES} bytes` });
      continue;
    }
    const cacheKey = relative(root, file).split(sep).join("/");
    const cached = cache?.files[cacheKey];
    if (cached && cached.mtimeMs === fileStat.mtimeMs && cached.sizeBytes === fileStat.size) {
      entries.push(cached.entry);
      byFormat[cached.entry.format] = (byFormat[cached.entry.format] ?? 0) + 1;
      processed += 1;
      continue;
    }
    try {
      const buf = await readFile(file);
      const report = analyzeBuffer(buf, file);
      const fuzzy = fuzzyHash(buf).hash.split(":").slice(2).join(":");
      const entry: ScanEntry = {
        file: relative(root, file).split(sep).join("/"),
        sizeBytes: report.sizeBytes,
        format: report.format.format,
        entropy: report.entropy,
        sha256: report.hashes.sha256,
        packerSignals: report.packerSignals,
        ...(report.layout?.pe?.imphash ? { imphash: report.layout.pe.imphash } : {}),
        ...(report.layout?.pe?.rich?.richHash ? { richHash: report.layout.pe.rich.richHash } : {}),
        ...(report.layout?.pe?.pdbPath ? { pdbPath: report.layout.pe.pdbPath } : {}),
        ...(report.layout?.elf?.buildId ? { buildId: report.layout.elf.buildId } : {}),
        ...(report.layout?.macho?.uuid ? { uuid: report.layout.macho.uuid } : {}),
        ...(fuzzy ? { fuzzy } : {}),
      };
      entries.push(entry);
      if (cache) cache.files[cacheKey] = { mtimeMs: fileStat.mtimeMs, sizeBytes: fileStat.size, entry };
      byFormat[report.format.format] = (byFormat[report.format.format] ?? 0) + 1;
      processed += 1;
    } catch (error) {
      errors.push({ file: relative(root, file), error: (error as Error).message });
    }
  }

  if (cachePath && cache) {
    try {
      await writeFile(cachePath, JSON.stringify(cache, null, 2));
    } catch {
      // Cache is an optimization; failure to write it is not fatal.
    }
  }

  return {
    root,
    filesScanned: entries.length,
    truncated: files.length > entries.length + skipped.length,
    skipped,
    errors,
    byFormat,
    entries,
  };
}

export function scanReportToMarkdown(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`# Reverso scan: ${report.root}`);
  lines.push("");
  lines.push(`- **Files analyzed:** ${report.filesScanned}${report.truncated ? " (truncated)" : ""}`);
  lines.push(`- **Errors:** ${report.errors.length}, **skipped:** ${report.skipped.length}`);
  lines.push("");
  lines.push("## Formats");
  lines.push("");
  for (const [format, count] of Object.entries(report.byFormat).sort((a, b) => b[1] - a[1])) {
    lines.push(`- **${format}:** ${count}`);
  }
  lines.push("");
  if (report.entries.length > 0) {
    lines.push("## Files");
    lines.push("");
    lines.push("| File | Format | Size | Entropy | Packer signals |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const entry of report.entries) {
      const signals = entry.packerSignals.length > 0 ? entry.packerSignals.join("; ") : "-";
      lines.push(`| ${entry.file} | ${entry.format} | ${entry.sizeBytes} | ${entry.entropy} | ${signals} |`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
