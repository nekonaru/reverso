/** Directory baselines for integrity checks. Zero dependencies, deterministic output. */
import type { ScanEntry } from "./scan.js";

export interface Baseline {
  version: 1;
  createdAt: string;
  root: string;
  entries: Record<string, { sha256: string; sizeBytes: number; format: string }>;
}

export interface BaselineDiff {
  added: string[];
  removed: string[];
  changed: string[];
  unchanged: number;
}

export function createBaseline(root: string, entries: ScanEntry[], createdAt = new Date().toISOString()): Baseline {
  const map: Baseline["entries"] = {};
  for (const entry of entries) {
    map[entry.file] = { sha256: entry.sha256, sizeBytes: entry.sizeBytes, format: entry.format };
  }
  return { version: 1, createdAt, root, entries: map };
}

export function verifyBaseline(baseline: Baseline, entries: ScanEntry[]): BaselineDiff {
  if (baseline.version !== 1) throw new Error(`Unsupported baseline version: ${baseline.version}`);
  const current = new Map<string, ScanEntry>();
  for (const entry of entries) current.set(entry.file, entry);

  const added: string[] = [];
  const changed: string[] = [];
  let unchanged = 0;
  for (const entry of entries) {
    const previous = baseline.entries[entry.file];
    if (!previous) {
      added.push(entry.file);
      continue;
    }
    if (previous.sha256 !== entry.sha256 || previous.sizeBytes !== entry.sizeBytes || previous.format !== entry.format) {
      changed.push(entry.file);
    } else {
      unchanged += 1;
    }
  }
  const removed = Object.keys(baseline.entries).filter((file) => !current.has(file));
  added.sort();
  changed.sort();
  removed.sort();
  return { added, removed, changed, unchanged };
}

export function baselineDiffToMarkdown(diff: BaselineDiff): string {
  const lines = [
    "# Baseline verification",
    "",
    `- **Unchanged:** ${diff.unchanged}`,
    `- **Added:** ${diff.added.length}`,
    `- **Removed:** ${diff.removed.length}`,
    `- **Changed:** ${diff.changed.length}`,
    "",
  ];
  for (const [title, files] of [["Added", diff.added], ["Removed", diff.removed], ["Changed", diff.changed]] as const) {
    if (files.length === 0) continue;
    lines.push(`## ${title}`, "");
    for (const file of files) lines.push(`- ${file}`);
    lines.push("");
  }
  return lines.join("\n");
}
