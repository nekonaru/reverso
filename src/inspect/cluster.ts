/** Groups scan results by shared build fingerprints and identical content. */
import type { ScanEntry, ScanReport } from "./scan.js";

export interface Cluster {
  kind: "exact" | "imphash" | "rich" | "build-id" | "pdb" | "uuid" | "fuzzy";
  key: string;
  files: string[];
}

export function clusterScan(report: ScanReport): Cluster[] {
  const groups = new Map<string, Cluster>();
  const add = (kind: Cluster["kind"], key: string, file: string): void => {
    const id = `${kind}:${key}`;
    let group = groups.get(id);
    if (!group) {
      group = { kind, key, files: [] };
      groups.set(id, group);
    }
    if (!group.files.includes(file)) group.files.push(file);
  };

  for (const entry of report.entries) {
    add("exact", entry.sha256, entry.file);
    if (entry.imphash) add("imphash", entry.imphash, entry.file);
    if (entry.richHash) add("rich", entry.richHash, entry.file);
    if (entry.buildId) add("build-id", entry.buildId, entry.file);
    if (entry.pdbPath) add("pdb", entry.pdbPath, entry.file);
    if (entry.uuid) add("uuid", entry.uuid, entry.file);
    if (entry.fuzzy) add("fuzzy", entry.fuzzy.slice(0, 32), entry.file);
  }

  return [...groups.values()]
    .filter((group) => group.files.length > 1)
    .sort((a, b) => b.files.length - a.files.length || a.kind.localeCompare(b.kind));
}

export function clusterToMarkdown(clusters: Cluster[]): string {
  const lines = ["# Reverso clusters", ""];
  if (clusters.length === 0) lines.push("- No shared fingerprints found", "");
  for (const cluster of clusters) {
    lines.push(`## ${cluster.kind}: \`${cluster.key}\``, "");
    for (const file of cluster.files) lines.push(`- ${file}`);
    lines.push("");
  }
  return lines.join("\n");
}
