/** Lightweight investigation cases stored as a single JSON file. */
import { analyzeFile } from "../core/analyze.js";

export interface CaseEvidence {
  file: string;
  sha256: string;
  sizeBytes: number;
  format: string;
  addedAt: string;
  notes?: string;
}

export interface Case {
  version: 1;
  id: string;
  name: string;
  createdAt: string;
  evidence: CaseEvidence[];
}

export function createCase(name: string, createdAt = new Date().toISOString()): Case {
  if (!name.trim()) throw new Error("Case name must not be empty");
  const id = createdAt.replace(/[^0-9]/g, "").slice(0, 14) + "-" + Math.random().toString(36).slice(2, 8);
  return { version: 1, id, name, createdAt, evidence: [] };
}

export async function addEvidence(current: Case, file: string, notes?: string): Promise<Case> {
  if (current.version !== 1) throw new Error(`Unsupported case version: ${current.version}`);
  const report = await analyzeFile(file);
  const entry: CaseEvidence = {
    file,
    sha256: report.hashes.sha256,
    sizeBytes: report.sizeBytes,
    format: report.format.format,
    addedAt: new Date().toISOString(),
    ...(notes ? { notes } : {}),
  };
  return { ...current, evidence: [...current.evidence.filter((e) => e.file !== file), entry] };
}

export function caseToMarkdown(current: Case): string {
  const lines = [
    `# Case: ${current.name}`,
    "",
    `- **ID:** ${current.id}`,
    `- **Created:** ${current.createdAt}`,
    `- **Evidence items:** ${current.evidence.length}`,
    "",
  ];
  if (current.evidence.length > 0) {
    lines.push("| File | Format | Size | SHA-256 | Notes |", "| --- | --- | --- | --- | --- |");
    for (const entry of current.evidence) {
      lines.push(`| ${entry.file} | ${entry.format} | ${entry.sizeBytes} | \`${entry.sha256}\` | ${entry.notes ?? "-"} |`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
