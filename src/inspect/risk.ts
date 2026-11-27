/** Explainable 0-100 risk score derived from static findings. */
import type { AnalysisReport } from "../core/analyze-buffer.js";

export interface RiskAssessment {
  score: number;
  reasons: string[];
}

export function assessRisk(report: AnalysisReport): RiskAssessment {
  let score = 0;
  const reasons: string[] = [];
  const add = (points: number, reason: string, cap?: number): void => {
    const before = score;
    score = Math.min(100, score + points);
    if (score > before) reasons.push(`${reason} (+${score - before}${cap ? `, capped at ${cap}` : ""})`);
  };

  const failed = (report.hardening?.checks ?? []).filter((check) => check.status === "fail");
  if (failed.length > 0) add(Math.min(30, failed.length * 8), `${failed.length} hardening check(s) failed`, 30);
  if (report.packerSignals.length > 0) add(Math.min(25, report.packerSignals.length * 10), "packer signals present", 25);
  const secretTypes = new Set((report.javascript?.secrets ?? []).map((secret) => secret.type));
  if (secretTypes.size > 0) add(Math.min(25, secretTypes.size * 12), `${secretTypes.size} secret type(s) in JavaScript`, 25);
  if (report.entropy >= 7.5) add(10, "very high file entropy");
  if (report.javascript && report.javascript.obfuscation.score >= 50) add(10, "JavaScript obfuscation score above 50");
  if (failed.some((check) => check.name.includes("NX") || check.name.includes("ASLR"))) add(10, "memory protection missing");

  return { score, reasons };
}
