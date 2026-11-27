/** Redacts likely secret values from a report before sharing it. */
import type { AnalysisReport } from "../core/analyze-buffer.js";

const PATTERNS: Array<[RegExp, (match: string) => string]> = [
  [/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g, (m) => mask(m, 6)],
  [/(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}/g, (m) => mask(m, 4)],
  [/(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g, (m) => mask(m, 4)],
  [/github_pat_[A-Za-z0-9_]{20,}/g, (m) => mask(m, 8)],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/g, (m) => mask(m, 4)],
  [/AIza[0-9A-Za-z_-]{35}/g, (m) => mask(m, 4)],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, () => "[REDACTED PRIVATE KEY HEADER]"],
];

function mask(value: string, visible: number): string {
  if (value.length <= visible * 2) return "[REDACTED]";
  return `${value.slice(0, visible)}...${value.slice(-visible)}`;
}

function redact(value: string): string {
  let out = value;
  for (const [pattern, replace] of PATTERNS) out = out.replace(pattern, (match) => replace(match));
  return out;
}

/** Returns a copy of the report with secret-looking values masked. */
export function redactReport(report: AnalysisReport): AnalysisReport {
  return {
    ...report,
    strings: {
      ...report.strings,
      categories: report.strings.categories.map((category) => ({
        ...category,
        samples: category.samples.map(redact),
      })),
    },
    javascript: report.javascript
      ? {
        ...report.javascript,
        secrets: report.javascript.secrets.map((secret) => ({ ...secret, match: redact(secret.match) })),
        urls: report.javascript.urls.map(redact),
      }
      : null,
  };
}
