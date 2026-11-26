/** Rule model for the native YARA-lite engine. No external rule language or runtime. */
export type RuleSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface RulePattern {
  kind: "hex" | "text" | "regex";
  value: string;
  label?: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  tags?: string[];
  patterns: RulePattern[];
  /** Restricted expression: labels, p1/p2, them, and/or/not, filesize/entropy comparisons. */
  condition: string;
}

export interface RuleMatch {
  id: string;
  name: string;
  severity: RuleSeverity;
  matched: boolean;
  matchedPatterns: string[];
  error?: string;
}

export interface RuleContext {
  fileSize: number;
  entropy: number;
}
