/** Safe rule evaluation. No eval, no dynamic code: a small restricted parser. */
import { parseHexPattern } from "../inspect/bytes.js";
import { shannonEntropy } from "../core/entropy.js";
import type { Rule, RuleContext, RuleMatch, RuleSeverity } from "./types.js";

const SEVERITIES: RuleSeverity[] = ["info", "low", "medium", "high", "critical"];
const MAX_SCAN_BYTES = 16 * 1024 * 1024;

/** Validates and normalizes a rule loaded from JSON. Throws on malformed input. */
export function parseRule(input: unknown): Rule {
  if (typeof input !== "object" || input === null) throw new Error("Rule must be an object");
  const r = input as Record<string, unknown>;
  if (typeof r["id"] !== "string" || !r["id"]) throw new Error("Rule requires an id");
  if (typeof r["name"] !== "string" || !r["name"]) throw new Error(`Rule ${r["id"]} requires a name`);
  if (typeof r["condition"] !== "string" || !r["condition"]) throw new Error(`Rule ${r["id"]} requires a condition`);
  const severity = typeof r["severity"] === "string" && SEVERITIES.includes(r["severity"] as RuleSeverity)
    ? r["severity"] as RuleSeverity
    : "info";
  if (!Array.isArray(r["patterns"])) throw new Error(`Rule ${r["id"]} requires patterns`);
  const patterns = r["patterns"].map((entry, index) => {
    if (typeof entry !== "object" || entry === null) throw new Error(`Rule ${r["id"]}: invalid pattern ${index}`);
    const p = entry as Record<string, unknown>;
    if (p["kind"] !== "hex" && p["kind"] !== "text" && p["kind"] !== "regex") {
      throw new Error(`Rule ${r["id"]}: pattern ${index} has invalid kind`);
    }
    if (typeof p["value"] !== "string" || !p["value"]) throw new Error(`Rule ${r["id"]}: pattern ${index} needs a value`);
    if (p["kind"] === "hex") parseHexPattern(p["value"]); // validate early
    if (p["kind"] === "regex") {
      try { new RegExp(p["value"]); } catch { throw new Error(`Rule ${r["id"]}: invalid regex in pattern ${index}`); }
    }
    return {
      kind: p["kind"] as "hex" | "text" | "regex",
      value: p["value"] as string,
      ...(typeof p["label"] === "string" ? { label: p["label"] as string } : {}),
    };
  });
  if (patterns.length === 0) throw new Error(`Rule ${r["id"]}: at least one pattern is required`);
  return {
    id: r["id"] as string,
    name: r["name"] as string,
    description: typeof r["description"] === "string" ? r["description"] as string : "",
    severity,
    ...(Array.isArray(r["tags"]) ? { tags: (r["tags"] as unknown[]).filter((t): t is string => typeof t === "string") } : {}),
    patterns,
    condition: r["condition"] as string,
  };
}

export function parseRulePack(input: unknown): Rule[] {
  const list = Array.isArray(input) ? input
    : typeof input === "object" && input !== null && Array.isArray((input as Record<string, unknown>)["rules"])
      ? (input as Record<string, unknown>)["rules"] as unknown[]
      : null;
  if (!list) throw new Error("Rule pack must be an array of rules or an object with a rules array");
  return list.map(parseRule);
}

/** Computes pattern hits and evaluates the rule condition. */
export function matchRule(rule: Rule, buf: Uint8Array, entropy?: number): RuleMatch {
  const results = rule.patterns.map((pattern) => matchesPattern(pattern, buf));
  const labels = new Map<string, boolean>();
  rule.patterns.forEach((pattern, index) => {
    labels.set(`p${index + 1}`, results[index]!);
    if (pattern.label) labels.set(pattern.label, results[index]!);
  });
  const context: RuleContext = { fileSize: buf.length, entropy: entropy ?? shannonEntropy(buf) };
  let matched = false;
  let error: string | undefined;
  try {
    matched = evaluateCondition(rule.condition, results, labels, context);
  } catch (caught) {
    error = (caught as Error).message;
  }
  return {
    id: rule.id,
    name: rule.name,
    severity: rule.severity,
    matched,
    matchedPatterns: rule.patterns.filter((_pattern, index) => results[index]).map((pattern) => pattern.label ?? pattern.value),
    ...(error ? { error } : {}),
  };
}

export function matchRules(rules: Rule[], buf: Uint8Array, entropy?: number): RuleMatch[] {
  const computed = entropy ?? shannonEntropy(buf);
  return rules.map((rule) => matchRule(rule, buf, computed));
}

function matchesPattern(pattern: Rule["patterns"][number], buf: Uint8Array): boolean {
  if (pattern.kind === "hex") {
    const bytes = parseHexPattern(pattern.value);
    if (bytes.length > buf.length) return false;
    outer: for (let i = 0; i + bytes.length <= buf.length; i++) {
      for (let j = 0; j < bytes.length; j++) {
        const expected = bytes[j];
        if (expected !== null && buf[i + j] !== expected) continue outer;
      }
      return true;
    }
    return false;
  }

  const text = new TextDecoder("utf8").decode(buf.subarray(0, Math.min(buf.length, MAX_SCAN_BYTES)));
  const wide = new TextDecoder("utf-16le").decode(buf.subarray(0, Math.min(buf.length, MAX_SCAN_BYTES)));
  if (pattern.kind === "text") {
    return text.includes(pattern.value) || wide.includes(pattern.value);
  }
  const regex = new RegExp(pattern.value);
  return regex.test(text) || regex.test(wide);
}

/** Recursive descent over: or, and, not, (...), identifiers, filesize/entropy comparisons. */
function evaluateCondition(
  source: string,
  patternResults: boolean[],
  labels: Map<string, boolean>,
  context: RuleContext,
): boolean {
  const tokens = tokenize(source);
  let pos = 0;
  const peek = () => tokens[pos];
  const take = () => tokens[pos++];

  const parsePrimary = (): boolean => {
    const token = take();
    if (!token) throw new Error("Unexpected end of condition");
    if (token === "(") {
      const value = parseOr();
      if (take() !== ")") throw new Error("Missing closing parenthesis");
      return value;
    }
    if (token === "not") return !parsePrimary();
    if (/^\d+$/.test(token) && peek() === "of") {
      take();
      const target = take();
      const count = Number(token);
      if (target === "them") return patternResults.filter(Boolean).length >= count;
      return false;
    }
    if (token === "them") return patternResults.some(Boolean);
    if (token === "all") {
      if (take() !== "of") throw new Error("Expected 'of' after 'all'");
      const target = take();
      if (target === "them") return patternResults.every(Boolean);
      return labels.get(target ?? "") ?? false;
    }
    if (token === "any") {
      if (take() !== "of") throw new Error("Expected 'of' after 'any'");
      const target = take();
      if (target === "them") return patternResults.some(Boolean);
      if (target && /^\d+$/.test(target)) {
        const count = Number(target);
        return patternResults.filter(Boolean).length >= count;
      }
      return labels.get(target ?? "") ?? false;
    }
    if (token === "filesize" || token === "entropy") {
      const operator = take();
      const raw = take();
      if (operator !== "<" && operator !== ">" && operator !== "<=" && operator !== ">=" && operator !== "==") {
        throw new Error(`Invalid comparison operator: ${operator ?? ""}`);
      }
      const value = parseSize(raw ?? "", token === "entropy");
      const left = token === "filesize" ? context.fileSize : context.entropy;
      if (operator === "<") return left < value;
      if (operator === ">") return left > value;
      if (operator === "<=") return left <= value;
      if (operator === ">=") return left >= value;
      return left === value;
    }
    return labels.get(token) ?? false;
  };

  const parseAnd = (): boolean => {
    let value = parsePrimary();
    while (peek() === "and") {
      take();
      const next = parsePrimary();
      value = value && next;
    }
    return value;
  };

  const parseOr = (): boolean => {
    let value = parseAnd();
    while (peek() === "or") {
      take();
      const next = parseAnd();
      value = value || next;
    }
    return value;
  };

  const result = parseOr();
  if (pos < tokens.length) throw new Error(`Unexpected token: ${tokens[pos]}`);
  return result;
}

function parseSize(raw: string, entropy: boolean): number {
  if (entropy) {
    const value = Number(raw);
    if (!Number.isFinite(value)) throw new Error(`Invalid entropy threshold: ${raw}`);
    return value;
  }
  const match = raw.match(/^(\d+(?:\.\d+)?)\s*(kb|mb|gb)?$/i);
  if (!match) throw new Error(`Invalid size threshold: ${raw}`);
  const multiplier = match[2]?.toLowerCase() === "kb" ? 1024 : match[2]?.toLowerCase() === "mb" ? 1024 ** 2 : match[2]?.toLowerCase() === "gb" ? 1024 ** 3 : 1;
  return Number(match[1]) * multiplier;
}

function tokenize(source: string): string[] {
  const tokens: string[] = [];
  const pattern = /==|<=|>=|\(|\)|<|>|\b(?:and|or|not|all|any|of|them|filesize|entropy)\b|[^\s()<>]+/g;
  for (const match of source.matchAll(pattern)) tokens.push(match[0]);
  return tokens;
}
