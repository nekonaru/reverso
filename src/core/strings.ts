export type StringEncoding = "ascii" | "utf16le";

export type StringCategory =
  | "url"
  | "ipv4"
  | "email"
  | "path-unix"
  | "path-windows"
  | "jwt"
  | "aws-key"
  | "github-token"
  | "slack-token"
  | "google-api-key"
  | "private-key"
  | "assigned-secret";

export interface ExtractedString {
  offset: number;
  encoding: StringEncoding;
  value: string;
  categories: StringCategory[];
}

export interface ExtractOptions {
  minLength?: number;
  maxStrings?: number;
}

const CATEGORY_PATTERNS: Array<{ category: StringCategory; pattern: RegExp }> = [
  { category: "url", pattern: /^https?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{3,}$/ },
  { category: "ipv4", pattern: /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$/ },
  { category: "email", pattern: /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/ },
  { category: "path-unix", pattern: /^\/(?:[A-Za-z0-9._-]+\/){1,}[A-Za-z0-9._-]*$/ },
  { category: "path-windows", pattern: /^[A-Za-z]:\\(?:[^<>:"|?*\\/]+\\?)+$/ },
  { category: "jwt", pattern: /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}$/ },
  { category: "aws-key", pattern: /^(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/ },
  { category: "github-token", pattern: /^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}$|^github_pat_[A-Za-z0-9_]{20,}$/ },
  { category: "slack-token", pattern: /^xox[baprs]-[A-Za-z0-9-]{10,}$/ },
  { category: "google-api-key", pattern: /^AIza[0-9A-Za-z_-]{35}$/ },
  { category: "private-key", pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/ },
  {
    category: "assigned-secret",
    pattern: /(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}/i,
  },
];

export function categorize(value: string): StringCategory[] {
  const categories: StringCategory[] = [];
  for (const { category, pattern } of CATEGORY_PATTERNS) {
    if (pattern.test(value)) categories.push(category);
  }
  return categories;
}

const ASCII_PRINTABLE = (b: number) => b >= 0x20 && b <= 0x7e;

/** Extract printable ASCII strings from a buffer. */
export function extractAsciiStrings(
  buf: Uint8Array,
  minLength: number,
  maxStrings: number,
  into: ExtractedString[],
): void {
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const b = i < buf.length ? buf[i]! : -1;
    if (b !== -1 && ASCII_PRINTABLE(b)) {
      if (start === -1) start = i;
      continue;
    }
    if (start !== -1 && i - start >= minLength) {
      const value = asciiSlice(buf, start, i);
      into.push({ offset: start, encoding: "ascii", value, categories: categorize(value) });
      if (into.length >= maxStrings) return;
    }
    start = -1;
  }
}

/** Extract printable UTF-16LE strings (even byte alignment). */
export function extractUtf16Strings(
  buf: Uint8Array,
  minLength: number,
  maxStrings: number,
  into: ExtractedString[],
): void {
  let start = -1;
  for (let i = 0; i + 1 < buf.length + 1; i += 2) {
    const b0 = i < buf.length ? buf[i]! : -1;
    const b1 = i + 1 < buf.length ? buf[i + 1]! : -1;
    const printable = b1 === 0 && b0 !== -1 && ASCII_PRINTABLE(b0);
    if (printable) {
      if (start === -1) start = i;
      continue;
    }
    if (start !== -1) {
      const length = (i - start) / 2;
      if (length >= minLength) {
        const value = utf16Slice(buf, start, i);
        into.push({ offset: start, encoding: "utf16le", value, categories: categorize(value) });
        if (into.length >= maxStrings) return;
      }
      start = -1;
    }
  }
}

function asciiSlice(buf: Uint8Array, start: number, end: number): string {
  let s = "";
  for (let i = start; i < end; i++) s += String.fromCharCode(buf[i]!);
  return s;
}

function utf16Slice(buf: Uint8Array, start: number, end: number): string {
  let s = "";
  for (let i = start; i < end; i += 2) s += String.fromCharCode(buf[i]!);
  return s;
}

export function extractStrings(buf: Uint8Array, options: ExtractOptions = {}): ExtractedString[] {
  const minLength = options.minLength ?? 4;
  const maxStrings = options.maxStrings ?? 5000;
  const into: ExtractedString[] = [];
  extractAsciiStrings(buf, minLength, maxStrings, into);
  if (into.length < maxStrings) extractUtf16Strings(buf, minLength, maxStrings, into);
  into.sort((a, b) => a.offset - b.offset);
  return into;
}

export interface CategorySummary {
  category: StringCategory;
  count: number;
  samples: string[];
}

/** Summarize categorized strings: counts and capped samples per category. */
export function summarizeCategories(strings: ExtractedString[], maxSamples = 25): CategorySummary[] {
  const byCategory = new Map<StringCategory, { count: number; samples: string[] }>();
  for (const entry of strings) {
    for (const category of entry.categories) {
      let bucket = byCategory.get(category);
      if (!bucket) {
        bucket = { count: 0, samples: [] };
        byCategory.set(category, bucket);
      }
      bucket.count++;
      if (bucket.samples.length < maxSamples && !bucket.samples.includes(entry.value)) {
        bucket.samples.push(entry.value);
      }
    }
  }
  return [...byCategory.entries()]
    .map(([category, { count, samples }]) => ({ category, count, samples }))
    .sort((a, b) => b.count - a.count);
}
