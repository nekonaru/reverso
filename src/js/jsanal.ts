export interface JsSecret {
  type: string;
  match: string;
  line: number;
}

export interface JsObfuscation {
  score: number;
  indicators: string[];
}

export interface JsAnalysis {
  bytes: number;
  lines: number;
  minified: boolean;
  frameworks: string[];
  sourceMapUrl: string | null;
  urls: string[];
  endpoints: string[];
  secrets: JsSecret[];
  obfuscation: JsObfuscation;
  suspiciousCalls: string[];
}

const MAX_URLS = 50;
const MAX_ENDPOINTS = 50;
const MAX_SECRETS = 50;
const MAX_SECRET_MATCH = 120;

const SECRET_PATTERNS: Array<{ type: string; pattern: RegExp }> = [
  { type: "aws-access-key", pattern: /(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}/g },
  { type: "github-token", pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/g },
  { type: "slack-token", pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { type: "google-api-key", pattern: /AIza[0-9A-Za-z_-]{35}/g },
  { type: "jwt", pattern: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g },
  { type: "private-key", pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g },
  {
    type: "assigned-secret",
    pattern: /(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/gi,
  },
];

const FRAMEWORK_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "webpack", pattern: /__webpack_require__|webpackJsonp|webpackChunk|__webpack_modules__/ },
  { name: "react", pattern: /react-dom|__SECRET_INTERNALS_DO_NOT_USE|createElement\(|useState\(/ },
  { name: "vue", pattern: /createApp\(|__VUE__|defineComponent\(|Vue\.component/ },
  { name: "angular", pattern: /ng-version|angular\.module|@angular\/core|platformBrowser/ },
  { name: "next.js", pattern: /__NEXT_DATA__|_next\/static|next\/dist/ },
  { name: "svelte", pattern: /__svelte|svelte\/internal/ },
  { name: "jquery", pattern: /jQuery|\$\(document\)|\.fn\.jquery/ },
  { name: "vite", pattern: /import\.meta\.hot|__vitePreload|\/@vite\// },
];

const OBFUSCATION_INDICATORS: Array<{ name: string; pattern: RegExp; weight: number }> = [
  { name: "eval()", pattern: /\beval\s*\(/g, weight: 25 },
  { name: "atob()", pattern: /\batob\s*\(/g, weight: 10 },
  { name: "new Function()", pattern: /new\s+Function\s*\(/g, weight: 20 },
  { name: "hex-identifier variables", pattern: /_0x[0-9a-fA-F]{4,}/g, weight: 15 },
  { name: "hex escape sequences", pattern: /\\x[0-9a-fA-F]{2}/g, weight: 10 },
  { name: "unicode escape sequences", pattern: /\\u[0-9a-fA-F]{4}/g, weight: 5 },
  { name: "unescape()", pattern: /\bunescape\s*\(/g, weight: 10 },
  { name: "string-array rotation", pattern: /\(\s*["'][A-Za-z0-9+/=]{20,}["']\s*\)\s*;/g, weight: 10 },
];

const utf8Encoder = new TextEncoder();

export function analyzeJavaScript(source: string): JsAnalysis {
  const bytes = utf8Encoder.encode(source).length;
  const lines = source.length === 0 ? 0 : source.split("\n").length;
  const avgLineLength = lines > 0 ? source.length / lines : 0;
  const maxLineLength = source.split("\n").reduce((max, line) => Math.max(max, line.length), 0);
  const minified = avgLineLength > 240 || (bytes > 40 * 1024 && lines < bytes / 400) || maxLineLength > 2000;

  const frameworks = FRAMEWORK_PATTERNS.filter(({ pattern }) => pattern.test(source)).map(({ name }) => name);

  const sourceMapMatch = source.match(/\/\/[#@]\s*sourceMappingURL=([^\s]+)\s*$/m);
  const sourceMapUrl = sourceMapMatch ? sourceMapMatch[1]! : null;

  const urls = dedupe(collect(source, /https?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{4,}/g, MAX_URLS));
  const endpoints = dedupe(collect(
    source,
    /["'`]\/(?:api|v\d+|graphql|rest|auth|oauth|rpc|internal)\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%{}-]{0,120}["'`]/g,
    MAX_ENDPOINTS,
    (m) => m.slice(1, -1),
  ));

  const lineStarts = computeLineStarts(source);
  const secrets: JsSecret[] = [];
  for (const { type, pattern } of SECRET_PATTERNS) {
    for (const match of source.matchAll(pattern)) {
      const value = match[0]!.slice(0, MAX_SECRET_MATCH);
      secrets.push({ type, match: value, line: lineOf(lineStarts, match.index ?? 0) });
      if (secrets.length >= MAX_SECRETS) break;
    }
    if (secrets.length >= MAX_SECRETS) break;
  }

  const indicators: string[] = [];
  let score = 0;
  for (const { name, pattern, weight } of OBFUSCATION_INDICATORS) {
    const matches = source.match(pattern);
    if (matches && matches.length > 0) {
      indicators.push(`${name} x${matches.length}`);
      score += weight * Math.min(matches.length, 10) * 0.25 + weight * 0.5;
    }
  }
  score = Math.min(100, Math.round(score));

  const suspiciousCalls = [
    /\beval\s*\(/.test(source) ? "eval" : null,
    /new\s+Function\s*\(/.test(source) ? "new Function" : null,
    /\batob\s*\(/.test(source) ? "atob" : null,
    /document\.cookie/.test(source) ? "document.cookie" : null,
    /localStorage\.(get|set)Item/.test(source) ? "localStorage" : null,
    /navigator\.sendBeacon/.test(source) ? "navigator.sendBeacon" : null,
  ].filter((x): x is string => x !== null);

  return {
    bytes,
    lines,
    minified,
    frameworks,
    sourceMapUrl,
    urls,
    endpoints,
    secrets,
    obfuscation: { score, indicators },
    suspiciousCalls,
  };
}

function collect(source: string, pattern: RegExp, max: number, transform: (m: string) => string = (m) => m): string[] {
  const out: string[] = [];
  for (const match of source.matchAll(pattern)) {
    out.push(transform(match[0]!));
    if (out.length >= max) break;
  }
  return out;
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

function computeLineStarts(source: string): number[] {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

function lineOf(lineStarts: number[], index: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}
