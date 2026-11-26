/** Native fuzzy hashing inspired by ssdeep: context-triggered piecewise hashes. */
const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PRIME1 = 0x01000193;
const PRIME2 = 0x01000197;
const INIT1 = 311;
const INIT2 = 331;
const MAX_PART = 64;

export interface FuzzyHash {
  blockSize: number;
  hash: string;
  part1: string;
  part2: string;
}

/** Computes a deterministic fuzzy hash. Same bytes always yield the same value. */
export function fuzzyHash(buf: Uint8Array, blockSize = 3): FuzzyHash {
  if (!Number.isInteger(blockSize) || blockSize < 2 || blockSize > 4096) {
    throw new Error("blockSize must be an integer from 2 to 4096");
  }
  let h1 = INIT1;
  let h2 = INIT2;
  let part1 = "";
  let part2 = "";

  for (const byte of buf) {
    h1 = (Math.imul(h1, PRIME1) + byte) >>> 0;
    h2 = (Math.imul(h2, PRIME2) + byte) >>> 0;
    if ((h1 & (blockSize - 1)) === 0) {
      if (part1.length < MAX_PART) part1 += BASE64[h1 & 63];
      if (part2.length < MAX_PART) part2 += BASE64[h2 & 63];
      h1 = INIT1;
      h2 = INIT2;
    }
  }
  if (part1.length === 0) part1 += BASE64[h1 & 63];
  if (part2.length === 0) part2 += BASE64[h2 & 63];

  return { blockSize, hash: `${blockSize}:${part1}:${part2}`, part1, part2 };
}

/** Similarity score from 0 to 100 between two fuzzy hash strings. */
export function fuzzySimilarity(a: string, b: string): number {
  const parse = (value: string): FuzzyHash | null => {
    const parts = value.split(":");
    if (parts.length !== 3) return null;
    const blockSize = Number(parts[0]);
    if (!Number.isFinite(blockSize)) return null;
    return { blockSize, hash: value, part1: parts[1] ?? "", part2: parts[2] ?? "" };
  };
  const left = parse(a);
  const right = parse(b);
  if (!left || !right) return 0;

  const scoreParts = (x: string, y: string): number => {
    const distance = levenshtein(x, y);
    const max = Math.max(x.length, y.length);
    return max === 0 ? 100 : Math.max(0, Math.round((1 - distance / max) * 100));
  };

  const blockScore = left.blockSize === right.blockSize ? 100 : 0;
  return Math.round(blockScore * 0.1 + scoreParts(left.part1, right.part1) * 0.45 + scoreParts(left.part2, right.part2) * 0.45);
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const rows = a.length + 1;
  const cols = b.length + 1;
  const dp = new Uint16Array(rows * cols);
  for (let i = 0; i < rows; i++) dp[i * cols] = i;
  for (let j = 0; j < cols; j++) dp[j] = j;
  for (let i = 1; i < rows; i++) {
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i * cols + j] = Math.min(dp[(i - 1) * cols + j]! + 1, dp[i * cols + j - 1]! + 1, dp[(i - 1) * cols + j - 1]! + cost);
    }
  }
  return dp[rows * cols - 1]!;
}
