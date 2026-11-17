/** Shannon entropy of a byte buffer, in bits per byte (0 to 8). */
export function shannonEntropy(buf: Uint8Array): number {
  if (buf.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < buf.length; i++) counts[buf[i]!]!++;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / buf.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export interface EntropyWindow {
  offset: number;
  size: number;
  entropy: number;
}

/**
 * Sliding window entropy over the buffer. Returns only windows at or above
 * `threshold` (default 7.0), which usually indicates packed or encrypted
 * regions. Windows overlap by half the window size.
 */
export function highEntropyWindows(
  buf: Uint8Array,
  windowSize = 4096,
  threshold = 7.0,
  maxWindows = 64,
): EntropyWindow[] {
  const results: EntropyWindow[] = [];
  if (buf.length < windowSize || windowSize <= 0) return results;
  const step = Math.floor(windowSize / 2);
  for (let offset = 0; offset + windowSize <= buf.length; offset += step) {
    const entropy = shannonEntropy(buf.subarray(offset, offset + windowSize));
    if (entropy >= threshold) {
      results.push({ offset, size: windowSize, entropy: round3(entropy) });
      if (results.length >= maxWindows) break;
    }
  }
  return results;
}

export function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}
