/** Byte-level helpers: hex pattern search and hex dumps. */

export interface FindBytesResult {
  pattern: string;
  offsets: number[];
  totalMatches: number;
  truncated: boolean;
}

/**
 * Parses a hex pattern such as "4d 5a 90 00" or "4d5a9000" or "4d5a??9000".
 * Supports "??", "*" and "xx" (case-insensitive) as single-byte wildcards.
 * Throws on any invalid token.
 */
export function parseHexPattern(input: string): Array<number | null> {
  const tokens = input.trim().split(/\s+/).filter((t) => t.length > 0);
  if (tokens.length === 0) throw new Error("Empty pattern");

  const expanded: string[] = [];
  for (const token of tokens) {
    const lower = token.toLowerCase();
    if (lower === "??" || lower === "*" || lower === "xx") {
      expanded.push("??");
      continue;
    }
    if (/^[0-9a-f]{2}$/.test(lower)) {
      expanded.push(lower);
      continue;
    }
    // Contiguous form: "4d5a??90" — pairs only, hex digits and wildcards.
    if (/^([0-9a-f?*]{2})+$/.test(lower)) {
      for (let i = 0; i + 2 <= lower.length; i += 2) {
        const pair = lower.slice(i, i + 2);
        expanded.push(pair === "??" || pair === "**" ? "??" : pair);
      }
      continue;
    }
    throw new Error(`Invalid hex pattern token: ${token}`);
  }

  if (expanded.length > 64) throw new Error("Pattern too long (max 64 bytes)");

  return expanded.map((token) => (token === "??" ? null : parseInt(token, 16)));
}

/** Finds every occurrence of a hex pattern in a buffer, with a cap on returned offsets. */
export function findPattern(buf: Uint8Array, patternInput: string, maxResults = 32): FindBytesResult {
  const pattern = parseHexPattern(patternInput);
  if (pattern.length > buf.length) {
    return { pattern: patternInput.trim(), offsets: [], totalMatches: 0, truncated: false };
  }

  // Anchor on the first literal byte to avoid scanning every alignment.
  const anchor = pattern.findIndex((p) => p !== null);
  const anchorByte = anchor === -1 ? null : pattern[anchor]!;

  const offsets: number[] = [];
  let totalMatches = 0;

  const matchesAt = (i: number): boolean => {
    for (let j = 0; j < pattern.length; j++) {
      const expected = pattern[j];
      if (expected !== null && buf[i + j] !== expected) return false;
    }
    return true;
  };

  for (let i = 0; i + pattern.length <= buf.length; i++) {
    if (anchorByte !== null && buf[i + anchor] !== anchorByte) continue;
    if (matchesAt(i)) {
      totalMatches++;
      if (offsets.length < maxResults) offsets.push(i);
    }
  }

  return {
    pattern: patternInput.trim(),
    offsets,
    totalMatches,
    truncated: offsets.length < totalMatches,
  };
}

/** Formats a buffer region as a classic hex dump with ASCII gutter. */
export function hexDump(buf: Uint8Array, offset: number, length: number, width = 16): string {
  const safeWidth = Math.min(Math.max(Math.floor(width), 1), 64);
  const start = Math.min(Math.max(Math.floor(offset), 0), buf.length);
  const end = Math.min(start + Math.max(Math.floor(length), 0), buf.length);
  const lines: string[] = [];

  for (let pos = start; pos < end; pos += safeWidth) {
    const chunk = buf.subarray(pos, Math.min(pos + safeWidth, end));
    const hexParts: string[] = [];
    for (let i = 0; i < safeWidth; i++) {
      if (i < chunk.length) hexParts.push(chunk[i]!.toString(16).padStart(2, "0"));
      else hexParts.push("  ");
      if (i === safeWidth / 2 - 1) hexParts.push("");
    }
    const ascii = [...chunk].map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${pos.toString(16).padStart(8, "0")}  ${hexParts.join(" ")}  |${ascii}|`);
  }

  return lines.join("\n");
}
