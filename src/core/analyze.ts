/** Node.js file wrapper around the platform-neutral analysis engine. */
import { readFile, stat } from "node:fs/promises";
export { analyzeBuffer, MAX_INPUT_BYTES } from "./analyze-buffer.js";
export type { AnalysisReport } from "./analyze-buffer.js";
import { analyzeBuffer, MAX_INPUT_BYTES } from "./analyze-buffer.js";
import type { AnalysisReport } from "./analyze-buffer.js";

export async function analyzeFile(filePath: string): Promise<AnalysisReport> {
  const fileStat = await stat(filePath);
  if (!fileStat.isFile()) throw new Error(`Not a regular file: ${filePath}`);
  if (fileStat.size > MAX_INPUT_BYTES) {
    throw new Error(`File too large for analysis (${fileStat.size} bytes, limit ${MAX_INPUT_BYTES})`);
  }
  const buf = await readFile(filePath);
  return analyzeBuffer(buf, filePath);
}
