/** Optional user config at ~/.reverso/config.json. Missing or invalid files are ignored. */
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

export interface ReversoConfig {
  scan?: { maxFiles?: number };
  strings?: { minLength?: number };
  rules?: string;
  format?: string;
}

export async function loadConfig(): Promise<ReversoConfig> {
  try {
    const raw = await readFile(join(homedir(), ".reverso", "config.json"), "utf8");
    const parsed = JSON.parse(raw) as ReversoConfig;
    if (typeof parsed !== "object" || parsed === null) return {};
    return {
      ...(typeof parsed.scan?.maxFiles === "number" ? { scan: { maxFiles: parsed.scan.maxFiles } } : {}),
      ...(typeof parsed.strings?.minLength === "number" ? { strings: { minLength: parsed.strings.minLength } } : {}),
      ...(typeof parsed.rules === "string" ? { rules: parsed.rules } : {}),
      ...(typeof parsed.format === "string" ? { format: parsed.format } : {}),
    };
  } catch {
    return {};
  }
}
