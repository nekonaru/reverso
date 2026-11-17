import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, parseArgs, VERSION } from "../src/cli.js";

let dir: string;
let file: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "reverso-cli-"));
  file = join(dir, "sample.bin");
  await writeFile(file, Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.from("hello\x00", "ascii")]));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function captureStdout(fn: () => Promise<number>): Promise<{ code: number; output: string }> {
  let output = "";
  vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string | Uint8Array) => {
    output += chunk.toString();
    return true;
  }) as typeof process.stdout.write);
  vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string | Uint8Array) => {
    output += chunk.toString();
    return true;
  }) as typeof process.stderr.write);
  return fn().then((code) => ({ code, output }));
}

describe("parseArgs", () => {
  it("parses positionals and flags", () => {
    const { positional, flags } = parseArgs(["analyze", "a.bin", "--format", "md", "--out=report.md"]);
    expect(positional).toEqual(["analyze", "a.bin"]);
    expect(flags.get("format")).toBe("md");
    expect(flags.get("out")).toBe("report.md");
  });

  it("treats flags without values as boolean", () => {
    const { flags } = parseArgs(["site", "https://example.com", "--allow-private"]);
    expect(flags.get("allow-private")).toBe(true);
  });
});

describe("run", () => {
  it("prints help with exit 0", async () => {
    const { code, output } = await captureStdout(() => run(["help"]));
    expect(code).toBe(0);
    expect(output).toContain("reverso");
  });

  it("prints the version", async () => {
    const { code, output } = await captureStdout(() => run(["version"]));
    expect(code).toBe(0);
    expect(output).toContain(VERSION);
  });

  it("reports capabilities", async () => {
    const { code, output } = await captureStdout(() => run(["capabilities"]));
    expect(code).toBe(0);
    expect(output).toContain("reverso_analyze");
  });

  it("runs format on a file", async () => {
    const { code, output } = await captureStdout(() => run(["format", file]));
    expect(code).toBe(0);
    expect(JSON.parse(output).format).toBe("elf64");
  });

  it("runs analyze with markdown output", async () => {
    const { code, output } = await captureStdout(() => run(["analyze", file, "--format", "md"]));
    expect(code).toBe(0);
    expect(output).toContain("# Reverso analysis");
  });

  it("returns 2 for unknown commands", async () => {
    const { code } = await captureStdout(() => run(["definitely-not-a-command"]));
    expect(code).toBe(2);
  });

  it("returns 2 for analyze without files", async () => {
    const { code } = await captureStdout(() => run(["analyze"]));
    expect(code).toBe(2);
  });

  it("returns 3 for layout on an unsupported format", async () => {
    const txt = join(dir, "note.txt");
    await writeFile(txt, "plain text without magic bytes, but long enough to look textual and boring\n".repeat(20));
    const { code } = await captureStdout(() => run(["layout", txt]));
    expect(code).toBe(3);
  });

  it("runs doctor and exits 0 on a healthy runtime", async () => {
    const { code } = await captureStdout(() => run(["doctor"]));
    expect(code).toBe(0);
  });
});
