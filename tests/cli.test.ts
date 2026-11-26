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

  it("runs find-bytes and reports offsets", async () => {
    const { code, output } = await captureStdout(() => run(["find-bytes", file, "7f 45 4c 46"]));
    expect(code).toBe(0);
    expect(JSON.parse(output).offsets).toContain(0);
  });

  it("prints a hex dump", async () => {
    const { code, output } = await captureStdout(() => run(["hex", file, "--length", "8"]));
    expect(code).toBe(0);
    expect(output).toContain("00000000");
  });

  it("scans a directory", async () => {
    const { code, output } = await captureStdout(() => run(["scan", dir, "--max-files", "10"]));
    expect(code).toBe(0);
    expect(JSON.parse(output).filesScanned).toBeGreaterThanOrEqual(1);
  });

  it("returns 3 for wasm on a non-wasm file", async () => {
    const txt = join(dir, "not-wasm.txt");
    await writeFile(txt, "definitely not a wasm module, but long enough to be text\n".repeat(4));
    const { code } = await captureStdout(() => run(["wasm", txt]));
    expect(code).toBe(3);
  });

  it("runs pcap on a capture file", async () => {
    const { makePcap } = await import("./pcap-helper.js");
    const capture = join(dir, "capture.pcap");
    await writeFile(capture, makePcap());
    const { code, output } = await captureStdout(() => run(["pcap", capture]));
    expect(code).toBe(0);
    expect(JSON.parse(output).packets).toBe(3);
  });

  it("returns 3 for pcap on a non-pcap file", async () => {
    const txt = join(dir, "not-pcap.txt");
    await writeFile(txt, "definitely not a pcap file, but long enough to be text\n".repeat(4));
    const { code } = await captureStdout(() => run(["pcap", txt]));
    expect(code).toBe(3);
  });

  it("decodes a JWT inline", async () => {
    const token = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url") + "." +
      Buffer.from(JSON.stringify({ iss: "reverso", sub: "x" })).toString("base64url") + ".sig";
    const { code, output } = await captureStdout(() => run(["jwt", token]));
    expect(code).toBe(0);
    expect(JSON.parse(output).algorithm).toBe("HS256");
  });

  it("returns 3 for jwt on garbage input", async () => {
    const { code } = await captureStdout(() => run(["jwt", "not-a-token"]));
    expect(code).toBe(3);
  });

  it("lists built-in rules", async () => {
    const { code, output } = await captureStdout(() => run(["rules", "list"]));
    expect(code).toBe(0);
    expect(JSON.parse(output).length).toBeGreaterThanOrEqual(10);
  });

  it("matches rules on a file", async () => {
    const { code, output } = await captureStdout(() => run(["match", file]));
    expect(code).toBe(0);
    expect(JSON.parse(output).matches.length).toBeGreaterThan(0);
  });

  it("computes a fuzzy hash", async () => {
    const { code, output } = await captureStdout(() => run(["fuzzy", file]));
    expect(code).toBe(0);
    expect(JSON.parse(output).hash).toMatch(/^\d+:/);
  });
});
