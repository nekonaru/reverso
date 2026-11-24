#!/usr/bin/env node
// Local verification pipeline: typecheck, tests with coverage, build, audit.
// Usage: node scripts/verify.mjs [--fast]   (--fast skips the audit)
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

const fast = process.argv.includes("--fast");
const root = process.cwd();

function run(label, cmd, args) {
  console.log(`\n== ${label} ==`);
  execFileSync(cmd, args, { stdio: "inherit" });
}

const nodeBin = process.execPath;
const tsc = join(root, "node_modules", "typescript", "bin", "tsc");
const vitest = join(root, "node_modules", "vitest", "vitest.mjs");

function npmArgs(args) {
  // Prefer the npm CLI JS entry (works without .cmd shims).
  const candidates = [
    process.env.npm_execpath,
    join(process.execPath, "..", "node_modules", "npm", "bin", "npm-cli.js"),
    join(process.execPath, "..", "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ].filter((candidate) => typeof candidate === "string" && existsSync(candidate));
  if (candidates.length > 0) return [nodeBin, [candidates[0], ...args]];
  return [process.platform === "win32" ? "npm.cmd" : "npm", args];
}

try {
  run("typecheck", nodeBin, [tsc, "-p", "tsconfig.json", "--noEmit"]);
  run("tests (with coverage)", nodeBin, [vitest, "run", "--coverage"]);
  run("build", nodeBin, [tsc, "-p", "tsconfig.json"]);
  run("build:web", nodeBin, [join(root, "scripts", "build-web.mjs")]);
  if (!fast) {
    // Audit production dependencies. The dev-only vitest chain currently carries
    // GHSA-fc5q-39xc-vjpf (picomatch ReDoS) with no patched release; it never
    // ships to users and is not reachable with attacker-controlled input here.
    const [cmd, args] = npmArgs(["audit", "--omit=dev", "--audit-level=high"]);
    run("dependency audit (production deps, high severity)", cmd, args);
  }
  console.log("\nverify: OK");
} catch (error) {
  console.error("\nverify: FAILED");
  process.exit(typeof error.status === "number" ? error.status : 1);
}
