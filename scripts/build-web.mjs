#!/usr/bin/env node
// Builds the in-browser analyzer from the same engines used by the CLI.
import { build } from "esbuild";
import { resolve } from "node:path";

const root = process.cwd();
const cryptoShim = resolve(root, "src/browser/crypto.ts");

const common = {
  bundle: true,
  minify: true,
  platform: "browser",
  target: "es2022",
  format: "iife",
  alias: { "node:crypto": cryptoShim },
  logLevel: "warning",
};

await build({
  ...common,
  entryPoints: [resolve(root, "src/browser/worker.ts")],
  outfile: resolve(root, "site/worker.js"),
});

await build({
  ...common,
  format: "esm",
  entryPoints: [resolve(root, "src/browser/index.ts")],
  outfile: resolve(root, "site/analyzer.js"),
});

console.log("build:web OK");
