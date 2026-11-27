#!/usr/bin/env node
// Generates a minimal CycloneDX-style SBOM from the committed lock file.
import { readFile, writeFile } from "node:fs/promises";

const lock = JSON.parse(await readFile("package-lock.json", "utf8"));
const root = JSON.parse(await readFile("package.json", "utf8"));
const packages = Object.entries(lock.packages ?? {});

const components = packages
  .filter(([path]) => path !== "")
  .map(([path, meta]) => ({
    type: "library",
    name: path.split("node_modules/").pop() ?? path,
    version: meta.version ?? "unknown",
    "scope": meta.dev ? "excluded" : "runtime",
  }));

const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    component: { type: "application", name: root.name, version: root.version },
    tools: [{ name: "reverso-sbom", version: "1.0.0" }],
  },
  components,
};

await writeFile("sbom.json", JSON.stringify(sbom, null, 2) + "\n");
console.log(`sbom: ${components.length} components written`);
