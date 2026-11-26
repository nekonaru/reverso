/** Built-in rule pack. Usable everywhere, including the browser and remote API. */
import { parseRule } from "./engine.js";
import type { Rule } from "./types.js";

const RAW: unknown[] = [
  {
    id: "packer-upx",
    name: "UPX packed binary",
    description: "UPX stub strings or compressed section names",
    severity: "medium",
    tags: ["packer"],
    patterns: [
      { kind: "text", value: "UPX!", label: "stub" },
      { kind: "text", value: ".upx", label: "section" },
    ],
    condition: "any of them",
  },
  {
    id: "packer-pyinstaller",
    name: "PyInstaller bundle",
    description: "Python standalone bundle markers",
    severity: "info",
    tags: ["packer", "python"],
    patterns: [
      { kind: "text", value: "PyInstaller", label: "brand" },
      { kind: "text", value: "pyi-", label: "archive" },
      { kind: "hex", value: "4d 45 49 0e 0e 0a 0b 0a", label: "cookie" },
    ],
    condition: "any of them",
  },
  {
    id: "runtime-electron",
    name: "Electron application",
    description: "Electron ASAR archive markers",
    severity: "info",
    tags: ["runtime"],
    patterns: [
      { kind: "text", value: "app.asar", label: "asar" },
      { kind: "text", value: "ELECTRON_RUN_AS_NODE", label: "env" },
    ],
    condition: "any of them",
  },
  {
    id: "runtime-go",
    name: "Go binary",
    description: "Go runtime markers",
    severity: "info",
    tags: ["runtime"],
    patterns: [
      { kind: "text", value: "go1.", label: "version" },
      { kind: "text", value: "Go build", label: "build" },
      { kind: "text", value: "runtime.main", label: "entry" },
    ],
    condition: "any of them",
  },
  {
    id: "runtime-rust",
    name: "Rust binary",
    description: "Rust runtime markers",
    severity: "info",
    tags: ["runtime"],
    patterns: [
      { kind: "text", value: "rust_begin_unwind", label: "unwind" },
      { kind: "text", value: "rustc", label: "compiler" },
    ],
    condition: "any of them",
  },
  {
    id: "runtime-dotnet",
    name: "DotNet assembly",
    description: "CLI metadata stream signature",
    severity: "info",
    tags: ["runtime"],
    patterns: [
      { kind: "text", value: "BSJB", label: "metadata" },
      { kind: "text", value: ".NETFramework", label: "framework" },
    ],
    condition: "any of them",
  },
  {
    id: "secret-private-key",
    name: "PEM private key",
    description: "PEM encoded private key material",
    severity: "high",
    tags: ["secret"],
    patterns: [
      { kind: "text", value: "-----BEGIN", label: "begin" },
      { kind: "text", value: "PRIVATE KEY-----", label: "key" },
    ],
    condition: "all of them",
  },
  {
    id: "secret-jwt",
    name: "JWT token",
    description: "Three-segment base64url token",
    severity: "medium",
    tags: ["secret"],
    patterns: [
      { kind: "regex", value: "eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{4,}", label: "token" },
    ],
    condition: "them",
  },
  {
    id: "network-url",
    name: "Embedded URL",
    description: "HTTP or HTTPS URL embedded in the file",
    severity: "info",
    tags: ["network"],
    patterns: [
      { kind: "regex", value: "https?://[^\\s\"']{4,}", label: "url" },
    ],
    condition: "them",
  },
  {
    id: "heuristic-high-entropy",
    name: "Very high entropy",
    description: "Likely packed, compressed or encrypted content",
    severity: "low",
    tags: ["heuristic"],
    patterns: [{ kind: "hex", value: "00", label: "anchor" }],
    condition: "entropy > 7.2",
  },
  {
    id: "script-eval",
    name: "Dynamic evaluation",
    description: "eval or Function constructor usage in a script",
    severity: "medium",
    tags: ["script"],
    patterns: [
      { kind: "text", value: "eval(", label: "eval" },
      { kind: "text", value: "new Function(", label: "function" },
    ],
    condition: "any of them",
  },
];

export const DEFAULT_RULES: Rule[] = RAW.map(parseRule);
