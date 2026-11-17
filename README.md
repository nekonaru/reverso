# Reverso

[![CI](https://github.com/nekonaru/reverso/actions/workflows/ci.yml/badge.svg)](https://github.com/nekonaru/reverso/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%5E22.23.4%20%7C%7C%20%5E24.22.1-339933.svg)](https://nodejs.org/)

**A native-first reverse engineering toolkit.** Static analysis of binaries,
JavaScript bundles and websites from one CLI or one MCP server, with zero
runtime dependencies and no proprietary tools required.

*[Baca versi Bahasa Indonesia](README.id.md)*

Reverso is an independent project. It is a reimplementation informed by a study
of publicly available reverse engineering tooling; no source code from other
projects is included. Use it only on files and systems you are authorized to
analyze.

## What you can do

| Command | What it does |
| --- | --- |
| `reverso analyze <file>` | Full triage report: hashes, entropy, format, strings, layout, hardening, archive listing, JavaScript analysis |
| `reverso format <file>` | Magic-byte format detection: ELF, PE, Mach-O, ZIP, APK, IPA, JAR, WASM, DEX, PCAP and more |
| `reverso layout <file>` | Structural layout for ELF, PE and Mach-O: sections, program headers, imports, exports |
| `reverso hardening <file>` | Hardening checks: PIE, NX stack, stack canary, RELRO, FORTIFY, ASLR, NX compat, Control Flow Guard, Authenticode |
| `reverso strings <file>` | Printable ASCII and UTF-16LE strings, categorized (URLs, IPv4, emails, JWTs, keys, assigned secrets) |
| `reverso entropy <file>` | Shannon entropy with high-entropy region detection (packed or encrypted areas) |
| `reverso archive <file>` | ZIP/APK/IPA/JAR entry listing with type detection and suspicious-entry flagging |
| `reverso js <file>` | JavaScript bundle analysis: minification, obfuscation score, frameworks, source maps, URLs, API endpoints, secrets |
| `reverso site <url>` | Mirror a website locally, same origin, with link rewriting and a private-address guard |
| `reverso mcp` | Start the MCP stdio server exposing every analyzer as a tool |
| `reverso doctor` | Check the runtime environment |
| `reverso capabilities` | List every analyzer, command and MCP tool |

Everything runs offline. Analysis requires no network, no Ghidra, no Hopper,
no IDA, no license server.

## Requirements

- Node.js `^22.23.4 || ^24.22.1 || >=26.12.1`
- No native addons, no Python, no external tools

## Install

From source (the supported method today):

```bash
git clone https://github.com/nekonaru/reverso.git
cd reverso
npm ci
npm run build
npm link        # puts `reverso` on your PATH
```

Then:

```bash
reverso doctor
```

## Quick start

```bash
# Triage an unknown binary
reverso analyze ./target.bin

# Same report as Markdown, written to a file
reverso analyze ./target.bin --format md --out report.md

# Binary structure and hardening
reverso layout ./target.elf
reverso hardening ./win32.exe

# What kind of file is this?
reverso format ./mystery.bin

# Endpoint and secret inventory of a web bundle
reverso js ./app.min.js

# Mirror a site for offline analysis (stays on the same origin)
reverso site https://example.com --out ./mirror --max-pages 200

# JSON for scripting
reverso strings ./firmware.bin --min-length 6 | jq '.categories'
```

## Use Reverso from an MCP client

`reverso mcp` speaks [Model Context Protocol](https://modelcontextprotocol.io/)
over stdio (protocol `2025-06-18`). Add it to your client:

```json
{
  "mcpServers": {
    "reverso": {
      "command": "node",
      "args": ["/path/to/reverso/dist/cli.js", "mcp"]
    }
  }
}
```

Or, if the package is installed globally:

```json
{
  "mcpServers": {
    "reverso": {
      "command": "reverso",
      "args": ["mcp"]
    }
  }
}
```

Tools exposed:

| Tool | Inputs | Returns |
| --- | --- | --- |
| `reverso_analyze` | `path` | Full static analysis report (JSON) |
| `reverso_strings` | `path`, `minLength?` | Strings with categories (JSON) |
| `reverso_entropy` | `path` | Shannon entropy and high-entropy regions (JSON) |
| `reverso_format` | `path` | Format detection (JSON) |
| `reverso_layout` | `path` | ELF/PE/Mach-O structure (JSON) |
| `reverso_hardening` | `path` | Hardening checks (JSON) |
| `reverso_archive_list` | `path` | ZIP/APK/IPA/JAR listing (JSON) |
| `reverso_js_analyze` | `path` or inline `source` | JavaScript analysis (JSON) |

## Safety notes

- **Files are analyzed read-only.** Reverso never executes the target.
- **The website mirror stays on the start origin** and refuses to fetch
  loopback, private, link-local and reserved addresses (both literal IPs and
  DNS answers) unless you pass `--allow-private` explicitly.
- **Output size is capped.** Inputs are limited to 256 MiB, extracted strings
  to 5000, archive entries to 5000, and MCP reads to 64 MiB.

Use Reverso only on targets you are authorized to analyze.

## Development

```bash
npm ci
node scripts/verify.mjs   # typecheck + tests with coverage + build + audit
npm test                  # tests only
npm run test:coverage     # tests with coverage thresholds
```

Coverage thresholds are enforced (70% lines, 60% branches). The CI pipeline
runs the same verification on Ubuntu and Windows, on Node 22 and 24, plus a
secret scan. Branch protection requires all of them green.

Project layout:

```text
src/
├── core/      # format detection, entropy, hashes, strings, orchestrator, report
├── binary/    # ELF / PE / Mach-O parsers and hardening checks
├── archive/   # ZIP-family parser (APK/IPA/JAR detection)
├── js/        # JavaScript bundle analysis
├── web/       # website mirror (same origin, private-address guard)
├── mcp/       # MCP stdio server
└── cli.ts     # command dispatcher (thin layer over the engines)
tests/         # unit and integration tests (vitest)
docs/specs/    # testable specifications
```

The specification with done criteria lives in [docs/specs/core.md](docs/specs/core.md).

## Limitations

- Reverso performs **static** analysis. It does not decompile to pseudocode;
  it parses, inventories and scores. For interactive decompilation, point a
  decompiler at the file yourself and use Reverso for triage, extraction and
  reporting.
- The JavaScript analysis is heuristic (regex and pattern based), like all
  static JS analysis. Obfuscation scores are indicators, not proof.
- Website mirroring respects the same-origin policy by design; it will not
  crawl a whole domain.

## License

MIT. See [LICENSE](LICENSE).
