# Changelog

## v1.0.0

First stable release. Reverso triages unknown files natively, with no external
analysis tools, from one CLI or one MCP server.

### New features

- **Full triage report.** `reverso analyze` produces hashes, entropy, format,
  strings, layout, hardening, archive listing and JavaScript analysis in one
  JSON or Markdown report.
- **Binary parsing.** Native ELF, PE and Mach-O parsers (sections, program
  headers, imports, exports) plus hardening checks: PIE, NX stack, stack
  canary, RELRO, FORTIFY, ASLR, NX compat, Control Flow Guard and Authenticode.
- **JavaScript analysis.** Minification detection, obfuscation score with
  indicators, framework fingerprints, source map detection, URL, API endpoint
  and secret extraction.
- **Website mirror.** `reverso site <url>` mirrors a site locally, same
  origin, with relative link rewriting, a private-address guard (literal IPs
  and DNS answers), per-file and total byte caps, and streamed body reading.
- **MCP server.** `reverso mcp` exposes all analyzers as Model Context
  Protocol tools over stdio (protocol `2025-06-18`).
- **String intelligence.** ASCII and UTF-16LE strings categorized as URLs,
  IPv4, emails, paths, JWTs, AWS keys, GitHub tokens, Slack tokens, Google
  API keys, private keys and assigned secrets.
- **Archive inventory.** ZIP/APK/IPA/JAR listing with type detection and
  suspicious entry flagging.

### Improvements

- **Zero runtime dependencies.** The package ships with nothing to install or
  audit at runtime.
- **Output caps everywhere.** 256 MiB input cap for files, 64 MiB over MCP,
  5000 extracted strings, 5000 archive entries.
- **Enforced verification.** Strict TypeScript, 84 tests with coverage
  thresholds, production dependency audit and a secret scan in CI, on Ubuntu
  and Windows, Node 22 and 24.

### Bug fixes

- **Mirror memory cap.** Response bodies are now streamed and aborted past
  the per-file cap instead of being buffered first.
- **Archive robustness.** Malformed ZIP files no longer abort the whole
  report; the archive section is omitted instead.

## v0.1.0

Initial development snapshot. Core analysis engines, CLI skeleton and MCP
server, before the release hardening pass.
