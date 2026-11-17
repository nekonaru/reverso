# Changelog

## v1.1.0

Big introspection update: whole-directory triage, structural binary diffing,
byte-level search, and native WebAssembly and Android DEX inspectors.

### New features

- **Directory triage.** `reverso scan <dir>` recursively analyzes every file
  (skipping node_modules, .git and dist), with a format breakdown, per-file
  SHA-256, entropy and packer signals.
- **Binary diff.** `reverso diff <a> <b>` compares size, entropy, hardening
  traits, sections, imports, exports and string categories between two files.
- **Byte search and hex dump.** `reverso find-bytes` locates hex patterns
  (`4d 5a ?? 60`) with wildcards; `reverso hex` prints a classic hex dump.
- **WebAssembly inspector.** `reverso wasm` parses the binary format: sections,
  types, imports, exports, counts and the name section.
- **Android DEX inspector.** `reverso dex` parses the header, checksum and
  the categorized string table (URLs, AWS keys, class descriptors, more).
- **Six new MCP tools.** `reverso_scan`, `reverso_diff`, `reverso_find_bytes`,
  `reverso_hex`, `reverso_wasm`, `reverso_dex` (14 tools total).

### Improvements

- **Audit hardening and performance.** Bulk `TextDecoder` string extraction,
  single-source version constant, symlink-aware CLI launch detection for npm
  bin shims, executable bit on `dist/cli.js` via postbuild, numeric flags
  clamped to sane ranges, `capabilities` derived from the tool registry.
- **Richer diff signals.** ELF, PE and Mach-O hardening traits (PIE, RELRO,
  canary, stripped, ASLR, CFG, ...) are compared explicitly.

### Bug fixes

- **Boolean flags from strings.** `--allow-private true` now parses as true;
  previously it silently left the guard enabled.
- **Corrupt archives.** A malformed ZIP EOCD no longer reaches the parser
  unchecked; the archive section is omitted instead of crashing.
- **Capabilities drift.** The MCP tool list in `capabilities` is now generated
  from the registry instead of a stale hardcoded list.

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
