# Changelog

## v2.1.0

Six new native format inspectors, plus richer PCAP and WebAssembly details.

### New features

- **PDF inspector.** `reverso pdf` reports objects, encryption, JavaScript, OpenAction, embedded files, URIs and metadata without rendering the document.
- **OOXML inspector.** `reverso ooxml` detects DOCX, XLSX and PPTX, external relationships, VBA projects and document text.
- **PyInstaller inspector.** `reverso pyinstaller` decodes the CArchive cookie, Python version and table of contents.
- **Windows shortcut inspector.** `reverso lnk` reports flags, attributes, target paths, arguments, working directory and timestamps.
- **DotNet inspector.** `reverso dotnet` reads CLI metadata streams and string samples from managed assemblies.
- **EVM disassembler.** `reverso evm` decodes opcodes and collects PUSH4 selector candidates from hex bytecode or a file.
- **PCAP enrichment.** DNS query names and HTTP request lines are now extracted from captures.
- **WASM producers.** The custom `producers` section is decoded into language and tool entries.

### Improvements

- Six new MCP tools (`reverso_pdf`, `reverso_ooxml`, `reverso_pyinstaller`, `reverso_lnk`, `reverso_dotnet`, `reverso_evm`) bringing the total to 24.
- Five of the new inspectors also run in the browser and over the HTTP API. OOXML is Node only because it needs zlib.

## v2.0.0

Milestone release: a versioned report schema, a job based public API and hardened hosted operation.

### New features

- **Report schema v2.** Every analysis report carries `schemaVersion: "2.0"`. The field is additive, so existing consumers can ignore it.
- **Job API.** `POST /api/jobs` returns a pollable job id; `GET /api/jobs/<id>` returns the result. Jobs are retained for ten minutes with a bounded queue.
- **Rule pack endpoint.** `GET /api/rules` serves the built-in rule pack for agents and the web UI.
- **Host hardening.** `REVERSO_API_KEY` requires an API key on `/api` and `/mcp`; `REVERSO_RATE_LIMIT` caps requests per client IP per minute with HTTP 429 and `Retry-After`.
- **MCP sessions.** `initialize` issues an `Mcp-Session-Id` header; later requests echo it and unknown sessions are rejected.

### Improvements

- 193 tests pass, including job creation, rate-limit behavior, MCP sessions and fuzz coverage.
- `docs/online.md` documents the complete hosted setup.

## v1.8.0

Investigation workflows and report exports, with a fuzz corpus in CI.

### New features

- **Directory baselines.** `reverso baseline create <dir>` records SHA-256, size and format per file. `reverso baseline verify <dir>` reports added, removed, changed and unchanged files, with JSON or Markdown output and a non-zero exit code when differences exist.
- **Investigation cases.** `reverso case create/add/report` stores evidence with hash, size, format, timestamp and notes in a single JSON file.
- **Report exports.** `reverso analyze --format sarif` emits SARIF 2.1.0 for CI, `--format html` produces a standalone styled report, and `reverso scan --format csv` produces a spreadsheet-ready inventory.
- **Fuzz corpus.** CI now runs deterministic random and truncated inputs through `analyzeBuffer` and the individual parsers.

### Improvements

- The in-browser analyzer keeps the last ten analyses in browser-local storage and lets you restore any result with one click. No data leaves the browser.

## v1.7.0

Rule matching, fuzzy similarity and deeper build inventories, all native.

### New features

- **YARA-lite rule engine.** `reverso match` applies a built-in pack (or a JSON pack via `--rules`) with hex, text and regex patterns. Conditions support labels, `N of them`, `and/or/not`, parentheses, `filesize` and `entropy`, parsed by a small safe interpreter, never `eval`.
- **Fuzzy hashing.** `reverso fuzzy` computes an ssdeep-style context-triggered hash. `reverso diff` reports a 0 to 100 similarity score and both hashes.
- **PE version info.** File and product versions are extracted from UTF-16 `VS_VERSIONINFO` resources when present.
- **ELF relocation and dependency inventory.** `DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH` and REL/RELA counts are reported.
- **Mach-O dylibs and rpaths.** Load commands for dynamic libraries and rpaths are decoded into readable lists.

### Improvements

- `reverso rules list` prints the built-in pack; `reverso match` supports JSON and Markdown output.
- Two new MCP tools, `reverso_match` and `reverso_fuzzy`, plus browser and HTTP API support.

## v1.6.0

Deeper native inspection of dynamic dependencies, build paths and universal binaries. Audited against real Windows binaries.

### New features

- **ELF dependencies.** `reverso layout` resolves `DT_NEEDED`, `DT_RPATH` and `DT_RUNPATH` through `DT_STRTAB`, mapping virtual addresses to file offsets via `PT_LOAD` segments.
- **PE delay imports.** The delay-load import directory is decoded into the same import list structure as regular imports (RVA and VA descriptor forms).
- **PDB path.** CodeView debug entries are decoded to recover the build machine's PDB path and the number of debug directories.
- **DEX classes.** `reverso dex` resolves `class_defs` through `type_ids` into readable class descriptors.
- **Universal Mach-O slices.** Fat binaries now report each slice's CPU, bitness, file type, segments and UUID, with bounds checks and per-slice errors.

### Bug fixes

- **Fat binary header stride.** 64-bit fat Mach-O headers use 32-byte architecture entries, not 20-byte entries. The previous parser misread CPU types and slice offsets on fat64 files; it now uses the correct layout for both variants.

### Improvements

- Markdown reports show needed libraries, RPATH/RUNPATH, delay imports, PDB paths, DEX class lists and per-slice Mach-O details.

## v1.5.0

Reverso becomes usable online: in the browser with no install, or through a small hosted API and MCP service.

### New features

- **In-browser analyzer.** The project website now has a "Try Reverso online" section with 15 analyzers, a Web Worker, a 64 MB per-file cap and copy/download controls. Files stay in the browser and are never uploaded.
- **HTTP API.** `POST /api/analyze?tool=<name>` accepts a raw file body and returns the same JSON as the CLI. `GET /health` supports health checks. CORS is enabled and the request body is capped at 8 MB by default.
- **Remote MCP.** `POST /mcp` answers stateless JSON-RPC over JSON or server-sent events. Every file tool accepts inline base64 `content`; `reverso_diff` accepts `contentA` and `contentB`.
- **Hosting kit.** `Dockerfile`, `render.yaml` free-tier blueprint and `npm start` run the website, API and remote MCP in one Node process. See `docs/online.md`.

### Improvements

- **Shared engines.** The analysis engine is split into a platform-neutral core, so the CLI, MCP, browser and HTTP API all produce identical results without duplicated logic.
- **Build pipeline.** `npm run build:web` bundles the browser analyzer, and `npm run verify` now checks it on every push.

## v1.4.0

Build provenance and appended-data forensics, validated on real Windows binaries.

### New features

- **PE Rich fingerprint.** The Rich header in the DOS stub is XOR-decoded into compiler entries (product, build, count) and reduced to a deterministic `richHash`. `reverso diff` reports changes to it.
- **Authenticode file digest.** PE reports now include SHA-1 and SHA-256 file digests computed with the checksum field and certificate directory entry zeroed and the certificate table excluded.
- **ELF build-id.** GNU build-id is extracted from `SHT_NOTE` sections when present; `reverso diff` reports changes.
- **Mach-O UUID.** `LC_UUID` is decoded into a canonical UUID string; `reverso diff` reports changes.
- **Overlay detection.** PE and ELF reports show the size and SHA-256 of data appended after the last section's raw data.

### Improvements

- **Rich marker alignment.** The Rich header scan now handles markers at any byte offset in the DOS stub, which is the common case for real Microsoft binaries.
- **Note alignment.** ELF note fields are aligned relative to the note record rather than absolute file offsets, so oddly aligned note sections still decode.

## v1.3.0

Forensic depth for binaries and captures: the PE import hash, per-section entropy, and native PCAP and JWT inspection.

### New features

- **PE import hash.** `reverso layout` reports the PE import hash (`imphash`), computed from the import descriptor in appearance order.
- **Per-section entropy.** ELF and PE section listings now carry per-section Shannon entropy; the report flags sections above 7.0 bits as packing candidates.
- **PCAP inspector.** `reverso pcap <file>` parses classic PCAP captures: version, snaplen, link type, packet count, duration, protocol breakdown, top talkers and top destination ports. pcapng is detected and refused with guidance.
- **JWT decoder.** `reverso jwt <token|file>` decodes header and payload, converts `iat`/`nbf`/`exp` to ISO dates, flags expired tokens, `alg=none`, sensitive claims and missing `exp`. The signature is never verified, by design.
- **Two new MCP tools.** `reverso_pcap` and `reverso_jwt` (16 tools total).

### Improvements

- **ELF strict magic validation.** `parseElf` now throws on invalid `EI_CLASS`/`EI_DATA` instead of analyzing garbage.
- **Layout resilience.** `reverso layout` exits 3 with a clear message when a binary cannot be parsed, instead of an unhandled error.

## v1.2.0

A new mark, and a public home for the project.

### New features

- **New mark.** Adopted the owner-provided mark: a split hexagon dissolving into bytes. The logo kit (tile, transparent, mono ink/gold/white, favicons, app icons, lockups, both colour lockups) ships under `assets/logo/`.
- **Project website.** Landing site at [nekonaru.github.io/reverso](https://nekonaru.github.io/reverso/): overview, install instructions, MCP configuration and FAQ, deployed automatically to GitHub Pages on every push that touches `site/`.

### Improvements

- **Documentation.** READMEs link the project site; repository homepage updated.

## v1.1.1

Internal cleanup release. No behaviour change.

### Bug fixes

- **Comment punctuation.** One comment contained an em dash; replaced with a comma. No code, API or output change.

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
