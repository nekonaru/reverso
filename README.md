<div align="center">

<img src="assets/logo/symbol-tile.svg" width="120" alt="Reverso logo">

# Reverso: Native reverse engineering toolkit

<p><b>One CLI and one MCP server for static reverse engineering.<br/>
Binaries, JavaScript bundles and websites, analyzed offline, with zero
dependencies.</b></p>

<a href="https://github.com/nekonaru/reverso/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/nekonaru/reverso?style=flat-square"></a>
<a href="https://github.com/nekonaru/reverso/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/nekonaru/reverso/ci.yml?branch=main&style=flat-square"></a>
<a href="https://nodejs.org/"><img alt="Node.js" src="https://img.shields.io/badge/node-%5E22.23.4%20%7C%7C%20%5E24.22.1%20%7C%7C%20%3E%3D26.12.1-339933?style=flat-square"></a>
<a href="https://github.com/nekonaru/reverso"><img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-101E26?style=flat-square"></a>
<a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-f4c430?style=flat-square"></a>

</div>

<br />

**English** | [Bahasa Indonesia](README.id.md)

> [!NOTE]
> Use Reverso only on files, applications and websites you are authorized to analyze.

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Development](#development)
- [Testing](#testing)
- [Security](#security)
- [Continuous Integration](#continuous-integration)
- [FAQ](#faq)
- [Author](#author)
- [License](#license)

---

## About

Reverso is a native-first reverse engineering toolkit for developers, security
researchers and agentic tooling. It triages unknown binaries, inventories
JavaScript bundles, and mirrors websites for offline analysis, from one command
or one MCP server. Everything runs locally: no Ghidra, Hopper, IDA, Python or
license server is required for the built-in analyzers, and the package ships
with zero runtime dependencies. Visit
[the project site](https://nekonaru.github.io/reverso/) for a quick overview.

> _"Analyze anything, install nothing."_

---

## Features

### Analysis engines

| Feature | Description |
| --- | --- |
| **Full triage report** | `reverso analyze <file>`: hashes, size, entropy, format, strings, layout, hardening, archive listing and JavaScript analysis in one report, as JSON or Markdown |
| **Format detection** | Magic-byte detection for ELF, PE, Mach-O, ZIP (APK/IPA/JAR), WASM, DEX, PDF, PCAP and more |
| **Binary layout** | ELF, PE and Mach-O structure: sections, program headers, imports, exports |
| **Hardening checks** | PIE, NX stack, stack canary, RELRO and FORTIFY for ELF; ASLR, NX compat, Control Flow Guard, high entropy VA and Authenticode for PE |
| **Entropy analysis** | Shannon entropy with high-entropy region detection for packed or encrypted content |
| **String intelligence** | ASCII and UTF-16LE strings, categorized as URLs, IPv4, emails, paths, JWTs, AWS keys, GitHub tokens, Slack tokens, Google API keys, private keys and assigned secrets |
| **JavaScript analysis** | Minification detection, obfuscation score with indicators, framework fingerprints (webpack, React, Vue, Angular, Next.js, Vite, Svelte, jQuery), source map reference, URL and API endpoint extraction, secret scanning |
| **Archive inventory** | ZIP/APK/IPA/JAR entry listing with sizes, compression method, encryption flags, type detection and suspicious entry flagging |
| **Packer signals** | UPX signature and stub detection, plus multi-region high entropy heuristic |

### Inspectors and utilities

| Feature | Description |
| --- | --- |
| **Directory triage** | `reverso scan <dir>` recursively triages every file (format, entropy, SHA-256, packer signals) with a format breakdown |
| **Binary diff** | `reverso diff <a> <b>`: hashes, entropy, size, hardening traits (PIE, RELRO, canary, ASLR, CFG, ...), sections, imports, exports and string categories |
| **Hex pattern search** | `reverso find-bytes <file> <hex>`: `4d 5a ?? 60`-style patterns with `??` wildcards, plus a classic hex dump via `reverso hex` |
| **WebAssembly inspector** | `reverso wasm <file>`: sections, types, imports, exports, function/table/memory/global counts and the name section |
| **DEX inspector** | `reverso dex <file>`: header counts, checksum, and the categorized string table of Android Dalvik executables |

### Website mirror

| Feature | Description |
| --- | --- |
| **Same-origin mirroring** | `reverso site <url>` mirrors HTML, CSS and assets locally with relative link rewriting |
| **Safety guard** | Blocks loopback, private, link-local and reserved addresses (literal IPs and DNS answers) unless `--allow-private` is passed |
| **Resource caps** | Limits pages, depth, file size and total bytes; skips cross-origin redirects |

### Automation

| Feature | Description |
| --- | --- |
| **MCP server** | `reverso mcp` exposes every analyzer as a Model Context Protocol tool over stdio (protocol `2025-06-18`) |
| **Script-friendly** | JSON output by default, Markdown reports with `--format md`, files over stdout with `--out` |
| **Environment self-check** | `reverso doctor` validates the runtime before you rely on it |

---

## Requirements

| Dependency | Minimum Version | Notes |
| --- | --- | --- |
| **Node.js** | `^22.23.4`, `^24.22.1` or `>=26.12.1` | ESM, TypeScript strict, zero runtime dependencies |

No C/C++ toolchain, Python, Java or external analysis tools are needed.

> [!TIP]
> You can run the CLI straight from the repository without installing it globally.
> See [Installation](#installation), Option B.

### Never used a terminal? Start here

<details>
<summary><b>How to open a terminal</b></summary>

1. **Windows:** press `Win + R`, type `wt` or `powershell`, press Enter.
2. **macOS:** press `Cmd + Space`, type `Terminal`, press Enter.
3. **Linux:** press `Ctrl + Alt + T`, or find `Terminal` in your application menu.

</details>

---

## Installation

### Option A: Global command (npm link)

1. Install Git and Node.js (see the details below for Git).
2. Clone, build and link:

   ```bash
   git clone https://github.com/nekonaru/reverso.git
   cd reverso
   npm ci
   npm run build
   npm link
   ```

   > [!IMPORTANT]
   > `npm run build` must finish without errors. If it prints type errors,
   > stop and open an issue instead of running the binary.

3. Verify: `reverso doctor`

<details>
<summary><b>I have Git installed</b></summary>

Skip the Git step above. `git --version` should print a version.

</details>

<details>
<summary><b>I don't have Git</b></summary>

Download the source archive from
[GitHub](https://github.com/nekonaru/reverso/archive/refs/heads/main.zip), unzip
it, then run `npm ci`, `npm run build` and `npm link` inside the extracted
folder.

</details>

### Option B: Run from the repository without installing

```bash
git clone https://github.com/nekonaru/reverso.git
cd reverso
npm ci
npm run build
node dist/cli.js doctor
```

Use `node dist/cli.js <command>` anywhere you would use `reverso <command>`.

---

## Usage

### First launch

1. Check the runtime: `reverso doctor`
2. Analyze a file: `reverso analyze ./some-file.bin`
3. Point your MCP client at `reverso mcp` (see below)

> [!NOTE]
> Reverso is static-only. It never executes the file you analyze.

### Everyday use

- `reverso analyze ./target.bin` for a full triage report (add `--format md --out report.md` for Markdown)
- `reverso scan ./samples --max-files 500` to triage a whole directory of unknowns
- `reverso diff ./before.bin ./after.bin` to see exactly what changed between two builds
- `reverso find-bytes ./firmware.bin "7f 45 4c 46"` to locate byte patterns with wildcards
- `reverso hex ./mystery.bin --offset 0 --length 256` for a hex dump with offsets
- `reverso format ./mystery.bin` to identify a file
- `reverso layout ./target.elf` and `reverso hardening ./win32.exe` for binary structure and protections
- `reverso strings ./firmware.bin --min-length 6` for categorized strings
- `reverso js ./app.min.js` to inventory endpoints and secrets in a web bundle
- `reverso dex ./classes.dex` to inspect an Android DEX string table
- `reverso wasm ./module.wasm` to inspect a WebAssembly module
- `reverso site https://example.com --out ./mirror` to mirror a site offline
- `reverso capabilities` to list every analyzer and MCP tool

### Use Reverso from an MCP client

`reverso mcp` speaks Model Context Protocol over stdio (protocol `2025-06-18`).
Add it to your client configuration:

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

Tools exposed: `reverso_analyze`, `reverso_strings`, `reverso_entropy`,
`reverso_format`, `reverso_layout`, `reverso_hardening`, `reverso_archive_list`,
`reverso_js_analyze`, `reverso_scan`, `reverso_diff`, `reverso_find_bytes`,
`reverso_wasm`, `reverso_dex` and `reverso_hex`.

---

## Project Structure

```text
reverso/
├── src/
│   ├── core/         # format detection, entropy, hashes, strings, orchestrator, report
│   ├── binary/       # ELF / PE / Mach-O parsers and hardening checks
│   ├── archive/      # ZIP-family parser (APK/IPA/JAR detection)
│   ├── js/           # JavaScript bundle analysis
│   ├── web/          # website mirror (same origin, private-address guard)
│   ├── mcp/          # MCP stdio server
│   ├── doctor.ts     # environment self-check
│   ├── index.ts      # public API
│   └── cli.ts        # command dispatcher (thin layer over the engines)
├── tests/            # unit and integration tests (vitest)
├── docs/
│   ├── specs/        # testable specification (done criteria)
│   └── brand.md      # logo usage and colors
├── assets/logo/      # final logo files (mark, lockups, icons)
├── scripts/verify.mjs# local verification pipeline
├── README.md         # this file (English)
└── README.id.md      # Bahasa Indonesia
```

---

## Development

### Add a new analyzer

1. Write the analyzer in `src/` (pure functions, no I/O where avoidable).
2. Register it in `src/core/analyze.ts` and expose it from `src/index.ts`.
3. Add a CLI command in `src/cli.ts` and an MCP tool in `src/mcp/server.ts`.
4. Add tests in `tests/` and run `node scripts/verify.mjs`.
5. Document the command in both READMEs and the spec in `docs/specs/`.

### Run the verification pipeline

1. `node scripts/verify.mjs` (typecheck, tests with coverage, build, audit).
2. Everything must pass before a pull request is opened.
3. CI runs the same pipeline on Ubuntu and Windows, Node 22 and 24.

### Cut a release

1. Bump the version in `package.json` (and the CLI banner constant) as `MAJOR.MINOR.PATCH`.
2. Update `CHANGELOG.md` and `CHANGELOG.id.md` with the same sections as the release notes.
3. Open a pull request; merge once CI is green.
4. Tag `vX.Y.Z` on the merge commit and push the tag.
5. Publish the GitHub Release with bilingual notes (`Project vX.Y.Z` as the title).

> [!WARNING]
> `dist/` is generated by `npm run build`. Never edit files in `dist/` by hand
> and never commit them.

---

## Testing

```bash
npm ci
npm test                  # test suite
npm run test:coverage     # tests with coverage thresholds
node scripts/verify.mjs   # full pipeline (typecheck, coverage, build, audit)
```

| Check | Requirement |
| --- | --- |
| Unit and integration tests | All pass (129 tests) |
| Line coverage | At least 70% |
| Branch coverage | At least 60% |
| Type check | `tsc --noEmit`, zero errors |
| Dependency audit | `npm audit --omit=dev --audit-level=high`, zero findings |
| Secret scan | gitleaks job in CI, zero findings |

Linting is the TypeScript compiler in strict mode (`strict`,
`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`). There is no separate
linter configuration by design.

---

## Security

Reverso parses untrusted files without executing them, caps input sizes
(256 MiB files, 64 MiB over MCP) and blocks private network addresses in its
web mirror by default. The package has no runtime dependencies. Production
dependencies are audited in CI on every push, and all CI runs include a secret
scan.

Found a vulnerability? Use the repository's private vulnerability reporting on
GitHub (Security tab, "Report a vulnerability"). Do not open a public issue for
security reports.

---

## Continuous Integration

| Workflow | Purpose |
| --- | --- |
| `ci.yml` | Verify job (typecheck, tests with coverage, build, audit) on Ubuntu and Windows, Node 22 and 24, plus a gitleaks secret scan |

Branch protection on `main` requires every one of these checks to pass before
merging. Releases are cut only from green `main` after the security gate.

---

## FAQ

<details>
<summary><b>Does Reverso execute the binary it analyzes?</b></summary>

No. All analysis is static. Nothing is loaded, run or emulated.

</details>

<details>
<summary><b>Can it decompile to pseudocode?</b></summary>

No. Reverso triages, inventories and scores. For decompilation, feed the file
to a dedicated decompiler; use Reverso for triage, extraction and reporting.

</details>

<details>
<summary><b>Does it need an internet connection?</b></summary>

No for analysis. The test suite and the mirror integration tests bind to
loopback only during development. Analysis itself never touches the network.

</details>

<details>
<summary><b>Why did `reverso analyze` flag high entropy?</b></summary>

High entropy (above roughly 7 bits per byte) usually means compressed,
encrypted or packed content. Check the reported regions and the packer
signals before assuming malware.

</details>

<details>
<summary><b>Is Reverso published on npm?</b></summary>

Not yet. Install from source as shown in Installation. The package manifest is
release-ready; publishing is pending the first stable release.

</details>

<details>
<summary><b>How is Reverso related to other reverse engineering tools?</b></summary>

Reverso is an independent project rebuilt from a study of publicly available
tooling. No source code from other projects is included. It complements heavy
interactive tools rather than replacing them.

</details>

---

## Author

<div align="center">

| [![Nicolas Dwi Dharma](https://github.com/nekonaru.png?size=100)](https://github.com/nekonaru) |
|:---:|
| **Nicolas Dwi Dharma** |
| [github.com/nekonaru](https://github.com/nekonaru) |

</div>

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
