# Spec: Reverso core (v0.1.0)

Goal: a native-first reverse engineering toolkit that runs fully locally.
One CLI and one MCP server share the same analysis engines. No proprietary
dependencies, no network access required for analysis.

## Done criteria (machine-checkable)

1. `reverso analyze <file>` prints a JSON report with: sha256/sha1/md5, size,
   Shannon entropy, format detection, printable strings (with categories),
   and format-specific details (ELF/PE/Mach-O layout, archive listing,
   JavaScript bundle analysis). Exit code 0.
2. `reverso layout <file>` prints section/load structure for ELF, PE and
   Mach-O binaries. Exit code 0 on supported formats, 3 on unsupported.
3. `reverso hardening <file>` reports PE and ELF hardening checks
   (ASLR/NX/CFG/signed for PE; PIE/NX stack/canary/RELRO/FORTIFY for ELF).
4. `reverso strings <file>` extracts ASCII and UTF-16LE strings, categorized
   (url, ipv4, email, path, jwt, aws-key, github-token, slack-token,
   google-api-key, private-key, assigned-secret).
5. `reverso js <file>` analyzes JavaScript bundles: minification detection,
   obfuscation score and indicators, source map reference, framework
   fingerprints, extracted URLs, API endpoints and likely secrets.
6. `reverso archive <file>` lists ZIP-based archives (ZIP, APK, IPA, JAR)
   with entry sizes, compression method, encryption flags and type detection.
7. `reverso site <url>` mirrors a website locally with same-origin scope,
   depth and page limits, per-file and total byte caps, a private-address
   guard and link rewriting to relative paths.
8. `reverso mcp` starts an MCP stdio server exposing the analyzers as tools.
   `initialize`, `ping`, `tools/list` and `tools/call` respond per the MCP
   specification.
9. `reverso doctor` checks the runtime and exits 0 when healthy.
10. `npm run verify` (typecheck, tests with coverage thresholds, build,
    audit) passes on a clean checkout.

## Constraints

- Node.js ^22.23.4 || ^24.22.1 || >=26.12.1, ESM, TypeScript strict.
- Zero runtime dependencies. Dev dependencies only for build and test.
- English source. No em dash or en dash in any file. MIT license.
- Analysis caps: at most 5000 extracted strings, 50 samples per category,
  5000 archive entries, 256 MiB input size, 64 MiB over MCP.
- The website mirror blocks private, loopback and link-local addresses
  unless `--allow-private` is passed explicitly.
