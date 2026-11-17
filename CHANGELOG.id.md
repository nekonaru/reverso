# Changelog

## v1.0.0

Rilis stabil pertama. Reverso mentriase berkas yang tidak dikenal secara
native, tanpa tool analisis eksternal, dari satu CLI atau satu MCP server.

### Fitur baru

- **Laporan triase lengkap.** `reverso analyze` menghasilkan hash, entropy,
  format, strings, layout, hardening, daftar arsip dan analisis JavaScript
  dalam satu laporan JSON atau Markdown.
- **Parser binary.** Parser ELF, PE dan Mach-O native (section, program
  header, impor, ekspor) plus cek hardening: PIE, NX stack, stack canary,
  RELRO, FORTIFY, ASLR, NX compat, Control Flow Guard dan Authenticode.
- **Analisis JavaScript.** Deteksi minifikasi, skor obfuscation dengan
  indikator, fingerprint framework, deteksi source map, ekstraksi URL,
  endpoint API dan secret.
- **Mirror website.** `reverso site <url>` mirror website secara lokal, same
  origin, dengan rewrite link ke relatif, penjaga alamat privat (IP literal
  dan jawaban DNS), batas byte per file dan total, serta pembacaan body
  secara streaming.
- **MCP server.** `reverso mcp` mengekspos semua analyzer sebagai tool Model
  Context Protocol lewat stdio (protokol `2025-06-18`).
- **Intelijen strings.** String ASCII dan UTF-16LE dikategorikan sebagai URL,
  IPv4, email, path, JWT, AWS key, GitHub token, Slack token, Google API key,
  private key dan assigned secret.
- **Inventaris arsip.** Daftar ZIP/APK/IPA/JAR dengan deteksi tipe dan
  penandaan entri mencurigakan.

### Peningkatan

- **Nol dependensi runtime.** Tidak ada yang perlu diinstal atau diaudit
  saat runtime.
- **Batas output di mana-mana.** Batas input 256 MiB untuk file, 64 MiB
  lewat MCP, 5000 string, 5000 entri arsip.
- **Verifikasi yang dipaksakan.** TypeScript strict, 84 test dengan
  threshold coverage, audit dependensi production dan secret scan di CI, di
  Ubuntu dan Windows, Node 22 dan 24.

### Perbaikan bug

- **Batas memori mirror.** Body respons kini dibaca secara streaming dan
  dibatalkan melewati batas per file, bukan dibuffer penuh dulu.
- **Robustness arsip.** File ZIP yang rusak tidak lagi menggagalkan seluruh
  laporan; section arsip cukup dihilangkan.

## v0.1.0

Snapshot pengembangan awal. Analyzer inti, kerangka CLI dan MCP server,
sebelum security hardening pra-rilis.
