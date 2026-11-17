# Changelog

## v1.1.1

Rilis pembersihan internal. Tidak ada perubahan perilaku.

### Perbaikan bug

- **Tanda baca komentar.** Satu komentar berisi em dash; diganti koma. Tidak ada perubahan kode, API atau output.

## v1.1.0

Update introspeksi besar: triase seluruh direktori, diff binary struktural,
pencarian tingkat byte, serta inspector WebAssembly dan Android DEX native.

### Fitur baru

- **Triase direktori.** `reverso scan <dir>` menganalisis seluruh file secara
  rekursif (melewati node_modules, .git dan dist), dengan rincian per format,
  SHA-256, entropy dan sinyal packer per file.
- **Diff binary.** `reverso diff <a> <b>` membandingkan ukuran, entropy, trait
  hardening, section, impor, ekspor dan kategori string antara dua file.
- **Pencarian byte dan hex dump.** `reverso find-bytes` mencari pola hex
  (`4d 5a ?? 60`) dengan wildcard; `reverso hex` menampilkan hex dump klasik.
- **Inspector WebAssembly.** `reverso wasm` mem-parse binary format: section,
  tipe, impor, ekspor, jumlah dan section name.
- **Inspector Android DEX.** `reverso dex` mem-parse header, checksum dan
  string table terkategori (URL, AWS key, class descriptor, dan lainnya).
- **Enam MCP tool baru.** `reverso_scan`, `reverso_diff`, `reverso_find_bytes`,
  `reverso_hex`, `reverso_wasm`, `reverso_dex` (total 14 tool).

### Peningkatan

- **Audit hardening dan performa.** Ekstraksi string massal `TextDecoder`,
  konstanta versi satu sumber, deteksi peluncuran CLI tahan-symlink untuk
  npm bin shim, bit executable pada `dist/cli.js` via postbuild, flag numerik
  dibatasi rentang wajar, `capabilities` diturunkan dari registry tool.
- **Sinyal diff lebih kaya.** Trait hardening ELF, PE dan Mach-O (PIE, RELRO,
  canary, stripped, ASLR, CFG, ...) dibandingkan secara eksplisit.

### Perbaikan bug

- **Flag boolean dari string.** `--allow-private true` kini diparse sebagai
  true; sebelumnya guard tetap aktif tanpa disadari.
- **Arsip rusak.** EOCD ZIP yang malformed tidak lagi sampai ke parser tanpa
  pengecekan; section arsip cukup dihilangkan, bukan crash.
- **Capabilities drift.** Daftar MCP tool di `capabilities` kini dibangkitkan
  dari registry, bukan daftar hardcoded yang kedaluwarsa.

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
