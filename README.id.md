# Reverso

[![CI](https://github.com/nekonaru/reverso/actions/workflows/ci.yml/badge.svg)](https://github.com/nekonaru/reverso/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%5E22.23.4%20%7C%7C%20%5E24.22.1-339933.svg)](https://nodejs.org/)

**Toolkit reverse engineering yang berjalan native.** Analisis statis untuk
binary, bundle JavaScript dan website dari satu CLI atau satu MCP server,
dengan nol dependensi runtime dan tanpa tool berbayar.

*[Read the English version](README.md)*

Reverso adalah proyek independen. Reverso adalah implementasi ulang (rebuild)
berdasarkan studi terhadap tooling reverse engineering yang tersedia secara
publik; tidak ada kode sumber dari proyek lain yang disertakan. Gunakan hanya
pada berkas dan sistem yang memang boleh kamu analisis.

## Yang bisa kamu lakukan

| Perintah | Fungsinya |
| --- | --- |
| `reverso analyze <file>` | Laporan triase lengkap: hash, entropy, format, strings, layout, hardening, daftar arsip, analisis JavaScript |
| `reverso format <file>` | Deteksi format dari magic bytes: ELF, PE, Mach-O, ZIP, APK, IPA, JAR, WASM, DEX, PCAP dan lainnya |
| `reverso layout <file>` | Struktur ELF, PE dan Mach-O: section, program header, impor, ekspor |
| `reverso hardening <file>` | Cek hardening: PIE, NX stack, stack canary, RELRO, FORTIFY, ASLR, NX compat, Control Flow Guard, Authenticode |
| `reverso strings <file>` | String printable ASCII dan UTF-16LE, dikategorikan (URL, IPv4, email, JWT, key, secret) |
| `reverso entropy <file>` | Entropy Shannon dengan deteksi region entropy tinggi (area yang dipack/dienskripsi) |
| `reverso archive <file>` | Daftar entri ZIP/APK/IPA/JAR dengan deteksi tipe dan penandaan entri mencurigakan |
| `reverso js <file>` | Analisis bundle JavaScript: minifikasi, skor obfuscation, framework, source map, URL, endpoint API, secret |
| `reverso site <url>` | Mirror website secara lokal, same origin, dengan rewrite link dan penjaga alamat privat |
| `reverso mcp` | Jalankan MCP stdio server yang mengekspos semua analyzer sebagai tool |
| `reverso doctor` | Cek lingkungan runtime |
| `reverso capabilities` | Daftar semua analyzer, perintah dan MCP tool |

Semuanya berjalan offline. Analisis tidak butuh jaringan, tidak butuh Ghidra,
Hopper, IDA atau license server.

## Kebutuhan

- Node.js `^22.23.4 || ^24.22.1 || >=26.12.1`
- Tanpa native addon, tanpa Python, tanpa tool eksternal

## Instalasi

Dari source (metode yang didukung saat ini):

```bash
git clone https://github.com/nekonaru/reverso.git
cd reverso
npm ci
npm run build
npm link        # menaruh `reverso` di PATH kamu
```

Lalu:

```bash
reverso doctor
```

## Mulai cepat

```bash
# Triase binary yang tidak dikenal
reverso analyze ./target.bin

# Laporan yang sama dalam Markdown, ditulis ke file
reverso analyze ./target.bin --format md --out report.md

# Struktur binary dan hardening
reverso layout ./target.elf
reverso hardening ./win32.exe

# File ini file apa?
reverso format ./mystery.bin

# Inventaris endpoint dan secret dari bundle web
reverso js ./app.min.js

# Mirror site untuk analisis offline (tetap di origin yang sama)
reverso site https://example.com --out ./mirror --max-pages 200

# JSON untuk scripting
reverso strings ./firmware.bin --min-length 6 | jq '.categories'
```

## Pakai Reverso dari MCP client

`reverso mcp` berbicara [Model Context Protocol](https://modelcontextprotocol.io/)
lewat stdio (protokol `2025-06-18`). Tambahkan ke client kamu:

```json
{
  "mcpServers": {
    "reverso": {
      "command": "node",
      "args": ["/path/ke/reverso/dist/cli.js", "mcp"]
    }
  }
}
```

Atau, kalau paketnya sudah terpasang secara global:

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

Tool yang diekspos:

| Tool | Input | Output |
| --- | --- | --- |
| `reverso_analyze` | `path` | Laporan analisis statis lengkap (JSON) |
| `reverso_strings` | `path`, `minLength?` | String terkategori (JSON) |
| `reverso_entropy` | `path` | Entropy Shannon dan region entropy tinggi (JSON) |
| `reverso_format` | `path` | Deteksi format (JSON) |
| `reverso_layout` | `path` | Struktur ELF/PE/Mach-O (JSON) |
| `reverso_hardening` | `path` | Cek hardening (JSON) |
| `reverso_archive_list` | `path` | Daftar ZIP/APK/IPA/JAR (JSON) |
| `reverso_js_analyze` | `path` atau `source` inline | Analisis JavaScript (JSON) |

## Catatan keamanan

- **Berkas dianalisis secara read-only.** Reverso tidak pernah mengeksekusi
  target.
- **Mirror website tetap di origin awal** dan menolak mengambil alamat
  loopback, privat, link-local dan reserved (baik IP literal maupun jawaban
  DNS) kecuali kamu memakai `--allow-private` secara eksplisit.
- **Ukuran output dibatasi.** Input dibatasi 256 MiB, string yang diekstrak
  5000, entri arsip 5000, dan pembacaan via MCP 64 MiB.

Gunakan Reverso hanya pada target yang memang boleh kamu analisis.

## Pengembangan

```bash
npm ci
node scripts/verify.mjs   # typecheck + test dengan coverage + build + audit
npm test                  # test saja
npm run test:coverage     # test dengan threshold coverage
```

Threshold coverage dijalankan otomatis (70% lines, 60% branches). Pipeline CI
menjalankan verifikasi yang sama di Ubuntu dan Windows, pada Node 22 dan 24,
plus secret scan. Branch protection mewajibkan semuanya hijau.

Struktur proyek:

```text
src/
├── core/      # deteksi format, entropy, hash, strings, orkestrasi, report
├── binary/    # parser ELF / PE / Mach-O dan cek hardening
├── archive/   # parser keluarga ZIP (deteksi APK/IPA/JAR)
├── js/        # analisis bundle JavaScript
├── web/       # mirror website (same origin, penjaga alamat privat)
├── mcp/       # MCP stdio server
└── cli.ts     # dispatcher perintah (lapisan tipis di atas engine)
tests/         # unit dan integration test
docs/specs/    # spesifikasi yang bisa diuji
```

Spesifikasi dengan done criteria ada di [docs/specs/core.md](docs/specs/core.md).

## Keterbatasan

- Reverso melakukan analisis **statis**. Reverso tidak mengkompilasi balik ke
  pseudocode; Reverso mem-parse, menginventarisasi dan memberi skor. Untuk
  decompilation interaktif, arahkan decompiler ke berkasnya sendiri dan pakai
  Reverso untuk triase, ekstraksi dan pelaporan.
- Analisis JavaScript bersifat heuristik (regex dan pola), seperti semua
  analisis JS statis. Skor obfuscation adalah indikator, bukan bukti.
- Mirror website dibatasi same-origin secara desain; ia tidak akan merayapi
  satu domain penuh.

## Lisensi

MIT. Lihat [LICENSE](LICENSE).
