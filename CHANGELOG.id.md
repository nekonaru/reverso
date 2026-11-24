# Changelog

## v1.5.0

Reverso bisa dipakai secara online: di browser tanpa instalasi, atau lewat API dan MCP server yang di-host.

### Fitur baru

- **Analyzer di browser.** Situs proyek kini punya bagian "Try Reverso online" dengan 15 analyzer, Web Worker, batas 64 MB per file serta tombol salin dan unduh. File tetap di browser dan tidak pernah di-upload.
- **HTTP API.** `POST /api/analyze?tool=<nama>` menerima file mentah dan mengembalikan JSON yang sama seperti CLI. `GET /health` untuk health check. CORS aktif dan body dibatasi 8 MB secara default.
- **MCP jarak jauh.** `POST /mcp` menjawab JSON-RPC stateless lewat JSON atau server-sent events. Setiap tool file menerima `content` base64; `reverso_diff` menerima `contentA` dan `contentB`.
- **Paket hosting.** `Dockerfile`, blueprint gratis `render.yaml` dan `npm start` menjalankan situs, API dan MCP jarak jauh dalam satu proses Node. Lihat `docs/online.md`.

### Peningkatan

- **Engine bersama.** Inti analisis dipisah menjadi modul platform-neutral, sehingga CLI, MCP, browser dan HTTP API menghasilkan hasil identik tanpa logika ganda.
- **Pipeline build.** `npm run build:web` mem-bundle analyzer browser, dan `npm run verify` kini memeriksanya di setiap push.

## v1.4.0

Provenansi build dan forensik data yang ditambahkan, divalidasi pada binary Windows nyata.

### Fitur baru

- **Rich fingerprint PE.** Rich header di DOS stub di-XOR kembali menjadi entri compiler (produk, build, count) dan diringkas menjadi `richHash` deterministik. `reverso diff` melaporkan perubahannya.
- **Digest file Authenticode.** Laporan PE kini memuat digest SHA-1 dan SHA-256 dengan field checksum dan entri certificate directory dinolkan serta tabel sertifikat dikecualikan.
- **ELF build-id.** GNU build-id diekstrak dari section `SHT_NOTE` saat ada; `reverso diff` melaporkan perubahannya.
- **UUID Mach-O.** `LC_UUID` didekode menjadi string UUID kanonik; `reverso diff` melaporkan perubahannya.
- **Deteksi overlay.** Laporan PE dan ELF menampilkan ukuran dan SHA-256 data yang ditambahkan setelah raw data section terakhir.

### Peningkatan

- **Keselarasan marker Rich.** Pemindaian Rich header kini menangani marker di offset byte mana pun di DOS stub, kasus umum pada binary Microsoft nyata.
- **Alignment note.** Field note ELF disejajarkan relatif terhadap record note, bukan offset absolut, sehingga section note dengan alignment aneh tetap terbaca.

## v1.3.0

Kedalaman forensik untuk binary dan capture: PE import hash, entropy per section, serta inspeksi PCAP dan JWT native.

### Fitur baru

- **PE import hash.** `reverso layout` melaporkan PE import hash (`imphash`), dihitung dari descriptor impor sesuai urutan kemunculan.
- **Entropy per section.** Daftar section ELF dan PE kini membawa Shannon entropy per section; laporan menandai section di atas 7.0 bit sebagai kandidat packer.
- **Inspector PCAP.** `reverso pcap <file>` mem-parse classic PCAP: versi, snaplen, link type, jumlah paket, durasi, rincian protokol, top talker dan top port tujuan. pcapng dideteksi dan ditolak dengan panduan.
- **Decoder JWT.** `reverso jwt <token|file>` mendekode header dan payload, mengonversi `iat`/`nbf`/`exp` ke tanggal ISO, menandai token expired, `alg=none`, claim sensitif dan `exp` yang hilang. Signature tidak pernah diverifikasi, secara desain.
- **Dua MCP tool baru.** `reverso_pcap` dan `reverso_jwt` (total 16 tool).

### Peningkatan

- **Validasi magic ELF ketat.** `parseElf` kini melempar error pada `EI_CLASS`/`EI_DATA` yang tidak valid, bukan menganalisis sampah.
- **Layout lebih tahan banting.** `reverso layout` keluar dengan kode 3 dan pesan yang jelas saat binary tidak bisa di-parse, bukan error yang tidak tertangani.

## v1.2.0

Mark baru, dan rumah publik untuk proyek ini.

### Fitur baru

- **Mark baru.** Mengadopsi mark dari pemilik: heksagon terbelah yang larut menjadi byte. Logo kit (tile, transparan, mono ink/gold/white, favicon, app icon, lockup, lockup dua warna) ada di `assets/logo/`.
- **Project website.** Landing page di [nekonaru.github.io/reverso](https://nekonaru.github.io/reverso/): gambaran umum, instruksi instalasi, konfigurasi MCP dan FAQ, dideploy otomatis ke GitHub Pages pada setiap push yang menyentuh `site/`.

### Peningkatan

- **Dokumentasi.** README kini menautkan project site; homepage repository diperbarui.

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
