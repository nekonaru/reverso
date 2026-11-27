# Changelog

## v3.0.0

Tonggak platform dan berbagi: laporan lebih aman, dokumentasi API yang bisa dibaca mesin dan resource MCP.

### Fitur baru

- **Redaksi secret.** `reverso analyze --redact` dan `?redact=1` pada API menyamarkan JWT, cloud key, token dan header private key dalam laporan yang dibagikan.
- **Dokumen OpenAPI.** `GET /api/openapi.json` menjelaskan endpoint publik.
- **Batch API.** `POST /api/batch` menganalisis hingga 20 input base64 dalam satu request.
- **Resource MCP.** `resources/list` dan `resources/read` menyediakan rule pack, capabilities dan versi lewat URI `reverso://`.
- **SBOM.** `npm run sbom` menghasilkan `sbom.json` bergaya CycloneDX dari lock file yang ter-commit.
- **Threat model.** `docs/threat-model.md` mendokumentasikan batas, kontrol yang diterapkan dan risiko residual.
- **Laporan HTML v3** menampilkan skor risiko dan alasannya di samping temuan lain.

### Open: butuh akses akun

- npm trusted publishing, image container publik dan deploy hosting. Semua konfigurasi sudah siap; pemilik perlu menghubungkan akun.

## v2.2.0

Korelasi, penilaian dan efisiensi alur kerja untuk investigasi skala besar.

### Fitur baru

- **Clustering fingerprint.** `reverso cluster <dir>` mengelompokkan file berdasarkan hash eksak, imphash, Rich hash, ELF build-id, path PDB, UUID Mach-O dan prefiks fuzzy hash.
- **Skor risiko yang bisa dijelaskan.** Setiap laporan analisis kini membawa skor `risk` 0 sampai 100 berserta alasan dari hardening gagal, sinyal packer, secret, entropy dan obfuscation. `reverso risk <file>` menampilkannya langsung.
- **Cache scan inkremental.** `reverso scan <dir> --cache <file>` memakai ulang hasil file yang tidak berubah berdasarkan ukuran dan waktu modifikasi.
- **Watch mode.** `reverso watch <dir> --interval 5` melaporkan file baru, hilang dan berubah terhadap baseline sampai dihentikan.
- **Shell completion.** `reverso completion bash|zsh|powershell` menghasilkan skrip completion.
- **Konfigurasi pengguna.** Default bisa diatur di `~/.reverso/config.json` untuk batas scan, panjang string, rule pack dan format output.
- **`reverso explain <field>`** menampilkan penjelasan singkat field laporan yang umum.

### Peningkatan

- Entri scan kini menyimpan fingerprint build (imphash, Rich hash, build-id, path PDB, UUID dan fuzzy hash) sehingga clustering tidak perlu passing kedua.

## v2.1.0

Enam inspektor format native baru, plus detail PCAP dan WebAssembly yang lebih kaya.

### Fitur baru

- **Inspektor PDF.** `reverso pdf` melaporkan objek, enkripsi, JavaScript, OpenAction, file tertanam, URI dan metadata tanpa merender dokumen.
- **Inspektor OOXML.** `reverso ooxml` mendeteksi DOCX, XLSX dan PPTX, relasi eksternal, proyek VBA dan teks dokumen.
- **Inspektor PyInstaller.** `reverso pyinstaller` mengurai cookie CArchive, versi Python dan daftar isi.
- **Inspektor shortcut Windows.** `reverso lnk` melaporkan flag, atribut, path target, argumen, working directory dan timestamp.
- **Inspektor DotNet.** `reverso dotnet` membaca metadata stream CLI dan contoh string dari assembly managed.
- **Disassembler EVM.** `reverso evm` mengurai opcode dan mengumpulkan kandidat selector PUSH4 dari bytecode hex atau file.
- **Pengayaan PCAP.** Nama query DNS dan baris request HTTP kini diekstrak dari capture.
- **Produsen WASM.** Custom section `producers` diurai menjadi entri bahasa dan tool.

### Peningkatan

- Enam MCP tool baru (`reverso_pdf`, `reverso_ooxml`, `reverso_pyinstaller`, `reverso_lnk`, `reverso_dotnet`, `reverso_evm`) sehingga total 24.
- Lima inspektor baru juga berjalan di browser dan lewat HTTP API. OOXML khusus Node karena membutuhkan zlib.

## v2.0.0

Rilis tonggak: schema laporan berversi, API publik berbasis pekerjaan dan pengoperasian hosted yang lebih keras.

### Fitur baru

- **Schema laporan v2.** Setiap laporan analisis membawa `schemaVersion: "2.0"`. Field ini aditif, sehingga konsumen lama bisa mengabaikannya.
- **Job API.** `POST /api/jobs` mengembalikan id pekerjaan yang bisa dipoll; `GET /api/jobs/<id>` mengembalikan hasilnya. Pekerjaan disimpan sepuluh menit dengan antrean terbatas.
- **Endpoint rule pack.** `GET /api/rules` menyajikan rule pack bawaan untuk agent dan UI web.
- **Pengerasan host.** `REVERSO_API_KEY` mewajibkan API key pada `/api` dan `/mcp`; `REVERSO_RATE_LIMIT` membatasi request per IP per menit dengan HTTP 429 dan `Retry-After`.
- **Sesi MCP.** `initialize` mengeluarkan header `Mcp-Session-Id`; request berikutnya mengirimkannya kembali dan sesi yang tidak dikenal ditolak.

### Peningkatan

- 193 test pass, termasuk pembuatan pekerjaan, perilaku rate limit, sesi MCP dan cakupan fuzz.
- `docs/online.md` mendokumentasikan seluruh penyiapan hosted.

## v1.8.0

Alur investigasi dan ekspor laporan, dengan corpus fuzz di CI.

### Fitur baru

- **Baseline direktori.** `reverso baseline create <dir>` menyimpan SHA-256, ukuran dan format per file. `reverso baseline verify <dir>` melaporkan file baru, hilang, berubah dan tidak berubah, dengan output JSON atau Markdown serta kode keluar bukan nol saat ada perbedaan.
- **Kasus investigasi.** `reverso case create/add/report` menyimpan evidence dengan hash, ukuran, format, waktu dan catatan dalam satu file JSON.
- **Ekspor laporan.** `reverso analyze --format sarif` menghasilkan SARIF 2.1.0 untuk CI, `--format html` menghasilkan laporan mandiri bergaya, dan `reverso scan --format csv` menghasilkan inventaris siap spreadsheet.
- **Corpus fuzz.** CI kini menjalankan input acak dan terpotong yang deterministik melalui `analyzeBuffer` dan parser individual.

### Peningkatan

- Analyzer di browser menyimpan sepuluh analisis terakhir di localStorage browser dan memungkinkan hasil dipulihkan dengan satu klik. Tidak ada data yang keluar dari browser.

## v1.7.0

Pencocokan aturan, kemiripan fuzzy dan inventaris build yang lebih dalam, semuanya native.

### Fitur baru

- **Rule engine YARA-lite.** `reverso match` memakai pack bawaan (atau pack JSON lewat `--rules`) dengan pola hex, teks dan regex. Kondisi mendukung label, `N of them`, `and/or/not`, tanda kurung, `filesize` dan `entropy`, diurai interpreter kecil yang aman, bukan `eval`.
- **Fuzzy hash.** `reverso fuzzy` menghasilkan hash piecewise bergaya ssdeep. `reverso diff` melaporkan skor kemiripan 0 sampai 100 dan kedua hash.
- **Version info PE.** Versi file dan produk diekstrak dari resource `VS_VERSIONINFO` UTF-16 saat tersedia.
- **Inventaris relokasi dan dependensi ELF.** `DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH` dan jumlah REL/RELA dilaporkan.
- **Dylib dan rpath Mach-O.** Load command untuk dynamic library dan rpath diurai menjadi daftar yang terbaca.

### Peningkatan

- `reverso rules list` menampilkan pack bawaan; `reverso match` mendukung output JSON dan Markdown.
- Dua MCP tool baru, `reverso_match` dan `reverso_fuzzy`, plus dukungan di browser dan HTTP API.

## v1.6.0

Pemeriksaan native lebih dalam untuk dependensi dinamis, path build dan binary universal. Diaudit terhadap binary Windows nyata.

### Fitur baru

- **Dependensi ELF.** `reverso layout` mengurai `DT_NEEDED`, `DT_RPATH` dan `DT_RUNPATH` lewat `DT_STRTAB`, memetakan alamat virtual ke offset file melalui segmen `PT_LOAD`.
- **Delay import PE.** Directory delay-load diurai menjadi struktur impor yang sama seperti impor biasa (bentuk descriptor RVA dan VA).
- **Path PDB.** Entri debug CodeView diurai untuk mendapatkan path PDB mesin build dan jumlah directory debug.
- **Kelas DEX.** `reverso dex` menyelesaikan `class_defs` lewat `type_ids` menjadi deskriptor kelas yang terbaca.
- **Slice Mach-O universal.** Binary fat kini melaporkan CPU, bitness, tipe file, segment dan UUID per slice, dengan pengecekan batas dan error per slice.

### Perbaikan bug

- **Stride header binary fat.** Header Mach-O fat 64-bit memakai entri arsitektur 32 byte, bukan 20 byte. Parser lama salah membaca CPU dan offset slice pada file fat64; kini memakai layout yang benar untuk kedua varian.

### Peningkatan

- Laporan Markdown menampilkan library yang dibutuhkan, RPATH/RUNPATH, delay import, path PDB, daftar kelas DEX dan detail slice Mach-O.

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
