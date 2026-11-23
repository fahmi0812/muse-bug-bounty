# P2 — MCP 16 platform bounty (tanpa auto-submit)

> Status: **P2 / docs saja.** MCP di sini = cara *membaca* data program
> (scope, kebijakan, template laporan) lewat Model Context Protocol,
> **bukan** cara mengirim laporan otomatis.
>
> **Larangan keras (tetap berlaku):** tidak ada auto-submit ke platform
> mana pun, tidak ada pembayaran/deposit otomatis, tidak ada kredensial
> di repo. Submit laporan selalu manual oleh manusia, setelah review di
> `strix view` (P1-2).

## Daftar 16 platform

| # | Platform | MCP / akses baca | Catatan |
| --- | --- | --- | --- |
| 1 | HackerOne | MCP komunitas / API baca | Program, scope, Hacktivity (cek dedup) |
| 2 | Bugcrowd | API baca | Program, scope, template laporan |
| 3 | Intigriti | API baca | Program, scope |
| 4 | Immunefi | API baca | Program Web3, scope, severity |
| 5 | YesWeHack | API baca | Program, scope |
| 6 | HackerOne (VDP) | sama dgn 1 | VDP tanpa bounty tetap dibaca scope-nya |
| 7 | Bugcrowd (VDP) | sama dgn 2 | — |
| 8 | Intigriti (VDP) | sama dgn 3 | — |
| 9 | Open Bug Bounty | Web baca | VDP publik |
| 10 | Cobalt | API baca | Pentest-as-a-service, scope |
| 11 | Synack | API baca | Undangan saja — baca bila sudah member |
| 12 | Google VRP | Web baca | Scope Google |
| 13 | Meta Bug Bounty | Web baca | Scope Meta |
| 14 | Apple Security Bounty | Web baca | Scope Apple |
| 15 | Microsoft MSRC | API baca | Scope + CVRF |
| 16 | GitHub Security Lab / VDP repo | API baca | Scope per repo |

Daftar ini titik awal; platform yang tidak punya MCP/API baca tetap
bisa dipakai manual (baca scope di web, salin ke `programs/*.md`).

## Template config (tanpa kredensial)

Satu file per platform, di `programs/mcp/<platform>.json` (belum dibuat
di v1 — template di bawah ini contohnya). Token **tidak pernah**
ditulis di file ini; dibaca dari environment / credential store lokal
saat runtime, dan hanya untuk operasi baca.

```json
{
  "platform": "hackerone",
  "mcp_server": "npx -y @contoh/mcp-hackerone",
  "mode": "read-only",
  "allowed_operations": ["list_programs", "get_scope", "search_hacktivity"],
  "forbidden_operations": ["submit_report", "send_message", "make_payment"],
  "auth": {
    "type": "env",
    "env_var": "HACKERONE_API_TOKEN",
    "note": "Token diisi di .env lokal, JANGAN di file ini"
  },
  "rate_limit_per_minute": 30
}
```

Aturan config:

- `"mode": "read-only"` wajib. Server MCP yang meminta operasi tulis
  ditolak sebelum jalan (pre-execution guard).
- `forbidden_operations` selalu berisi `submit_report`,
  `send_message`, `make_payment` — tanpa kecuali.
- `rate_limit_per_minute` default 30; hormati 429 + backoff.
- Token dari env var / vault lokal, mode file 0600, tidak di-log.

## Alur yang diizinkan

1. Baca scope program → tulis/sinkronkan ke `programs/<nama>.md`
   (scope gate baca dari sini).
2. Cek dedup: cari Hacktivity / laporan publik sebelum validasi
   (hindari duplikat).
3. Ambil template laporan platform → isi manual dari finding yang
   sudah terverifikasi → **user yang kirim sendiri** di web platform.

## Alur yang dilarang

- Submit laporan otomatis (dalam bentuk apa pun).
- Membalas pesan triager otomatis.
- Mengubah scope program di platform.
- Mengambil kredensial / token dari repo, log, atau laporan.

## Writeup search RAG/FAISS (pelengkap P2)

Pencarian writeup publik (HackerOne Hacktivity, blog, writeup) untuk
belajar teknik — indeks lokal FAISS di atas korpus writeup yang
dikumpulkan manual. Dipakai saat triage ("apakah teknik ini pernah
dilaporkan di program ini?"), bukan untuk menyalin laporan orang lain.
Korpus writeup tidak di-commit (hak cipta penulis masing-masing);
indeks dibangun lokal dari URL yang dikumpulkan sendiri.
