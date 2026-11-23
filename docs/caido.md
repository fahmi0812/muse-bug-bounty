# Caido MCP — jalur live proxy (P1-7)

SARIF (`bounty/lib/sarif.js`) hanya dibaca **setelah** Strix selesai —
batch, post-hoc. Jalur Caido MCP bekerja **selagi hunting**: agen
membaca request satu per satu dari history proxy Caido dan me-replay
request tersimpan via ID, jadi hunting mengikuti trafik nyata
(lead → primitive → finding), bukan hanya laporan akhir.

## Yang dibangun

- `bounty/lib/caido.js` — klien MCP stdio JSON-RPC (zero-dep):
  `startCaidoMcp`, `stopCaidoMcp`, `listRequests`, `replayRequest`,
  `attachEvidenceToFinding`, `checkCaidoHealth`, parser
  `parseListResponse` / `parseReplayResponse`, `resolveToolNames`.
- `tests/caido.test.js` — 9 test dengan server MCP palsu (stdio).

## Setup

1. Instal dan jalankan Caido (community edition cukup) di laptop:
   unduh dari https://caido.io, jalankan, dengarkan di
   `127.0.0.1:8080`.
2. Aktifkan API lokal di Caido: Settings → API → Enable local API.
   Cek: `curl http://127.0.0.1:8080/api/health`.
3. Sediakan server MCP Caido. **Jalur terverifikasi** (README
   caido/mcp-caido):
   ```text
   git clone https://github.com/caido/mcp-caido
   cd mcp-caido
   npm install
   npm run build
   ```
   Lalu jalankan wrapper dengan `mcpPath` ke `dist/index.js` itu
   (CLI: `bounty caido ... --mcp-path <path>` — wiring CLI oleh parent).
   Env yang diteruskan ke server: `CAIDO_API_URL`
   (default `http://127.0.0.1:8080`) dan `CAIDO_API_KEY` bila ada.
4. Atur scope di Caido (project) SEBELUM hunting: hanya request
   dalam scope yang dibaca/di-replay. `listRequests` mengembalikan
   semua traffic yang dilihat server; filter dengan HTTPQL
   (`--filter 'req.host contains "target.com"'`) dan periksa
   `in_scope` sebelum memakai sebuah request.

## Alur pakai

```text
bounty caido start [--mcp-path <path>] [--caido-url http://127.0.0.1:8080]
bounty caido list [--filter 'req.method == "POST"'] [--limit 20]
bounty caido replay --request-id req-1
bounty caido evidence --request-id req-1 --finding <id>
```

- `list` memakai tool `caido_list_requests` (resmi) atau
  `list_requests` (fork) — nama diselesaikan adaptif dari
  `tools/list`.
- `replay` mengirim ulang request tersimpan via ID — **read/replay
  saja**. Tidak ada modifikasi parameter, tidak ada fuzzing di lib
  ini (itu kerja skill/operator dengan akun test).
- `evidence` menempelkan ID request HTTP ke finding:
  `Caido request #<id> — <url>` — sama seperti Strix 1.7 yang
  membawa HTTP request ID sebagai evidence.
- Lawan SARIF: SARIF = batch setelah run selesai; Caido = live
  selama run berjalan. Keduanya saling melengkapi, bukan pengganti.

## Aturan keras

- **Scope:** project Caido harus dalam scope program. Replay HANYA
  request in-scope, ke target in-scope. Jangan replay request
  produksi / akun orang lain.
- **Token:** `CAIDO_API_KEY` hanya dari env — tidak pernah di-log,
  tidak pernah masuk objek sesi atau output.
- **Tanpa auto-submit:** lib ini tidak mengirim laporan ke mana pun.
  Evidence hanya menempel di finding lokal.

## Yang belum terverifikasi (best-effort)

- **Nama paket npm `@caido/mcp-server` TIDAK terverifikasi:**
  registry npm mengembalikan 404 untuk nama itu pada 23 Nov 2026.
  Jangan andalkan `npx @caido/mcp-server` — pakai `mcpPath` ke
  checkout `caido/mcp-caido` (jalur terverifikasi di atas).
- **Bentuk argumen `tools/call`** (`filter`/`limit`/`request_id`)
  diambil dari dokumentasi, belum diuji terhadap server asli
  (tidak ada Caido di VM). Bila server menolak argumen, pesan
  error-nya dikembalikan apa adanya — periksa `inputSchema` dari
  `tools/list` dan sesuaikan.
- **Versi Caido:** fork Vibe Hacking diuji terhadap Caido v0.58.3;
  server resmi menargetkan Caido 0.59+ untuk fitur replay lanjutan.
  Bila tool replay tidak ada di `tools/list`, `replayRequest`
  mengembalikan `{error}` — bukan sukses diam-diam.
