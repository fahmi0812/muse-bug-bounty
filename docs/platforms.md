# Integrasi Platform (read-only) — P0-7

Modul `bounty/lib/platforms.js` membaca scope program dan mencari laporan
publik (cek duplikat), lalu membuat **draf** laporan Markdown. Modul ini
**TIDAK PERNAH** mengirim laporan, membayar, atau menyetor apa pun —
tidak ada jalur auto-submit di repo ini, dan draf harus dikirim manual
oleh manusia lewat UI platform setelah direview.

## Yang bisa dilakukan

| Kemampuan | HackerOne | Bugcrowd |
|---|---|---|
| Baca scope program (`getProgramScope`) | ✅ terverifikasi | ⚠️ best-effort |
| Cari laporan publik / cek duplikat (`searchHacktivity`) | ⚠️ best-effort | ❌ tidak ada pencarian publik |
| Draf laporan Markdown (`draftReport`) | ✅ (murni, tanpa jaringan) | ✅ (sama) |
| Bandingkan scope vs `programs/*.md` (`syncScopeToProgram`) | ✅ (tanpa menulis file) | ✅ (tanpa menulis file) |

Status bentuk API (dicek 2026-11-23 dari docs resmi):

- **HackerOne scope — terverifikasi.** Hacker API memakai HTTP Basic
  (username + token sebagai password). Scope dibaca dari
  `GET /v1/hackers/programs/{handle}` (structured_scopes tertanam di
  respons; atribut `asset_identifier`, `asset_type`, `max_severity`,
  `eligible_for_bounty`), fallback
  `GET /v1/programs/{id}/structured_scopes`.
  Sumber: https://api.hackerone.com/ (Resources → Programs).
- **HackerOne hacktivity — best-effort.** Tidak ada endpoint REST publik
  resmi yang terdokumentasi untuk pencarian laporan (tool MCP
  `search_hacktivity` memakai query Lucene, tapi HTTP di baliknya tidak
  didokumentasikan). Implementasi memakai feed publik
  `https://hackerone.com/hacktivity.json?query=...` dengan parsing
  toleran; bila bentuk respons berubah, fungsi mengembalikan `{error}`.
- **Bugcrowd scope — best-effort.** Docs resmi
  (https://docs.bugcrowd.com/api/getting-started/ dan
  https://docs.bugcrowd.com/api/usage/): base
  `https://api.bugcrowd.com`, auth `Authorization: Token
  USERNAME:PASSWORD`, `Accept: application/vnd.bugcrowd+json`, JSON:API,
  program di `/programs/{uuid}`, target lewat
  `?include=current_brief.target_groups.targets`. Handle diperlakukan
  sebagai UUID dulu; bila 404, fallback daftar `/programs` lalu cocokkan
  field `code` (bentuk filter `code` tidak terverifikasi).
- **Bugcrowd hacktivity — tidak didukung.** Bugcrowd tidak punya
  pencarian laporan publik seperti hacktivity; cek duplikat manual di UI.

## Setup token (read-only)

### HackerOne

1. Login ke HackerOne → foto profil → **Settings** → **API Token**.
2. Buat token baru (beri nama mis. `muse-bug-bounty-readonly`).
3. Catat **username** dan **token** — token hanya ditampilkan sekali.
4. Simpan di env (jangan di repo):

```text
export HACKERONE_USERNAME="username-anda"
export HACKERONE_TOKEN="token-anda"
```

Token hacker HackerOne hanya bisa membaca program/laporan yang memang
bisa diakses akun itu; tidak ada izin tulis dari modul ini.

### Bugcrowd

1. Login ke Bugcrowd → foto profil → **API Credentials**.
2. Isi nama kredensial → **Create credentials**, catat tokennya
   (format `username:password`, tidak ditampilkan lagi setelah refresh).
3. Simpan di env:

```text
export BUGCROWD_TOKEN="username:password"
```

Catatan: token Bugcrowd bisa dikunci ke **IP Allowlist** — bila request
ditolak dari IP yang tidak terdaftar, tambahkan IP itu di halaman
API Credentials. Limit: 60 request/menit per IP.

### Menyimpan token

- Pakai env shell atau file `.env` dengan mode **0600** (`chmod 600 .env`).
- **Jangan** commit token ke repo (`.env` sudah di `.gitignore`).
- Token tidak pernah di-log oleh modul ini (auth dikirim sebagai header,
  tidak pernah masuk ke output/temuan).

## Alur pakai (yang benar)

1. **Sinkron scope dulu** — sebelum hunting, bandingkan scope platform
   dengan file program lokal:

   ```js
   import { syncScopeToProgram } from "./bounty/lib/platforms.js";
   const diff = await syncScopeToProgram("hackerone", "acme", "programs/acme.md");
   // { added: [...], removed: [...], unchanged: [...] } — TANPA menulis file.
   ```

   Perbarui `programs/acme.md` secara manual (atau lewat persetujuan
   reviewer) bila ada `added`/`removed`. Scope yang salah = run terbuang
   + risiko ban.
2. **Cek duplikat sebelum menulis draf** — cari laporan publik yang sama:

   ```js
   import { searchHacktivity } from "./bounty/lib/platforms.js";
   const { results } = await searchHacktivity("hackerone", "SQL injection login");
   ```

   Bila ada laporan yang sama (judul + endpoint + kelas), jangan laporkan
   ulang — itu duplikat.
3. **Buat draf, review, kirim manual:**

   ```js
   import { draftReport } from "./bounty/lib/platforms.js";
   const md = draftReport({ title: "IDOR di /api/users/2", endpoint: "https://api.example.com/api/users/2", vulnClass: "IDOR", cwe: "CWE-639", severity: "high", evidence: "...", steps: "1. ..." });
   ```

   Draf diawali header `DRAFT — belum dikirim, kirim manual setelah
   review`. Verifikasi temuan, lengkapi bukti, lalu kirim lewat UI
   HackerOne/Bugcrowd.

## Yang TIDAK bisa / TIDAK dilakukan

- ❌ Mengirim laporan ke platform (tidak ada fungsi submit).
- ❌ Membayar bounty / deposit / award (tidak ada endpoint pembayaran).
- ❌ Mengubah scope program di platform (hanya baca).
- ❌ Mengakses laporan privat orang lain (hanya laporan publik + milik akun sendiri).
- ❌ Bugcrowd: tidak ada pencarian laporan publik (cek manual di UI).

## Error yang mungkin muncul

| Error | Artinya |
|---|---|
| `token belum diset (...)` | Env token/username belum diset. |
| `HTTP 401` | Token salah / kedaluwarsa / username salah. |
| `HTTP 403` | Akun tidak punya akses ke program itu (privat / belum diundang). |
| `HTTP 429` | Rate limit platform — tunggu, lalu ulangi. |
| `format hacktivity tidak dikenali` | Feed publik berubah bentuk (best-effort) — laporkan, jangan ditebak. |
| `program Bugcrowd tidak ditemukan` | Handle/UUID salah, atau program tidak bisa diakses akun itu. |
