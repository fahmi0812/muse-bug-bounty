# hunt-shadow-api — Shadow / Zombie API

Kelas: Improper Inventory Management | CWE: CWE-200, CWE-862 | OWASP: API9:2023

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan panggil endpoint versi lama untuk mengubah data akun orang lain.
- Jangan pakai data arsip (Wayback) di luar target in-scope.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Path berversi hidup berdampingan (`/api/v1/`, `/v2/`, `/beta/`, `/legacy/`) — versi lama merespons selain 404.
- Header versi (`X-API-Version`, `Accept: application/vnd.*.v1+json`) mengubah perilaku.
- Spesifikasi OpenAPI/Swagger lama masih bisa diunduh (termasuk dari arsip) dan rutenya masih hidup.
- Changelog menyebut endpoint yang "sudah dihapus" tapi masih merespons.
- Aplikasi mobile memanggil backend lebih lama dari yang dipakai web saat ini.

## Payload contoh
- Minta `/api/v1/`, `/api/v2/`, `/api/beta/`, `/api/legacy/` — catat yang tidak 404.
- Unduh `openapi.json` / `swagger.json` tiap versi, lalu bandingkan daftar path-nya.
- Uji operasi yang sama di versi lama vs baru dengan akun low — cari selisih auth/validasi.

## Bypass
- Versi lama sering lolos dari perbaikan versi baru — selisih perilaku adalah temuannya, bukan sekadar beda bentuk respons.
- Bila versi lama butuh auth, tetap catat sebagai hidup — jangan klaim mati hanya karena 401/403.

## Chain template
Versi API lama masih hidup → auth/validasi versi lama lebih lemah → operasi sensitif lolos dengan akun low → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Inventaris API tidak dijaga — versi lama dan rute internal tetap deploy tanpa perbaikan keamanan versi terbaru.

## Verifikasi
- Replay di versi baru harus ditolak/di-validasi — selisihnya adalah bukti.
- Buktikan hanya pada data akun test sendiri.
- Simpan daftar path + respons tiap versi, redaksi isi sensitif.
