# hunt-clickjacking — Clickjacking / UI Redressing

Kelas: UI Redressing | CWE: CWE-1021 | OWASP: A04:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Uji framing di browser lab milikmu sendiri; jangan menjebak pengguna nyata.
- Jangan laporkan halaman publik/read-only sebagai clickjacking.

## Detection pattern
- Respons halaman sensitif tanpa `X-Frame-Options` DAN tanpa CSP `frame-ancestors` = kandidat frameable.
- `X-Frame-Options: DENY` / `SAMEORIGIN` atau `frame-ancestors 'none'` / `'self'` = terlindungi, berhenti.
- Target bernilai: login, transfer/konfirmasi pembayaran, ubah email/password, matikan 2FA, dialog "Authorize" OAuth, aksi admin.

## Sinyal uji
- `curl -sI <halaman>` → periksa kedua header di atas (screening saja).
- Buktikan di browser nyata dengan iframe transparan: halaman target benar-benar tampil di dalam iframe (tidak ada framebusting `if(top!==self)`).
- Aksi sensitif harus tetap jalan saat di-frame: cookie sesi harus ikut terkirim lintas situs. Cookie `SameSite=Lax/Strict` yang tidak terkirim = clickjack gagal.
- Aksi harus state-changing (transfer, ubah pengaturan, otorisasi) — halaman baca saja bukan temuan.

## Bypass
- Tidak ada "bypass" di sini — yang diuji adalah apakah proteksi framing + cookie benar-benar menggagalkan serangan; bila salah satu menahan, bukan temuan.

## Chain template
Halaman aksi sensitif tanpa proteksi framing + cookie sesi terkirim lintas situs → korban diklik diam-diam → aksi berjalan atas nama korban (transfer, ubah email, otorisasi OAuth).

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Header anti-framing tidak diset di halaman sensitif; cookie sesi tanpa `SameSite` ketat; tidak ada framebusting atau konfirmasi ulang aksi sensitif.

## Verifikasi
- Header hilang saja BUKAN temuan — wajib PoC frame di browser nyata + aksi sensitif yang berhasil.
- Simpan screenshot/rekaman overlay + respons header sebagai bukti.
- Halaman publik tanpa aksi = Low/informasional; API/JSON/gambar bukan target clickjacking.
