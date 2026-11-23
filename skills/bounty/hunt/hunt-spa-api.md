# hunt-spa-api — SPA Hidden Backend API

Kelas: Broken Access Control | CWE: CWE-862 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan panggil API backend untuk mengubah data akun orang lain.
- Jangan pakai kunci yang terpanen di bundle untuk login sebagai orang lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Halaman login terproteksi tapi API di belakangnya tidak — halaman login aman tidak berarti API aman.
- Bundle JS SPA (React/Vue/Angular/Next) berisi host, rute, dan kadang kunci backend.
- Subdomain `console`, `app`, `dashboard`, `portal`, `admin` mengarah ke SPA.
- Chunk async (lazy-load) menyimpan rute tambahan di luar bundle utama.
- Rute ditemukan sebagai segmen string (`"account/payment/list"`), bukan URL penuh.

## Payload contoh
- Unduh shell HTML, petakan semua bundle JS, lalu panen host API + string rute dari bundle.
- Cari juga chunk async lewat peta chunk di bundle utama, unduh, panen ulang.
- Tentukan kontrol: minta endpoint yang seharusnya terproteksi tanpa auth — catat bentuk penolakan yang benar (401 / pesan auth).
- Minta tiap rute tanpa header `Authorization`, bandingkan dengan kontrol.

## Bypass
- Grup rute di host API kedua sering luput dari middleware auth — uji tiap host, bukan satu.
- Rute dengan metode berbeda (GET vs POST) bisa punya aturan auth berbeda — uji keduanya.
- Bila respons 200 tapi isinya kosong/generik, jangan klaim temuan — butuh data nyata akun test.

## Chain template
Bundle SPA memetakan API → rute sensitif tanpa auth → data/fungsi akun lain terbuka → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Auth ditegakkan di gateway/login, bukan di tiap grup rute API; peta rute lengkap dikirim ke browser lewat bundle.

## Verifikasi
- Replay dengan kontrol yang memang tertolak — selisih respons adalah bukti.
- Buktikan hanya pada data akun test sendiri.
- Simpan request/response, redaksi isi sensitif.
