# hunt-websocket — WebSocket Hijacking & Abuse

Kelas: Broken Access Control | CWE: CWE-1385 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan kirim pesan atas nama user nyata lewat socket mereka.
- Berhenti saat kena rate limit / 429.

## Detection pattern
- Handshake WebSocket tidak cek header `Origin`.
- Token / cookie sesi tidak dicek ulang saat handshake, atau tidak dicek per pesan.
- Pesan WebSocket mengubah data tanpa cek kepemilikan / peran.
- Pesan dari satu user disiarkan ke user lain tanpa filter.

## Payload contoh
- Buka socket dari origin test milikmu dengan cookie akun test — uji apakah handshake diterima.
- Kirim pesan aksi (mis. ubah profil / kirim chat) dengan `user_id` akun test lain.
- Kirim pesan tanpa token setelah handshake — uji apakah masih diproses.

## Bypass
- Coba handshake tanpa `Origin` / dengan `Origin: null`.
- Coba pakai token lama / cookie yang sudah logout.
- Bila diblokir, catat dan berhenti.

## Chain template
Handshake tanpa cek Origin / auth → situs jahat membuka socket atas nama akun test korban → kirim / baca pesan sebagai korban — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
WebSocket tidak mewarisi perlindungan CSRF / origin dari HTTP; auth hanya dicek sekali saat handshake, bukan per pesan.

## Verifikasi
- Replay: dari origin test, buka socket dan kirim pesan sebagai akun test korban yang sedang login.
- Buktikan dengan dua akun test milikmu, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
