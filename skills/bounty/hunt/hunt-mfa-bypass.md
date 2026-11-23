# hunt-mfa-bypass — MFA tidak ditegakkan (celah logika verifikasi dua langkah)

Kelas: Broken Authentication | CWE: CWE-307, CWE-287 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- DILARANG menebak/brute-force kode MFA, OTP, atau kode pemulihan — uji hanya celah logika penegakan, bukan menebak kode.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Langkah MFA bisa dilewati dengan langsung membuka halaman sesudah login.
- Aksi sensitif (ganti kata sandi, ganti email, tarik dana) tidak meminta ulang MFA.
- Status MFA tidak terikat ke sesi: sesi lama tetap berlaku setelah MFA diaktifkan.
- Alur pemulihan akun (lupa kata sandi) tidak meminta MFA padahal akun punya MFA.
- Kode pemulihan bisa dipakai berulang kali atau tidak pernah kedaluwarsa.

## Cara menguji
- Login akun test low dengan MFA aktif, lalu coba buka halaman pasca-login secara langsung.
- Coba aksi sensitif akun test tanpa menyelesaikan MFA.
- Coba alur lupa kata sandi akun test yang MFA-nya aktif, amati apakah MFA diminta.
- Aktifkan MFA di akun test, lalu coba pakai sesi yang dibuat sebelum MFA aktif.

## Chain template
MFA tidak ditegakkan → aksi sensitif tanpa verifikasi kedua → akun test terpengaruh → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Penegakan MFA hanya di satu jalur login, tidak di semua jalur dan aksi sensitif; status MFA tidak terikat ke sesi.

## Verifikasi
- Replay dengan akun test yang MFA-nya aktif harus selalu diminta MFA di tiap jalur.
- Simpan langkah replay + respons, redaksi isi sensitif.
