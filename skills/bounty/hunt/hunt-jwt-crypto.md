# hunt-jwt-crypto — JWT crypto (token yang bisa dipalsukan)

Kelas: Broken Authentication / Cryptography | CWE: CWE-327, CWE-347 | OWASP: A02:2021, A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan tebak/brute-force rahasia penanda tangan; uji hanya perilaku verifikasi token.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Token diterima walau algoritme penandanya diganti ke "tidak ada".
- Token yang ditandatangani dengan kunci publik diterima sebagai kunci rahasia.
- Kunci penanda lemah atau bisa ditebak dari materi publik aplikasi.
- Token lama tetap berlaku setelah ganti kata sandi atau logout.

## Cara menguji
- Minta token akun low, ubah klaim perannya, kirim lagi — harus ditolak.
- Coba token dengan algoritme penanda kosong — harus ditolak.
- Coba token akun low yang kadaluarsa — harus ditolak.
- Logout akun test, lalu coba pakai token lamanya — harus ditolak bila sudah dicabut.

## Chain template
Token lemah → klaim peran diubah → akses di luar peran akun test → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Verifikasi token tidak memeriksa algoritme dan kunci dengan benar; pencabutan token tidak ditegakkan.

## Verifikasi
- Replay dengan token asli harus jalan; token yang diubah harus ditolak.
- Simpan token uji (akun test saja) + respons, redaksi isi sensitif.
