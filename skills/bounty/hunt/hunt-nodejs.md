# hunt-nodejs — Node.js security (pola rawan di aplikasi Node)

Kelas: Application Security | CWE: CWE-400, CWE-20, CWE-94 | OWASP: A03:2021, A04:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan jalankan kode di server target; uji hanya perilaku yang terlihat dari respons.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Objek JSON dari pengguna digabung ke objek internal tanpa filter kunci.
- Nama kunci khusus (seperti kunci prototipe) mengubah perilaku objek hasil.
- Input yang dipakai sebagai pola pencarian membuat server lambat luar biasa.
- Serialisasi/deserialisasi menerima struktur yang tidak pernah dipakai UI.

## Cara menguji
- Kirim field tambahan di body JSON, lihat apakah tersimpan atau memengaruhi respons.
- Kirim pola pencarian yang sangat panjang/bersarang, ukur waktu respons (sekali, jangan spam).
- Bandingkan perilaku akun low vs high pada endpoint yang sama.
- Catat dependensi yang disebut di error atau header, cek apakah versinya rawan (baca saja).

## Chain template
Input JSON longgar → objek internal berubah → aksi di luar peran akun test → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Input pengguna digabung mentah ke objek internal; pola pencarian tidak dibatasi; dependensi lama tidak diperbarui.

## Verifikasi
- Replay dengan input normal harus kembali normal; input aneh harus ditolak atau tidak berpengaruh.
- Simpan request/response + waktu respons, redaksi isi sensitif.
