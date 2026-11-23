# hunt-deserialization — Insecure Deserialization (deteksi)

Kelas: Deserialization | CWE: CWE-502 | OWASP: A08:2021

Fokus: DETEKSI saja. Jangan kirim objek berbahaya, jangan picu eksekusi, jangan ubah state server. Bukti cukup = server menerima dan memproses objek serial tanpa validasi (respons berubah / error tipe objek).

## Detection pattern
- Parameter berisi objek serial (base64 / JSON dengan `__type__` / `$type`).
- Error menyebut nama class / deserializer internal.
- Mengubah tipe objek mengubah perilaku server.

## Payload contoh
- Ubah field `__type__` ke nama class lain yang tidak berbahaya (lab saja).
- Kirim objek dengan field tambahan yang tidak dikenal — uji apakah diproses.
- Ubah format serial (JSON ↔ XML) pada endpoint yang sama.

## Bypass
- Coba format serial lain bila satu format ditolak.
- Catat dan hentikan bila filter tipe aktif.

## Chain template
Deserialisasi tanpa validasi → bukti pemrosesan objek →
dampak — laporkan di titik bukti pemrosesan, tanpa eksekusi lanjutan.

## Verifikasi
- Replay dengan objek normal harus kembali normal.
- Tanpa replay, label UNVERIFIED.
- Simpan request/response, redaksi isi objek sensitif.
