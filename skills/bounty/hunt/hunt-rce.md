# hunt-rce — Remote Code Execution (deteksi)

Kelas: Injection / Deserialization | CWE: CWE-94 | OWASP: A03:2021

Fokus skill ini: DETEKSI dan bukti non-destruktif saja. Jangan jalankan perintah sistem, jangan hapus/ubah file, jangan buka shell. Bukti cukup = respons yang membuktikan input dievaluasi sebagai kode (mis. output fungsi waktu / matematika sederhana di lab).

## Detection pattern
- Input template / ekspresi dievaluasi server (mis. `7*7` jadi `49` di respons).
- Error berisi stack trace / nama fungsi internal.
- Parameter nama file / perintah diteruskan ke shell tanpa sanitasi.
- Deserialisasi objek tanpa validasi tipe / signature.

## Payload contoh
- `{{7*7}}` — uji evaluasi template (lab saja).
- `7*7` di kolom kalkulasi — bandingkan respons dengan input polos.
- Header `Content-Type` yang salah pada endpoint deserialisasi.

## Bypass
- Coba variasi sintaks template bila satu sintaks diblokir.
- Catat dan hentikan bila filter aktif — jangan kejar bypass agresif.

## Chain template
Input dievaluasi → bukti evaluasi (output fungsi sederhana) →
dampak (baca file / eksekusi) — laporkan di titik bukti evaluasi cukup, tanpa eksekusi lanjutan.

## Verifikasi
- Replay dengan input normal harus kembali normal.
- Bukti harus bisa di-replay; tanpa replay, label UNVERIFIED.
- Jangan simpan output sistem; redaksi path internal.
