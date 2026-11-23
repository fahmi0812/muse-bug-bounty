# triage-validation — Verdict Kandidat Temuan

Satu kandidat, satu verdict. Jangan naikkan verdict karena "kelihatannya parah".

## Verdict

### confirmed
- Replay berhasil dari sesi bersih, langkah tercatat.
- Dampak nyata terbukti (baca data orang lain / lakukan aksi terlarang).
- Masuk scope, bukan perilaku yang dimaksud aplikasi.
- Boleh ditulis jadi laporan.

### needs_validation
- Ada sinyal, tapi replay belum bersih / langkah belum lengkap.
- Dampak belum terbukti, atau butuh akun/role lain untuk menguji.
- Tindakan: kembali ke hunt + `verify-adversarial.md`, jangan lapor dulu.

### rejected
- Tidak bisa di-replay, atau ternyata perilaku yang dimaksud.
- Out-of-scope, duplikat, atau false positive yang terbukti.
- Tindakan: catat alasannya satu baris, lalu buang.

## Cara menilai
1. Replay dari nol: akun baru/bersih, browser bersih, langkah bernomor.
2. Uji kontrol negatif: akun tanpa hak yang sama harus GAGAL.
   Kalau kontrol negatif juga berhasil, itu mungkin perilaku umum.
3. Uji batas: ubah satu variabel saja per percobaan.
4. Cek dedup: Hacktivity program + daftar temuan sendiri.
5. Cek scope: endpoint di Allowed? Bukan Denied?

## Catatan triage (simpan per kandidat)
- Target + endpoint + parameter, tanggal, akun yang dipakai (milik sendiri).
- Request/response kunci (sudah diredaksi).
- Verdict + alasan satu kalimat + langkah berikutnya.
