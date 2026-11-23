# evidence-hygiene — Bukti Bersih

Bukti yang bocor kredensial bisa membatalkan laporan — atau lebih buruk,
membocorkan akun orang lain.

## Yang wajib diredaksi (ganti dengan `[REDACTED]`)
- Cookie sesi, token JWT utuh, API key, Authorization header.
- Password, OTP, kode reset, token reset password.
- PII orang lain: nama, email, nomor telepon, alamat, KTP, kartu.
- Kunci privat, isi `.env`, connection string database.

## Screenshot
- Potong hanya area relevan; tutup bar alamat bila ada token di URL.
- Blur/potong nama/email korban lain yang ikut tampil.
- Jangan lampirkan screenshot DevTools berisi cookie mentah.

## HAR / request-response mentah
- Hapus header `Cookie`, `Authorization`, `X-Api-Key` sebelum simpan.
- Hapus body berisi password/token; sisakan field yang relevan.
- Simpan HAR hasil edit di folder bukti, bukan HAR mentah dari browser.

## Penyimpanan
- Bukti mentah (sebelum redaksi) hanya di mesin lokal, jangan diunggah.
- Yang diunggah / dilampirkan ke platform hanya versi yang diredaksi.
- File bukti beri nama jelas: `YYYY-MM-DD-<target>-<kelas>.md`.
- Jangan commit bukti berisi token ke repo, sekalipun repo privat.

## Cek akhir sebelum lampirkan
- Cari di bukti: `Cookie:`, `Authorization:`, `token=`, `@`, nomor HP.
- Jika ada satu pun yang lolos → redaksi ulang, jangan kirim.
