# verify-adversarial — Membantah Kandidat, Bukan Membenarkan

Peranmu di sini adalah lawan, bukan pembela. Tugasmu membuktikan
kandidat itu BUKAN bug. Kalau gagal membantahnya, barulah ia kuat.

## Prinsip
- Asumsi awal: kandidat salah / false positive / perilaku dimaksud.
- Cari penjelasan paling sederhana yang bukan kerentanan.
- Satu replay gagal = sinyal kuat, bukan "coba lagi dengan cara lain".

## Langkah bantahan
1. **Replay bersih.** Sesi baru, akun sendiri, langkah dari nol.
   Gagal replay → UNVERIFIED, berhenti di sini.
2. **Kontrol negatif.** Akun tanpa hak / tanpa login harus gagal.
   Kalau ikut berhasil, mungkin itu data publik / perilaku umum.
3. **Ubah satu variabel.** Ganti ID, role, atau header satu per satu.
   Kalau hasil tidak berubah, penyebabnya mungkin bukan variabel itu.
4. **Cek maksud aplikasi.** Apakah fitur memang dirancang begitu
   (mis. data profil publik, share link yang sengaja bisa dibuka)?
5. **Cek scope & dedup.** Out-of-scope atau sudah dilaporkan orang lain?

## Label
- **UNVERIFIED** — tidak bisa di-replay, atau replay belum bersih.
  Jangan naikkan severity, jangan tulis laporan dulu.
- **CONFIRMED** — semua bantahan gagal; replay + kontrol negatif konsisten.
- **REJECTED** — satu bantahan berhasil membuktikan bukan bug.

## Yang dilarang saat verifikasi
- Mengubah payload terus sampai "akhirnya kena" lalu mengklaim itu bukti.
- Memakai data/ akun orang lain sebagai korban.
- Melewati rate limit / jam otomasi program demi replay.
