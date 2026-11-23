# trailofbits — Pola Audit Trail of Bits (ringkas)

> **Atribusi eksplisit:** pola di bawah terinspirasi praktik audit
> Trail of Bits dan dilisensikan **CC-BY-SA-4.0** oleh pemilik aslinya.
> Isi ini ditulis ulang secara orisinal untuk repo ini — **bukan vendor
> verbatim** dari materi Trail of Bits. Bila memakai kembali isi ini,
> sertakan atribusi ini dan bagikan dengan lisensi yang sama
> (CC-BY-SA-4.0).

## Kapan dipakai

- Audit mendalam / review kode target (bila scope mengizinkan) atau
  review temuan sebelum laporan: menilai kualitas temuan, skor severity,
  dan apakah perbaikan benar-benar menutup lubang.
- Dipakai setelah kandidat terverifikasi, sebelum laporan ditulis.

## Sub-skill

### fp-check — filter false positive

- Tanyakan untuk tiap kandidat: apakah ada kontrol yang sudah menutupnya
  (validasi, allowlist, WAF, autentikasi)? Apakah jalurnya reachable
  dari input yang dikendalikan penyerang? Apakah "dampak" butuh asumsi
  yang tidak terbukti (mis. akses yang tidak dimiliki)?
- Satu jawaban "sudah tertutup / tidak reachable / asumsi tak terbukti"
  → kandidat diturunkan atau dibuang, dengan alasan tertulis.

### cvss-scoring — CVSS v4.0

- Skor dengan CVSS v4.0: Base (exploitability + dampak), lalu Threat
  dan Environmental bila data program tersedia.
- Tulis tiap komponen skor (bukan hanya angka akhir) supaya reviewer
  program bisa memeriksa. Jangan menaikkan skor dengan dampak yang
  belum terbukti.
- Bila program memakai CVSS 3.1, catat keduanya dan pakai versi program
  sebagai acuan laporan.

### variant-analysis — cari varian dari satu temuan

- Satu bug jarang sendirian: cari pola yang sama di endpoint, parameter,
  dan modul lain (mis. satu SQLi → cek semua query di file yang sama;
  satu IDOR → cek semua handler dengan pola ID yang sama).
- Tiap varian diverifikasi sendiri — jangan klaim varian tanpa replay.

### semgrep-rule-creator — buat rule Semgrep

- Tulis rule Semgrep dari pola temuan (pattern + metavariable), uji
  terhadap kode rentan (harus kena) dan kode aman (tidak boleh kena).
- Rule yang lolos uji disimpan sebagai artefak audit; rule yang
  false-positive di kode aman → perbaiki atau buang.

### differential-review — review diferensial

- Bandingkan dua versi kode / dua implementasi yang seharusnya setara
  (mis. endpoint lama vs baru, dua role, dua parser): beda perilaku =
  sinyal bug (satu sisi lupa cek, satu sisi cek).
- Cocok untuk regression: perbaikan yang menutup satu jalur tapi
  membuka jalur lain.

### static-analysis — analisis statis

- Jalankan CodeQL / Semgrep, kumpulkan hasil sebagai SARIF.
- Saring: hasil statis = kandidat. Tiap kandidat butuh verifikasi manual
  / replay sebelum jadi finding. Jangan laporkan mentah hasil scanner.

### supply-chain-risk — risiko supply chain

- Nilai dependensi dan build: paket tanpa maintainer jelas, tanpa
  lockfile, script install yang menjalankan kode, atau dependensi
  yang diambil dari URL tak terverifikasi.
- Berkaitan dengan `vbsec-21.md` tipe 20 (slopsquatting): paket
  hasil saran AI harus diverifikasi di registry resmi.

### fix-review — review perbaikan

- Setelah perbaikan diklaim: cek apakah patch benar-benar menutup jalur
  (replay exploit lama harus gagal), apakah ada bypass (variasi input
  lain masih lolos), dan apakah patch merusak fungsi normal (regresi).
- Perbaikan yang hanya menutup satu payload tapi bukan akar masalah →
  laporkan sebagai incomplete fix, bukan confirmed fixed.

## Verifikasi non-destruktif

- Semua sub-skill di atas menghasilkan kandidat/penilaian, bukan bukti
  eksploitasi. Bukti eksploitasi tetap lewat `verify-adversarial.md`
  dengan replay terkontrol di akun/lab sendiri.
- Jangan ubah kode target, jangan hapus data, jangan kirim payload
  destruktif.
