# review-pr — Review PR Diff-Aware

> Atribusi: pola terinspirasi `anthropics/claude-code-security-review`
> (review PR diff-aware) — isi di bawah ditulis ulang secara orisinal
> untuk repo ini, bukan salinan verbatim.

## Kapan dipakai

- Ada pull request / diff kode baru yang perlu direview keamanannya
  sebelum merge — di repo sendiri atau repo target (bila scope
  mengizinkan baca kode).
- Dipakai saat: PR masuk, sebelum merge, atau saat triage perubahan
  yang menyentuh auth, input user, query, upload, atau dependensi.

## Checklist review

1. **Scope diff dulu.** Baca hanya baris yang berubah + konteks
   secukupnya. Jangan review seluruh repo tiap PR.
2. **Titik rawan.** Tandai perubahan yang menyentuh: autentikasi/
   otorisasi, input user → query/perintah/template, upload file,
   parsing XML/deserialisasi, kripto, secret/config, dependensi baru.
3. **Cocokkan pola.** Untuk tiap titik rawan, cocokkan dengan
   `vbsec-21.md` (21 tipe) dan skill `hunt-*` yang relevan.
4. **Cek test.** Apakah PR menambah/mengubah test untuk jalur yang
   diubah? Perubahan tanpa test di jalur sensitif = sinyal risiko.
5. **Cek dependensi baru.** Paket baru → verifikasi di registry resmi
   (lihat `vbsec-21.md` tipe 20, slopsquatting).
6. **Cek secret.** Tidak ada secret/kunci baru di diff (lihat
   `ghost-loop.md` fase Poltergeist).

## Komentar inline

- Satu komentar per masalah, di baris yang tepat, dengan: apa masalahnya,
  kenapa berbahaya (dampak konkret), dan saran perbaikan (kode aman).
- Bedakan severity: `blocking` (harus diperbaiki sebelum merge) vs
  `nit` (saran, bukan blocker). Jangan blokir PR karena nit.
- Jangan menulis komentar generik tanpa lokasi ("kode ini tidak aman").

## Second-pass false-positive filter

- Setelah pass pertama, baca ulang tiap temuan dengan kacamata pembela
  kode: apakah sudah ada validasi di tempat lain? Apakah jalurnya
  unreachable? Apakah ini pola yang dimaksud (mis. data publik)?
- Temuan yang terbantah → hapus komentarnya, catat alasan singkat.
- Hanya temuan yang lolos second-pass yang disampaikan ke author PR.
- Prinsipnya sama dengan `verify-adversarial.md`: tugasmu membantah,
  bukan membenarkan.

## Template GitHub Action

- File workflow: `.github/workflows/security-review.yml` (di repo ini).
- Cara kerja: saat PR dibuka/di-update, action menjalankan review
  diff-aware dan menulis komentar inline + ringkasan; temuan
  `blocking` menandai check gagal, `nit` tidak.
- Action ini TIDAK menggantikan review manusia — ia antrean awal.
  Keputusan merge tetap di tangan reviewer.
- Jangan jalankan action ini di repo yang di luar scope / tanpa izin.

## Verifikasi non-destruktif

- Review hanya membaca diff; tidak mengubah kode target, tidak
  menjalankan payload ke layanan nyata.
- Bila perlu membuktikan temuan, replay di lab / akun sendiri dengan
  input terkontrol (lihat `verify-adversarial.md`).
