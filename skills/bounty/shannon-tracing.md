# shannon-tracing — Tracing Source → Hipotesis → Exploit Live

> **PENTING — AGPL:** pola di bawah terinspirasi Shannon (AGPL).
> Ini **POLA SAJA** — jangan salin kode Shannon ke repo ini
> (repo ini Apache-2.0; kode AGPL tidak boleh disalin ke sini).
> Tulis ulang polanya dengan kata-katamu sendiri bila mengembangkannya.

## Kapan dipakai

- Target white-box (kode tersedia dan scope mengizinkan baca kode):
  lacak alur data dari sumber sampai sink, buat hipotesis, lalu buktikan
  dengan exploit live yang terkontrol.
- Bounty mayoritas black-box — skill ini P1, bukan P0. Dipakai bila
  kode tersedia; bila tidak, pakai skill `hunt-*` biasa.

## Prinsip: "no exploit, no report"

- Hipotesis tanpa bukti live = bukan laporan. Tiap klaim harus punya
  replay yang berhasil di sesi bersih, akun sendiri / lab.
- Gagal replay → UNVERIFIED, berhenti. Jangan menulis laporan dari
  teori source-code saja.

## Pola tracing (3 langkah)

### 1. Source — dari mana data masuk

- Petakan semua sumber input: parameter URL/body/header, upload file,
  webhook, pesan antrean, data dari layanan lain.
- Untuk tiap sumber, catat: tipe data, siapa yang mengendalikannya
  (user terautentikasi? anonim?), dan apakah sampai ke sink berbahaya.

### 2. Hipotesis — jalur serangan yang mungkin

- Lacak alur data (taint flow) dari source ke sink: query DB, perintah
  shell, template, redirect, deserialisasi, query LDAP, dsb.
- Tulis hipotesis dalam satu kalimat per jalur: "Input X di endpoint Y
  sampai ke sink Z tanpa validasi A, sehingga memungkinkan B."
- Prioritaskan hipotesis dengan sink paling berbahaya + input paling
  terkontrol penyerang. Buang hipotesis yang jalurnya terputus oleh
  validasi/encoding (catat kenapa terputus).

### 3. Exploit live — buktikan

- Uji hipotesis dengan payload minimal di lab / akun sendiri.
- Mulai dari yang paling ringan (deteksi: error, delay kecil, perubahan
  perilaku), baru naik ke pembuktian dampak bila perlu — dan hanya
  sejauh bukti cukup untuk laporan.
- Simpan request/response lengkap sebagai bukti; redaksi secret/PII
  (lihat `evidence-hygiene.md`).

## Menangani 2FA / TOTP / SSO

- Alur yang dilindungi 2FA/TOTP/SSO: jangan coba bypass mekanisme
  itu (di luar scope kebanyakan program + berisiko).
- Yang boleh diuji: logika di sekitarnya dengan sesi sendiri yang sah
  (mis. apakah sesi low-priv bisa memakai fungsi high-priv setelah
  login normal — lihat `hunt-broken-access.md`).
- Bila program secara eksplisit mengizinkan pengujian 2FA/SSO,
  ikuti aturan program itu dan dokumentasikan izinnya.

## Laporan

- Format: source → hipotesis → bukti replay → dampak.
- Sertakan jalur lengkap (file:baris bila dari kode) + request/response.
- Bila hipotesis terbantah di langkah 3, tulis sebagai REJECTED dengan
  alasan — itu hasil yang berguna, bukan kegagalan.

## Verifikasi non-destruktif

- Jangan hapus/ubah data, jangan ambil data orang lain, jangan DoS.
- Payload destruktif (DROP/DELETE massal, penghapusan akun) DILARANG.
- Semua bukti lewat `verify-adversarial.md` sebelum jadi finding.
