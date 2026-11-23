# ghost-loop — Loop Ghostsecurity (ringkas)

> Atribusi: pola loop terinspirasi Ghostsecurity (Apache-2.0) — isi di bawah
> ditulis ulang secara orisinal untuk repo ini, bukan salinan verbatim.
> Lisensi sumber: Apache-2.0.

## Kapan dipakai

- Audit repo target (bila scope mengizinkan baca kode) atau repo sendiri:
  cari secret, dependensi rentan, dan pola kode AI yang berisiko — dalam
  satu loop tertib, bukan scan acak.
- Dipakai setelah scope OK dan sebelum hunting dalam; hasil loop ini
  adalah kandidat, bukan finding.

## Loop (4 fase)

### 1. Poltergeist — secret scanner

- Pola: 163+ rule deteksi secret (API key, token, private key, password)
  + skor entropi string.
- Cara: scan file kode/config/dokumen; tiap cocok dicatat dengan file:baris
  + jenis secret + entropi.
- Saring: contoh di docs/test, placeholder (`xxx`, `example`, `TODO`),
  dan secret palsu di fixture → buang.
- Verifikasi: JANGAN panggil secret itu ke layanan asli. Cek hanya
  bentuk/format + apakah secret masih dipakai (git history / referensi
  kode). Secret aktif yang terkonfirmasi → redaksi di bukti, laporkan
  lewat jalur aman program (lihat `evidence-hygiene.md`).

### 2. Wraith — dependency via OSV

- Pola: petakan dependensi (lockfile/manifest) → cek ke database OSV
  (vuln yang diketahui per versi) → nilai exploitability.
- Exploitability: rentan saja belum cukup — cek apakah kode rentan
  benar-benar dipanggil (jalur eksekusi dari kode target), apakah fungsi
  rentan terjangkau dari input, dan apakah versi ter-patch tersedia.
- Prioritas: reachable + exploit tersedia + versi patch ada → naik.
  Unreachable / hanya di dev-dependency → turun, catat alasannya.

### 3. Reaper — proxy MITM (traffic live)

- Pola: proxy di tengah antara klien dan server untuk melihat traffic
  HTTPS live (request/response, header, cookie, token).
- Dipakai saat: butuh bukti replay (bukan teori) — mis. token bocor di
  respons, header sensitif, atau alur auth yang aneh.
- Aturan: hanya traffic akun sendiri / lab; jangan rekam traffic orang
  lain; simpan capture lokal, perm 0600, jangan commit; redaksi
  secret/PII sebelum dilampirkan ke laporan.

### 4. Exorcist — analisis kode AI (102 tipe)

- Pola: 102 tipe vuln pada kode hasil AI — cek silang dengan
  `vbsec-21.md` (21 tipe inti di sini) untuk pola yang berulang.
- Cara: tiap file kode hasil AI dibaca dengan checklist; pola yang cocok
  dicatat sebagai kandidat.
- Bedakan: pola yang benar-benar dieksekusi vs dead code / contoh docs.

## Sub-skill (bagian dari loop ini)

### ghost-repo-context

- Kumpulkan konteks repo sebelum scan: bahasa, framework, struktur,
  dependensi utama, titik masuk (route/handler). Tanpa konteks, hasil
  scan penuh noise.

### ghost-scan-deps

- Jalankan fase Wraith: daftar dependensi + versi → OSV → nilai
  exploitability (dipanggil atau tidak). Output: tabel dependensi
  rentan yang reachable.

### ghost-validate

- Validasi tiap kandidat dari 4 fase: replay dengan input terkontrol,
  kontrol negatif (akun tanpa hak / input normal), cek maksud aplikasi.
  Gagal replay → UNVERIFIED (lihat `verify-adversarial.md`).

### ghost-proxy

- Jalankan fase Reaper: setup proxy, rekam traffic sesi sendiri,
  petakan request/response ke kandidat finding. Capture = bukti,
  bukan finding.

## Verifikasi non-destruktif

- Secret: jangan dipakai untuk login/panggil API asli.
- Dependensi: jangan exploit; cukup buktikan jalur pemanggilan.
- Proxy: hanya sesi sendiri; jangan intercept orang lain.
- Semua kandidat → `verify-adversarial.md` sebelum naik jadi finding.
