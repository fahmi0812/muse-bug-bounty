# audit-context-building — Membangun Konteks Audit

Kelas: Methodology | CWE: CWE-1050 | OWASP: A04:2021 Insecure Design

Diadaptasi dari Trail of Bits (CC-BY-SA-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan pakai akun user nyata, jangan curi token orang lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Mulai audit tanpa membaca kode dulu: peta permukaan dari luar (route,
  endpoint, parameter, peran user) sebelum membuka satu file pun.
- Trust boundary tidak jelas: data dari user, file upload, webhook, atau
  service lain diperlakukan sama seperti data internal tepercaya.
- Asumsi tersembunyi: "hanya admin yang bisa ke sini", "input ini selalu
  angka", "token ini tidak bisa ditebak" — tidak pernah ditulis, apalagi
  diuji.
- Permukaan luas tapi prioritas tidak ada: semua endpoint dianggap sama
  penting, sehingga yang paling berbahaya tidak pernah disentuh.

## Cara membangun konteks
- Baca kode dari pinggir ke tengah: route → controller/handler → service
  → model/database. Catat setiap tempat data user masuk dan keluar.
- Gambar trust boundary: siapa (user low/high, admin, service lain,
  publik) boleh apa, di mana batasnya, dan apa yang terjadi bila batas
  itu dilewati.
- Tulis daftar asumsi secara eksplisit ("asumsi: session tidak bisa
  ditebak"), lalu uji satu per satu — asumsi yang tidak teruji adalah
  temuan yang menunggu.
- Prioritaskan permukaan: autentikasi, otorisasi, uang/pembayaran,
  upload file, lalu sisanya. Kerjakan dari yang paling berdampak.

## Chain template
Konteks lengkap (peta + boundary + asumsi) → asumsi yang runtuh saat
diuji → celah di permukaan prioritas → dampak — laporkan di titik
bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Audit dimulai dari kode acak tanpa peta; asumsi keamanan tidak pernah
ditulis dan tidak pernah diuji, sehingga celah di permukaan paling
berdampak tidak terlihat.

## Verifikasi
- Replay dengan akun low-priv harus gagal; dengan akun test korban (milikmu) berhasil.
- Buktikan dengan akun test sendiri, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
