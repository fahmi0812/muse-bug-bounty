# web2-recon — Recon web2 (peta permukaan sebelum hunt)

Kelas: Reconnaissance / Attack Surface Mapping | CWE: — | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan pindai host di luar scope, jangan sentuh layanan pihak ketiga.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Subdomain dan host terkait yang belum dipetakan (dari DNS publik target sendiri).
- Bundle JavaScript memuat nama endpoint, path API, dan kunci konfigurasi.
- Endpoint API terdaftar tapi tidak ada di UI (dari peta rute aplikasi).
- Parameter tersembunyi di form dan URL yang tidak dipakai UI.

## Cara memetakan
- Baca bundle JS aplikasi target, catat string path `/api/...` dan nama parameter.
- Bandingkan rute yang terlihat di UI dengan rute yang disebut di bundle.
- Catat endpoint yang merespons berbeda saat dipanggil dengan akun low vs high.
- Simpan peta sebagai daftar endpoint + metode + parameter + peran yang boleh.

## Chain template
Recon (peta endpoint) → endpoint yang tidak ada di UI → uji otorisasi peran → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Permukaan aplikasi lebih luas dari yang terlihat di UI; endpoint tersembunyi sering luput dari kontrol otorisasi.

## Verifikasi
- Replay dengan akun low harus ditolak bila endpoint itu sensitif.
- Simpan peta endpoint + bukti respons, redaksi isi sensitif.
