# hunt-vcenter — VMware vCenter / ESXi

Kelas: Remote Code Execution / Privilege Escalation | CWE: CWE-122, CWE-862 | OWASP: A01:2021

Ditulis dari pola publik (CVE/penelitian publik) — rantai CVE vCenter 2024–2025.

## Scope & larangan
- Hanya vCenter/ESXi yang eksplisit ada di scope program.
- Jangan uji vCenter pihak ketiga atau produksi yang tidak di-scope.
- Jangan jalankan exploit RCE ke target nyata — deteksi versi dan laporkan, validasi hanya di lab sendiri.
- Jangan ubah konfigurasi host/VM — hanya baca dan laporkan.

## Detection pattern
- vCenter versi rentan (cek banner/versi di endpoint yang di-scope):
  - CVE-2024-37079 — heap-overflow RCE di DCE/RPC (Jun 2024).
  - CVE-2024-37080 — privilege escalation ke root (Jun 2024).
  - CVE-2024-38812 — heap-overflow RCE (Okt 2024).
  - CVE-2025-22224 — heap-overflow RCE (Mar 2025, dieksploitasi aktif).
  - CVE-2025-22225 — authentication bypass (Mar 2025).
  - CVE-2025-22226 — information disclosure (Mar 2025).
- Layanan DCE/RPC (port 2012/2014/2020) terbuka ke internet.
- Akun SSO dengan hak lebar dipakai aplikasi pihak ketiga.
- ESXi host memakai kredensial default atau password lemah (hanya cek kebijakan, jangan brute force).

## Payload contoh
- Ambil versi vCenter dari endpoint yang di-scope, cocokkan dengan daftar CVE di atas.
- Cek port DCE/RPC terbuka dari luar (hanya koneksi TCP, tanpa exploit).
- Cek apakah akun SSO test punya hak admin yang tidak perlu.

## Bypass
- Versi yang sudah di-patch tidak lagi rentan — catat versi dan tutup.
- Bila vCenter tidak bisa diakses dari luar, catat sebagai tidak terekspos.

## Chain template
vCenter versi rentan + layanan terekspos → RCE / bypass auth → kontrol host ESXi dan semua VM → baca data, kunci pemilik keluar — laporkan di titik bukti cukup (versi + eksposur).

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (host, VM, data)?
3. Bisakah dibuktikan dari versi + eksposur tanpa menjalankan exploit?

## Root cause
Layanan manajemen (DCE/RPC, SSO) terekspos ke jaringan yang tidak tepercaya dan versi tidak di-patch.

## Verifikasi
- Buktikan dari nomor versi + port yang terbuka, bukan dari exploit yang dijalankan.
- Simpan banner/versi, redaksi kredensial.
