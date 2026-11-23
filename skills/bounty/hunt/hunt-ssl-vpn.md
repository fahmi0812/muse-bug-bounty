# hunt-ssl-vpn — SSL-VPN Appliances (Fortinet / Palo Alto / Citrix)

Kelas: Authentication Bypass / RCE | CWE: CWE-287, CWE-78 | OWASP: A07:2021

Ditulis dari pola publik (CVE/penelitian publik) — rantai CVE SSL-VPN 2023–2025.

## Scope & larangan
- Hanya appliance VPN yang eksplisit ada di scope program.
- Jangan uji VPN pihak ketiga atau produksi yang tidak di-scope.
- Jangan jalankan exploit RCE ke target nyata — deteksi versi dan laporkan, validasi hanya di lab sendiri.
- Jangan tebak password / brute force. Berhenti saat kena rate limit / 429.

## Detection pattern
- Appliance versi rentan (cek banner/versi di endpoint yang di-scope):
  - Fortinet FortiOS: CVE-2024-21762 — auth bypass SSL VPN (Feb 2024); CVE-2024-55591 — auth bypass (Jan 2025, dieksploitasi aktif); CVE-2023-27997 — RCE (Jun 2023).
  - Palo Alto GlobalProtect: CVE-2024-3400 — RCE command injection (Apr 2024, dieksploitasi aktif); CVE-2024-5910 — privilege escalation.
  - Citrix NetScaler ADC/Gateway: CVE-2023-3519 — RCE (Jul 2023); CVE-2023-4966 — "Citrix Bleed", session hijacking (Okt 2023).
- Portal VPN bisa diakses dari internet tanpa MFA.
- Session token VPN bisa dipakai ulang setelah logout (Citrix Bleed class).
- Endpoint admin appliance terekspos ke internet.

## Payload contoh
- Ambil versi appliance dari banner/portal yang di-scope, cocokkan dengan daftar CVE di atas.
- Cek apakah portal VPN minta MFA untuk akun test.
- Cek apakah session token test masih valid setelah logout.

## Bypass
- Versi yang sudah di-patch tidak lagi rentan — catat versi dan tutup.
- Bila portal tidak bisa diakses dari luar, catat sebagai tidak terekspos.

## Chain template
Appliance versi rentan + portal terekspos → bypass auth / RCE → akses jaringan internal → baca data, kunci pemilik keluar — laporkan di titik bukti cukup (versi + eksposur).

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (jaringan internal, data, kredensial)?
3. Bisakah dibuktikan dari versi + eksposur tanpa menjalankan exploit?

## Root cause
Appliance VPN terekspos ke internet dengan versi tidak di-patch, atau tanpa MFA dan session yang tidak dicabut.

## Verifikasi
- Buktikan dari nomor versi + portal yang terbuka, bukan dari exploit yang dijalankan.
- Simpan banner/versi, redaksi token/session.
