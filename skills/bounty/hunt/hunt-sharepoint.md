# hunt-sharepoint — Microsoft SharePoint

Kelas: Remote Code Execution / Spoofing | CWE: CWE-94, CWE-290 | OWASP: A01:2021

Ditulis dari pola publik (CVE/penelitian publik) — rantai CVE SharePoint 2023–2025.

## Scope & larangan
- Hanya SharePoint yang eksplisit ada di scope program.
- Jangan uji SharePoint pihak ketiga atau produksi yang tidak di-scope.
- Jangan jalankan exploit RCE ke target nyata — deteksi versi dan laporkan, validasi hanya di lab sendiri.
- Jangan ubah konten situs — hanya baca dan laporkan.

## Detection pattern
- SharePoint Server versi rentan (cek versi di endpoint yang di-scope):
  - CVE-2025-53770 — RCE "ToolShell" (Jul 2025, dieksploitasi aktif).
  - CVE-2025-53771 — spoofing "ToolShell" (Jul 2025).
  - CVE-2025-49704 — RCE (Jul 2025).
  - CVE-2025-49706 — spoofing (Jul 2025).
  - CVE-2024-38094 — RCE (Jul 2024).
  - CVE-2023-29357 — privilege escalation (Jun 2023).
- Endpoint `_layouts/15/ToolPane.aspx` atau API SharePoint bisa diakses tanpa auth yang benar.
- Akun dengan hak rendah bisa mengunggah/menjalankan web part atau mengubah halaman.
- SharePoint Online: guest bisa membaca situs yang seharusnya internal.

## Payload contoh
- Ambil versi SharePoint Server dari header/endpoint yang di-scope, cocokkan dengan daftar CVE di atas.
- Cek akses anonim ke halaman admin/tool pane dengan akun test.
- Cek apa yang bisa dibaca akun guest di situs test.

## Bypass
- Versi yang sudah di-patch tidak lagi rentan — catat versi dan tutup.
- Bila endpoint tidak bisa diakses dari luar, catat sebagai tidak terekspos.

## Chain template
SharePoint versi rentan / auth lemah → RCE atau akses data → kontrol server dan dokumen → baca data, kunci pemilik keluar — laporkan di titik bukti cukup (versi + eksposur).

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (server, dokumen, data)?
3. Bisakah dibuktikan dari versi + eksposur tanpa menjalankan exploit?

## Root cause
Server SharePoint terekspos dengan versi tidak di-patch, atau kontrol akses halaman tidak mengikat hak ke peran yang benar.

## Verifikasi
- Buktikan dari nomor versi + akses endpoint, bukan dari exploit yang dijalankan.
- Simpan versi/header, redaksi token/cookie.
