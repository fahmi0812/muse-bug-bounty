# hunt-cloud-iam — Cloud IAM (AWS / GCP / Azure)

Kelas: Privilege Escalation / Broken Access Control | CWE: CWE-862, CWE-269 | OWASP: A01:2021

Ditulis dari pola publik (CVE/penelitian publik) — pola eskalasi IAM cloud.

## Scope & larangan
- Hanya akun cloud/program yang eksplisit ada di scope, dan hanya dengan akun test milikmu.
- Jangan sentuh akun cloud pihak ketiga atau produksi yang tidak di-scope.
- Jangan tebak kredensial / brute force. Jangan ubah kebijakan IAM — hanya baca dan laporkan.
- Jangan akses metadata service dari instance yang bukan milikmu.

## Detection pattern
- Role/peran dengan izin lebar (`*` atau `AdministratorAccess`) dipakai aplikasi biasa.
- Jalur eskalasi dari peran rendah: `iam:PassRole` + `ec2:RunInstances`, `lambda:CreateFunction`, `iam:CreatePolicyVersion`, atau `sts:AssumeRole` ke peran admin (cek lewat kebijakan, bukan eksekusi).
- Metadata service bisa diakses dengan IMDSv1 (tanpa token) dari instance test — SSRF ke `169.254.169.254` hanya di lab sendiri.
- Kunci akses (access key) lama/tidak dipakai masih aktif, atau bocor di repo/JS (cek dengan akun test, redaksi nilai).
- Bucket/storage bisa dibaca publik (cek kebijakan bucket, jangan unduh data korban).

## Payload contoh
- Baca kebijakan IAM peran test, petakan izin ke jalur eskalasi yang dikenal.
- Cek IMDS dari instance test: `PUT` token IMDSv2 gagal vs `GET` IMDSv1 berhasil.
- Cek kebijakan bucket test: apakah publik bisa list/baca.

## Bypass
- Bila peran test tidak punya jalur eskalasi, catat dan tutup.
- Bila metadata service menolak IMDSv1, catat sebagai sudah diamankan.

## Chain template
Peran rendah + izin lebar / IMDSv1 → eskalasi ke admin cloud → akses semua resource → baca data, kunci pemilik keluar — laporkan di titik bukti cukup (kebijakan + jalur).

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun cloud, data, resource)?
3. Bisakah dibuktikan dari kebijakan IAM tanpa menjalankan eskalasi?

## Root cause
Kebijakan IAM memberi izin lebih lebar dari kebutuhan, atau metadata service tidak memaksa proteksi token.

## Verifikasi
- Buktikan dari kebijakan IAM dan respons metadata di akun/instance test milikmu.
- Simpan kebijakan (redaksi kunci), jangan simpan kredensial asli.
