# hunt-cloud-misconfig — Cloud / Infra Misconfiguration

Kelas: Misconfiguration / Exposure | CWE: CWE-200, CWE-732 | OWASP: A05:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu; jangan akses bucket/layanan milik pihak ketiga.
- Jangan mengubah/menghapus data walau diizinkan — PoC read-only saja.
- Jangan memakai kredensial yang ditemukan untuk lateral lebih jauh tanpa izin tertulis program.

## Detection pattern
- Bucket S3/GCS/Azure Blob publik: `GET /?max-keys=10` atau `aws s3 ls --no-sign-request` mengembalikan isi (bukan 403).
- Firebase Realtime DB terbuka: `/.json` bisa dibaca publik.
- Metadata cloud via SSRF: `169.254.169.254/latest/meta-data/iam/security-credentials/` — hanya relevan bila ada SSRF (lihat `hunt-ssrf`).
- Cognito Identity Pool: `identityPoolId` + `guestRoleArn` di JS bundle (mis. snippet CloudWatch RUM) — role tamu yang lebih luas dari `rum:PutRumEvents` = vending machine kredensial anonim.
- Panel admin terekspos: `/jenkins`, `/grafana`, `/kibana`, `/elasticsearch`, `/phpMyAdmin`, `/.env`, `/config.json`, `/api-docs`.
- Kredensial IAM/service-account di JS bundle atau file `.env` publik.

## Sinyal uji
- Coba nama bucket umum (target, target-backup, target-assets, target-prod, target-staging) — daftar saja, jangan tulis.
- Cognito: `get-id` tanpa auth berhasil → `get-credentials-for-identity` → `sts get-caller-identity` + minimal satu aksi list nyata (mis. `s3 ls`). Tanpa aksi di luar `rum:PutRumEvents` = Informational.
- Firebase: baca `/.json` saja; jangan PUT data uji ke DB target nyata.
- `.tfstate` publik: parse lokal, cari kredensial live — metadata resource saja bukan temuan.

## Bypass
- Bucket yang mengembalikan 403/XML `AccessDenied` = terlindungi, berhenti.
- Role tamu yang hanya `rum:PutRumEvents` pada ARN AppMonitor = konfigurasi yang dimaksudkan.

## Chain template
Bucket publik → kredensial di `.env`/SA JSON → enumerasi IAM (lihat `hunt-cloud-iam`) → eskalasi `iam:PassRole`. Atau: SSRF → metadata instance → kredensial role → baca S3/RDS. Atau: Cognito over-permission → STS anonim → akses layanan produksi.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Policy bucket/blob terlalu permisif; role tamu Cognito diberi wildcard; kredensial disematkan di bundle JS; panel admin tidak dibatasi jaringan/auth; secret dicetak di log/artefak.

## Verifikasi
- Buktikan baca data nyata (daftar isi, satu kredensial live yang terverifikasi read-only) — status 200 saja bukan dampak.
- Klaim "bucket bisa ditulis" wajib bukti marker unik + read-back dari sesi bersih.
- Redaksi semua kredensial/nilai secret sebelum melapor; jangan simpan nilainya di store.
