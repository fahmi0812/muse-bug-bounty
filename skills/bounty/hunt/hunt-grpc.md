# hunt-grpc — gRPC Services

Kelas: Broken Access Control / Exposure | CWE: CWE-862, CWE-319 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan memanggil mutasi destruktif (`DeleteUser`, `Reset`, `Exec`) ke target nyata — cukup buktikan method terpanggil + responsnya (baca saja).
- DoS (termasuk HTTP/2 Rapid Reset CVE-2023-44487) DILARANG diuji — cukup cek versi stack dari banner; tanpa izin tertulis, jangan kirim burst apa pun.

## Detection pattern
- Port 50051/443/8443/9090 menegosiasikan ALPN `h2`; POST HTTP/2 ke method asal mengembalikan trailer `grpc-status` (12 = UNIMPLEMENTED = server gRPC).
- Reflection aktif (`grpc.reflection.v1.ServerReflection`) → daftar semua service/method tanpa source code.
- Service `Admin`/`Internal`/`Payment` dengan method sensitif yang terpanggil tanpa metadata auth.
- Backend memercayai header yang disuntik proxy (`x-user-id`, `x-tenant-id`, `x-internal-request`) — bila proxy tidak men-strip-nya, spoofing = impersonasi tenant.
- gRPC-Web / grpc-gateway / Connect mengekspos ulang method internal lewat REST/JSON polos.
- gRPC plaintext (h2c) di port non-standar — metadata/bearer bisa disadap.

## Sinyal uji
- `grpcurl list` (reflection) → katalog service; `describe` method yang namanya sensitif (`admin`, `internal`, `debug`, `secret`, `impersonate`, `delete`).
- Panggil method sensitif tanpa auth: `grpc-status` 0 (OK) + data = temuan; `Unauthenticated (16)` / `PermissionDenied (7)` = auth bekerja, BUKAN temuan; `InvalidArgument (3)` = method terpanggil, perbaiki payload.
- IDOR: iterasi `user_id` 1, 2, 3, 100 — data pengguna lain kembali = temuan.
- Header spoof: kirim `x-user-id`/`x-tenant-id` lewat proxy publik DAN langsung ke backend — hanya bila proxy meneruskannya tanpa strip, ini exploitable nyata.
- Transcoding: panggil rute REST hasil mapping (`/v1/admin/users:list`, JSON `application/grpc-web+json`) tanpa auth.

## Bypass
- Reflection mati bukan batas keamanan — `.proto` yang bocor bisa dibangun jadi descriptor set (`-protoset`) untuk memanggil method yang sama.
- Metadata biner (`-bin`, base64) kadang lolos dari middleware yang hanya memeriksa metadata teks.

## Chain template
Reflection aktif → katalog service internal → method admin tanpa auth / spoof header proxy → baca data tenant lain / eksekusi RPC istimewa. Atau: transcoder mengekspos ulang RPC internal → bypass authz dari browser.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Layanan "internal" diekspos tanpa mTLS/auth per-method; auth hanya di edge proxy, backend memercayai header suntikan; transcoder meneruskan rute internal tanpa auth; reflection dibiarkan aktif di produksi.

## Verifikasi
- Bedakan status gRPC, bukan jumlah byte: respons non-kosong bisa tetap frame error.
- Reflection/health yang publik saja = Low/Medium — temuan adalah method sensitif yang terbukti terpanggil.
- Buktikan delta state (data pengguna lain / efek samping mutasi), bukan sekadar respons OK.
