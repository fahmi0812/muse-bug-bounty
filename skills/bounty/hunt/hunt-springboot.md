# hunt-springboot — Spring Boot Actuator & Framework

Kelas: Exposure / RCE | CWE: CWE-200, CWE-94 | OWASP: A01:2021, A05:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan unduh heap dump — isinya kredensial; cukup buktikan endpoint-nya terbuka.
- Jangan kirim payload SpEL / H2 / Spring4Shell ke target nyata — deteksi versi + paparan saja.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Header `X-Application-Context` atau halaman "Whitelabel Error Page" menandai Spring Boot.
- `/actuator` merespons JSON daftar endpoint — cek `env`, `heapdump`, `mappings`, `beans`, `loggers`, `shutdown`.
- `/actuator/env` menampilkan variabel lingkungan (kunci, kata sandi) — catat keberadaannya, jangan salin nilainya.
- Konsol H2 (`/h2-console`) terbuka tanpa auth.
- Jejak stack Java menyingkap versi Spring — bandingkan dengan CVE publik (Spring4Shell, Spring Cloud Function).

## Payload contoh
- Minta `/actuator`, `/actuator/env`, `/actuator/mappings`, `/actuator/beans` dengan header `Accept: application/json`.
- Coba base path lain: `/manage/actuator`, `/management/actuator`, `/app/actuator`.
- Minta halaman tak ada lalu cari teks "Whitelabel Error Page" / `org.springframework`.

## Bypass
- HTTP 200 saja bukan bukti — Spring sering balas 200 berisi halaman login/Whitelabel. Wajib JSON berbentuk actuator.
- Endpoint bisa aktif di base path berbeda — uji semua base sebelum menyimpulkan aman.

## Chain template
Actuator terbuka → `env`/`mappings` menyingkap rahasia + peta API → kredensial dipakai menyerang layanan lain → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Actuator di-deploy dengan default terbuka; properti lingkungan berisi rahasia tanpa proteksi akses.

## Verifikasi
- Replay harus mengembalikan JSON actuator yang sama — bukan halaman HTML.
- Jangan simpan nilai rahasia dari `env` — catat nama kuncinya saja, lalu redaksi.
- Simpan request/response, redaksi isi sensitif.
