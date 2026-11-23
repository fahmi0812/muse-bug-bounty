# hunt-lfi — Local File Inclusion

Kelas: Path Traversal / File Inclusion | CWE: CWE-98 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan baca file di luar aplikasi target, jangan ambil kredensial sistem.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Parameter nama file/path (`file`, `page`, `template`, `lang`) memengaruhi file yang dimuat.
- Respons berubah saat path berisi `../` atau pemisah direktori.
- Error menyingkap path absolut atau isi file yang tidak seharusnya tampil.
- Wrapper (`php://filter`, `data:`) memengaruhi output — uji baca saja, di lab.

## Payload contoh
- `?file=../../config` — uji traversal satu-dua level (file aplikasi saja).
- `?page=....//....//config` — uji filter traversal ganda.
- `?lang=en` → `?lang=../app/config` — uji parameter bahasa/template.
- Nilai absolut `/etc/passwd` DILARANG diuji ke target nyata; cukup buktikan traversal ke file aplikasi sendiri.

## Bypass
- Coba encoding (`%2e%2e%2f`) bila traversal polos diblokir.
- Coba pemisah null-byte tidak lagi relevan di runtime modern — catat bila gagal, jangan paksa.
- Bila WAF memblokir, catat dan berhenti — jangan spam variasi.

## Chain template
LFI (baca file aplikasi) → baca konfigurasi/kunci aplikasi → pakai kredensial aplikasi untuk akses data → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Input path user dipakai langsung sebagai path file tanpa allowlist; tidak ada pemisahan antara nama logis dan path fisik.

## Verifikasi
- Replay dengan path normal harus kembali normal; path traversal harus gagal bila aman.
- Buktikan hanya pada file aplikasi target, bukan file sistem.
- Simpan request/response, redaksi isi sensitif.
