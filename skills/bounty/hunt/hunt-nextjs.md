# hunt-nextjs — Next.js / SSR Framework

Kelas: Server Actions / Middleware / SSRF / Cache | CWE: CWE-862, CWE-918, CWE-200 | OWASP: A01:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan panggil Server Action untuk mengubah data akun orang lain.
- Jangan pakai `/_next/image` untuk memindai jaringan internal target.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Header `x-powered-by: Next.js` atau `__NEXT_DATA__` di HTML menandai Next.js.
- `/_next/data/<buildId>/` mengembalikan JSON halaman yang seharusnya butuh login.
- Server Action merespons tanpa cookie sesi — cek apakah aksi jalan tanpa auth.
- `/_next/image?url=` mengambil URL luar — uji hanya dengan URL milikmu sendiri.
- Source map (`.js.map`) di `/_next/static/` terbuka — baca rute dan logika saja.
- Endpoint debug (`/__nextjs_original-stack-frame`) terbuka di produksi.

## Payload contoh
- Minta halaman proteksi lewat `/_next/data/<buildId>/admin.json` dengan akun low — bandingkan dengan akun high.
- Panggil Server Action dengan header `Next-Action` tanpa cookie — amati apakah status berubah.
- `/_next/image?url=https://akun-test-milikmu.example/x.png` — buktikan fetch terjadi tanpa menyentuh host internal.

## Bypass
- Middleware kadang melewati path `/_next/static/` — uji rute proteksi lewat varian path itu.
- Build ID berubah tiap deploy — ambil ulang dari HTML sebelum uji, jangan pakai ID lama.
- Bila WAF memblokir, catat dan berhenti — jangan spam variasi.

## Chain template
Middleware lewati path statis → halaman proteksi terbaca lewat `/_next/data/` → data sensitif bocor → laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Auth hanya ditegakkan di sisi klien atau di middleware yang tidak mencakup semua path; Server Action dan data prerender tidak memeriksa sesi.

## Verifikasi
- Replay dengan sesi low vs high — bedakan yang memang boleh diakses publik.
- Buktikan hanya pada data akun test sendiri.
- Simpan request/response, redaksi isi sensitif.
