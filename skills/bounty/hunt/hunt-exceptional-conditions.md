# hunt-exceptional-conditions — Verbose Errors / Fail-Open

Kelas: Information Disclosure | CWE: CWE-209 | OWASP: A10:2025

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Kirim input cacat secukupnya untuk memicu error path — jangan banjir/fuzz agresif, berhenti saat kena rate limit / 429.
- Jangan mengeksploitasi kebocoran (mis. SQL error → injeksi) di file ini; itu ranah skill lain.

## Detection pattern
- Endpoint yang mem-parse input (API JSON, form, query param, upload) mengembalikan stack trace / halaman error developer saat diberi input tak terduga.
- Tanda per framework: `SequelizeDatabaseError` / `node_modules/` (Node), `<b>Warning</b> ... /var/www/...php on line N` (PHP), `Traceback (most recent call last)` (Python), `at com.app.Foo(Foo.java:42)` (Java), `Server Error in '/' Application` / `[System.XxxException` (.NET).
- Error JSON generik (`{"error":"Invalid input"}`) tanpa internals = penanganan benar, BUKAN temuan.

## Sinyal uji
- Ubah SATU asumsi per request: tipe salah (`{"rating":"x","comment":[1,2,3]}`), body JSON rusak/terpotong, angka overflow/negatif, string sangat panjang, null byte.
- Perhatikan BODY respons, bukan hanya status — 500 (bahkan 200/400) yang berisi stack trace adalah sinyalnya.
- Catat artefak yang bocor persis: path absolut, kelas ORM, versi library, frame stack.

## Bypass
- Tidak ada bypass — yang diuji adalah apakah error path membocorkan internals atau gagal tertutup (fail-open) vs gagal aman (fail-closed).

## Chain template
Error verbose → path/ORM/versi bocor → persenjataan serangan lanjutan (SQLi via error SQL, LFI via path absolut, RCE via versi library rentan). Laporkan kebocoran + apa yang dimungkinkannya.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Exception tidak ditangkap di batas aplikasi; halaman error development aktif di produksi; error handler mengembalikan detail internal ke klien.

## Verifikasi
- "Return 500" saja bukan disclosure — wajib ada artefak internal di body.
- Uji satu asumsi rusak per request agar sumber kebocoran jelas; jangan kombinasikan banyak input cacat sekaligus.
- Catat apa yang dimungkinkan kebocoran itu (mis. error SQL → `hunt-sqli`; path absolut → `hunt-lfi`).
- Simpan request/response, redaksi data sensitif sebelum melapor.
