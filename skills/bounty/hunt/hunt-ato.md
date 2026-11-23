# hunt-ato — Account Takeover (ATO)

Kelas: Broken Authentication | CWE: CWE-287 | OWASP: A07:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan pakai akun user nyata, jangan kirim email reset ke orang lain.
- Berhenti saat kena rate limit / 429 — jangan brute force.

## Detection pattern
- Reset password menghasilkan token yang bisa ditebak atau tidak kedaluwarsa.
- Ganti email / nomor HP akun tidak minta verifikasi ulang.
- Login SSO / OAuth menerima identitas tanpa cek kepemilikan.
- Session lama tetap hidup setelah ganti password.
- Akun bisa dibuat dengan email korban tanpa verifikasi (pre-hijack).

## Payload contoh
- Minta reset untuk akun test A, pakai token yang sama untuk akun test B.
- Ganti `email` di profil ke email akun test lain tanpa OTP.
- Daftar akun dengan email akun test lain yang belum terverifikasi, lalu verifikasi sendiri.

## Bypass
- Coba token reset lama setelah password diganti — uji apakah masih valid.
- Coba ubah `user_id` di body saat ganti email — uji cek kepemilikan.
- Bila diblokir, catat dan berhenti — jangan coba akun nyata.

## Chain template
Celah recovery / ganti email / SSO → ambil alih akun test korban → baca data, ubah password, kunci pemilik asli keluar — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Verifikasi kepemilikan akun (token, OTP, email) tidak mengikat ke identitas yang benar, atau tidak kedaluwarsa.

## Verifikasi
- Replay: akun test korban harus benar-benar berpindah tangan ke akun test penyerang.
- Buktikan dengan dua akun test milikmu, bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.

## Pendalaman
Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — parafrase, fokus deteksi + validasi.

### Pola deteksi tambahan
- Token reset tanpa kedaluwarsa / bisa dipakai ulang: minta dua token untuk akun test sendiri — pakai token pertama setelah token kedua terbit; bila masih valid, token lama tidak di-revoke.
- Ganti password tanpa step-up: endpoint menerima password baru tanpa password lama dan tanpa MFA — uji dari sesi akun test; ini pengali persistensi (cookie curian + ini = ATO permanen).
- Jawaban recovery sosial: jawaban ber-entropi rendah, atau jawabannya terpapar di `/api/me` / halaman recovery — uji dengan akun test sendiri, jangan tebak jawaban akun orang lain.
- SSO subdomain takeover: provider menerima `redirect_uri` wildcard subdomain dan ada subdomain menganggur (CNAME ke layanan yang sudah dihapus) — konfirmasi = code benar-benar sampai di host yang kamu klaim, bukan sekadar redirect.
- Pre-account takeover: akun masih pending / belum terverifikasi — uji alur invite dengan email milikmu; akun passwordless / magic-link yang memberi sesi hanya dari nomor atau email tanpa langkah token juga diuji dengan identitas milikmu.

### Chain tambahan
Curi cookie sesi → ganti password tanpa step-up → kunci pemilik asli keluar, ATO permanen dari perangkat mana pun.

### Catatan Gate-0 tambahan
- Nilai severity: kritis hanya bila tanpa interaksi korban (reset poisoning, token palsu, `redirect_uri` longgar); butuh satu klik email = high; butuh phishing aktif = medium.
- Validasi end-to-end: sesi akun test B harus benar-benar berpindah tangan — decoding atau membuat token saja bukan dampak.
