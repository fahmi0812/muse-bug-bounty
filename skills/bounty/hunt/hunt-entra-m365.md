# hunt-entra-m365 — Microsoft Entra ID / M365

Kelas: Broken Access Control | CWE: CWE-862 | OWASP: A01:2021

Ditulis dari pola publik (CVE/penelitian publik) — konfigurasi Entra ID dan M365 yang salah.

## Scope & larangan
- Hanya tenant/program yang eksplisit mencantumkan aplikasi Entra/M365 di scope.
- Jangan sentuh tenant pihak ketiga, jangan uji akun user nyata — hanya akun test milikmu.
- Jangan tebak password / brute force. Berhenti saat kena rate limit / 429.
- Jangan ubah kebijakan tenant (Conditional Access, admin consent) — hanya baca dan laporkan.

## Detection pattern
- Akun guest/tamu bisa membaca grup, file SharePoint, atau daftar anggota yang seharusnya internal.
- Conditional Access tidak menutup jalur lama: auth lama (legacy auth / SMTP/IMAP) masih aktif untuk akun test.
- Aplikasi multitenant menerima token dari tenant lain tanpa cek `issuer`/`tid` (kelas nOAuth — cross-tenant access).
- Admin consent diberikan ke aplikasi pihak ketiga dengan izin lebar (Mail.Read, Files.Read.All, Directory.Read.All).
- Token refresh / PRT bisa dipakai ulang dari konteks lain tanpa device check (replay).

## Payload contoh
- Daftar sebagai guest ke tenant test, enumerasi grup dan file yang bisa dibaca guest.
- Minta token untuk aplikasi multitenant test dari tenant test lain, cek apakah diterima.
- Cek aplikasi yang minta consent: catat izin yang diminta vs yang dipakai.

## Bypass
- Coba akses resource dengan token guest vs token member — bandingkan apa yang bocor.
- Coba jalur legacy auth (bila masih aktif di tenant test) saat Conditional Access memblokir jalur modern.
- Bila diblokir, catat dan berhenti — jangan coba akun nyata.

## Chain template
Guest / token lintas tenant / consent lebar → baca data internal → akses mailbox/file admin → eskalasi ke admin tenant — laporkan di titik bukti cukup.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (data, mailbox, admin tenant)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
Kebijakan akses (guest, Conditional Access, consent) tidak mengikat identitas dan perangkat ke resource yang benar, atau izin aplikasi lebih lebar dari kebutuhan.

## Verifikasi
- Buktikan dengan dua akun test milikmu (guest vs member), bukan akun user nyata.
- Simpan request/response, redaksi token/cookie.
