# hunt-aspnet — ASP.NET / ViewState

Kelas: Deserialization / Information Disclosure | CWE: CWE-502, CWE-209 | OWASP: A08:2021

Diadaptasi dari Claude-BugHunter (MIT/CC-BY-4.0) — ditulis ulang dengan kata sendiri.

## Scope & larangan
- Hanya target in-scope di `programs/*.md`. Hanya akun test milikmu (low/high).
- Jangan memalsukan ViewState atau menjalankan gadget deserialization ke target nyata — cukup buktikan primitifnya (signed-only, differential, disclosure).
- Jangan membaca trace/error log milik pengguna lain; berhenti saat kena rate limit / 429.

## Detection pattern
- Header `X-AspNet-Version`, `X-Powered-By: ASP.NET`, `Server: Microsoft-IIS`, cookie `ASP.NET_SessionId` / `.ASPXAUTH` — aplikasi .NET Framework klasik.
- Form berisi `__VIEWSTATE` + `__VIEWSTATEGENERATOR`; `__VIEWSTATEENCRYPTED` kosong = ViewState hanya ditandatangani (signed-only), bukan dienkripsi.
- `trace.axd` atau `elmah.axd` mengembalikan 200 tanpa login — dump request + stack trace.
- Endpoint `.svc?wsdl`, `.svc/mex`, `.asmx?WSDL`, `Telerik.Web.UI.WebResource.axd` — layanan WCF/SOAP yang sering terlupa.
- Error 500 menampilkan `Version Information: Microsoft .NET Framework` + stack trace = `customErrors mode="Off"`.

## Sinyal uji
- POST form dengan `__VIEWSTATE=AAAA` → pesan `Validation of viewstate MAC failed` (ViewState bertanda tangan).
- Bentuk ViewState berbeda memberi pesan error berbeda (`state information is invalid...`) = dua jalur parser berbeda (dual-parser) — catat, jangan eksploitasi.
- `GET /trace.axd` → 200 anonim = disclosure kritis; 403 = terlindungi, berhenti.
- `GET /elmah.axd` → 200 anonim = log error + jalur internal bocor.

## Bypass
- Validator request ASP.NET hanya memeriksa query string + body URL-encoded; header Cookie/Referer dan body JSON/XML sering tidak divalidasi — uji konteksnya, bukan spam payload.
- `trace.axd` yang `localOnly` kadang memakai `X-Forwarded-For` — uji satu header saja, jangan brute force.
- WCF `?wsdl`/`?mex` kadang anonim walau operasinya butuh auth — baca metadata saja.

## Chain template
Fingerprint ASP.NET → ViewState signed-only + kunci bocor dari disclosure lain → deserialisasi (RCE) — atau: `trace.axd`/`elmah.axd` anonim → kredensial/token di log → akses lanjutan. Laporkan di titik bukti cukup; primitif tanpa kunci bukan RCE.

## Gate-0 validation
1. Apa yang bisa penyerang lakukan sekarang yang sebelumnya tidak bisa?
2. Apa yang hilang dari korban (akun, data, uang)?
3. Bisakah direproduksi dalam 10 menit dari nol dengan akun test?

## Root cause
ViewState dikonfigurasi signed-only (`viewStateEncryptionMode="Never"`); `<machineKey>` tidak sinkron di farm atau bocor lewat repo; `trace.axd`/`elmah.axd` dan `customErrors Off` tertinggal dari development; endpoint WCF/Telerik lama tidak dimatikan.

## Verifikasi
- `__VIEWSTATEENCRYPTED` kosong saja = Low-Medium (primitif, bukan exploit).
- `trace.axd`/`elmah.axd` 200 anonim dengan data live = Critical; stack trace murni = Low.
- Simpan request/response, redaksi kredensial/token sebelum melapor.
