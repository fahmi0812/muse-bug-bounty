# hunt-xxe — XML External Entity

Kelas: Injection | CWE: CWE-611 | OWASP: A03:2021 Injection

## Detection pattern
- Aplikasi menerima upload / input XML (SVG, docx, SOAP, import data).
- Respons berisi isi file lokal atau error parser XML.
- Parser memproses DTD / external entity.
- Upload SVG diproses server dan isinya memengaruhi respons.

## Payload contoh
- `<!ENTITY xxe SYSTEM "file:///etc/passwd">` lalu pakai `&xxe;`
  di dokumen XML (uji baca file di lab saja).
- `<!ENTITY xxe SYSTEM "http://<server-log-milikmu>/ping">` — uji
  blind XXE lewat callback ke server log sendiri.
- Entity dengan parameter eksternal untuk blind / error-based.

## Bypass
- Coba encoding / variasi DTD bila kata `SYSTEM` difilter.
- Coba lewat SVG (`<svg><!ENTITY ...>`) bila upload XML langsung ditolak.
- Coba format turunan XML (docx, xlsx) bila endpoint menerima file.

## Chain template
XXE baca file → SSRF internal → baca layanan internal.

## Verifikasi
- Buktikan isi file / callback benar dari server (bukan dari parser lokal).
- Jangan baca file berisi kredensial; cukup buktikan akses baca
  (mis. file non-sensitif di lab).
- Simpan request XML + respons sebagai bukti.
