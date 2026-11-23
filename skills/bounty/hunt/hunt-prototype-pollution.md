# hunt-prototype-pollution — Prototype Pollution

Kelas: Injection | CWE: CWE-1321 | OWASP: A03:2021

## Detection pattern
- Input JSON dengan kunci `__proto__` / `constructor` / `prototype` mengubah perilaku aplikasi.
- Properti baru muncul di semua objek setelah input dikirim.
- Error / perilaku aneh setelah merge objek rekursif.

## Payload contoh
- Kirim `{"__proto__": {"testFlag": "polluted"}}` di body JSON (lab saja).
- Periksa apakah properti `testFlag` muncul di objek lain.
- Coba kunci `constructor.prototype` sebagai alternatif.

## Bypass
- Coba JSON dengan array bila objek langsung diblokir.
- Coba parameter query yang di-merge ke objek.

## Chain template
Pollution → properti global berubah → bypass / XSS / DoS →
dampak — laporkan dengan bukti properti muncul di objek lain.

## Verifikasi
- Replay tanpa kunci `__proto__` harus bersih.
- Pakai nama properti penanda yang jelas-jelas test (`testFlag`), bukan properti sistem.
- Simpan request/response sebelum dan sesudah.
