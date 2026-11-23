# THREAT_MODEL.md — OWASP Juice Shop (lab)

## Aset

- Data user (email, password hash, alamat)
- Keranjang + pembayaran (simulasi)
- Feedback + data produk

## Aktor

- Pengguna low-priv (akun test), admin (akun test), penyerang eksternal

## Trust boundary

- Internet → aplikasi Juice Shop (localhost:3000)
- Aplikasi → database SQLite lab
- Low-priv → admin

## Ancaman (STRIDE singkat)

| Ancaman | Aset | Prioritas |
|---|---|---|
| Spoofing | Login | Tinggi |
| Tampering | Keranjang / harga | Tinggi |
| Information Disclosure | Data user | Tinggi |
| Elevation of Privilege | Peran admin | Tinggi |
| Denial of Service | API produk | Rendah |

## Prioritas hunt

1. SQLi di login / pencarian produk
2. XSS di feedback / pencarian
3. IDOR / BOLA di keranjang dan user

## Di luar scope

- Semua host di luar localhost:3000 (lab lokal saja)
