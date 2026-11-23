# THREAT_MODEL.md — [TARGET]

## Aset

- [Aset 1: data / fungsi — mis. data user, pembayaran]
- [Aset 2]

## Aktor

- [Aktor: pengguna low-priv, admin, penyerang eksternal, penyerang internal]

## Trust boundary

- [Batas 1: internet → aplikasi]
- [Batas 2: aplikasi → database]
- [Batas 3: low-priv → high-priv]

## Ancaman (STRIDE singkat)

| Ancaman | Aset | Prioritas |
|---|---|---|
| Spoofing | [aset] | [Tinggi/Sedang/Rendah] |
| Tampering | [aset] | [..] |
| Repudiation | [aset] | [..] |
| Information Disclosure | [aset] | [..] |
| Denial of Service | [aset] | [..] |
| Elevation of Privilege | [aset] | [..] |

## Prioritas hunt

1. [Kelas vuln prioritas 1 + alasannya]
2. [Kelas vuln prioritas 2]

## Di luar scope

- [Hal yang tidak diuji — sesuai programs/*.md]
