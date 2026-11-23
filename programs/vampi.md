# Program: vampi (lab lokal, API)

Nama: vampi
Scope: localhost:5000
Allowed: localhost:5000, 127.0.0.1:5000
Allowed: /users/*, /books/*, /auth/*, /openapi.json
Denied: /admin/internal
Budget: $5
Rate: 10 req/detik
Roles: low, high
Automation: boleh scan otomatis (lab lokal, jam bebas)
Catatan: lab lokal Docker / native, API-only (Vulnerable API). Akun test low-priv dan high-priv dibuat otomatis di lab. Oracle: eval/oracle/labels/vampi.json.
