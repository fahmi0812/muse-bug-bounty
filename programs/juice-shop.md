# Program: juice-shop (lab lokal)

Nama: juice-shop
Scope: localhost:3000
Allowed: localhost:3000, 127.0.0.1:3000
Allowed: /rest/*, /api/*, /#/search, /#/login
Denied: /admin/internal
Budget: $5
Rate: 10 req/detik
Roles: low, high
Automation: boleh scan otomatis (lab lokal, jam bebas)
Catatan: lab lokal Docker / native. Akun test low-priv dan high-priv dibuat otomatis di lab. Oracle: eval/oracle/labels/juice-shop.json.
