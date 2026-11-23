# Program: dvwa (lab lokal)

Nama: dvwa
Scope: localhost:8080
Allowed: localhost:8080, 127.0.0.1:8080
Allowed: /vulnerabilities/*, /login.php
Denied: /admin/internal
Budget: $5
Rate: 10 req/detik
Roles: low, high
Automation: boleh scan otomatis (lab lokal, jam bebas)
Catatan: lab lokal Docker / native, difficulty low. Akun test low-priv dan high-priv dibuat otomatis di lab. Oracle: eval/oracle/labels/dvwa.json.
