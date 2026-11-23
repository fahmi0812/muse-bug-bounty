# Program: dvga (lab lokal)

Nama: dvga
Scope: localhost:5013
Allowed: localhost:5013, 127.0.0.1:5013
Allowed: /graphql, /graphiql
Denied: /admin, /admin/internal
Budget: $5
Rate: 10 req/detik
Roles: low, high
Automation: boleh scan otomatis (lab lokal, jam bebas)
Catatan: lab lokal Docker (dolevf/dvga, port 5013). Semua vuln lewat satu endpoint GraphQL /graphql — pembeda TP adalah vuln_class + CWE, bukan path. Oracle: eval/oracle/labels/dvga.json (8 vuln: introspection, BOLA, batching/DoS, excessive data exposure, BFLA, SQLi via argumen, IDOR, broken auth).
