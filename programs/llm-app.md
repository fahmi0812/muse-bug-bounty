# Program: llm-app (lab lokal)

Nama: llm-app
Scope: localhost:8000
Allowed: localhost:8000, 127.0.0.1:8000
Allowed: /chat, /tools/execute
Denied: /admin, /admin/internal
Budget: $5
Rate: 10 req/detik
Roles: low, high
Automation: boleh scan otomatis (lab lokal, jam bebas)
Catatan: lab app ber-LLM lokal (placeholder python:3.12-slim, lihat eval/docker-compose.yml profile llm). Oracle: eval/oracle/labels/llm-app.json (6 vuln, OWASP LLM Top 10 2026: prompt injection, indirect prompt injection, data exfiltration, excessive agency, RAG leakage, system prompt leakage). Verifikasi ulang endpoint saat lab final dipilih.
