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
Catatan: lab app ber-LLM lokal (LLMVault, CyberSunil/LLMVault, MIT — build dari repo resmi, lihat eval/docker-compose.yml profile llm; port 8000:5000). Oracle: eval/oracle/labels/llm-app.json (6 vuln, OWASP LLM Top 10 2026: prompt injection, indirect prompt injection, data exfiltration, excessive agency, RAG leakage, system prompt leakage). Endpoint/oracle BELUM diverifikasi terhadap rute LLMVault — verifikasi live di laptop sebelum angka bench llm-app diklaim.
