// bounty/lib/review-html.js — generator halaman review statis (P1-2).
// buildReviewHtml(candidates) -> string HTML. Tanpa dependensi, tanpa
// server, tanpa JS: tabel kandidat + instruksi approve/reject via CLI.
// Dipakai `bounty review --export-html [file]` (default eval/review.html).
function esc(v) {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function row(c) {
  const id = c.id ?? "";
  const program = c.program ?? "";
  const method = (c.method ?? "").toUpperCase();
  const endpoint = c.endpoint ?? c.path ?? "";
  const vulnClass = c.vuln_class ?? c.vulnClass ?? "";
  const cwe = c.cwe ?? "";
  const status = c.status ?? "candidate";
  return `<tr><td>${esc(id)}</td><td>${esc(program)}</td><td>${esc(method)}</td>`
    + `<td><code>${esc(endpoint)}</code></td><td>${esc(vulnClass)}</td>`
    + `<td>${esc(cwe)}</td><td>${esc(status)}</td></tr>`;
}

/**
 * buildReviewHtml(candidates) -> string HTML lengkap.
 * candidates: array baris store (snake_case: vuln_class/cwe, atau camelCase).
 * Daftar kosong tetap menghasilkan halaman dengan pesan "tidak ada kandidat".
 */
export function buildReviewHtml(candidates = []) {
  const list = Array.isArray(candidates) ? candidates : [];
  const rows = list.map(row).join("\n");
  const body = list.length === 0
    ? `<p>Tidak ada kandidat menunggu review.</p>`
    : `<table>
<thead><tr><th>ID</th><th>Program</th><th>Method</th><th>Endpoint</th><th>Kelas</th><th>CWE</th><th>Status</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>`;
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>Review Kandidat — bounty</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}
th{background:#f0f0f0}
code{font-size:.9em}
</style>
</head>
<body>
<h1>Review Kandidat</h1>
<p>Dibuat: ${esc(new Date().toISOString())} — ${list.length} kandidat menunggu review.</p>
${body}
<h2>Cara approve / reject (via CLI)</h2>
<pre>bounty review --approve &lt;id&gt;   # setujui kandidat menjadi finding
bounty review --reject &lt;id&gt;    # tolak kandidat
bounty review --queue           # lihat antrean kandidat lagi</pre>
<p>Hanya kandidat yang di-approve yang menjadi finding. Jangan kirim laporan
ke program sebelum review manual selesai.</p>
</body>
</html>
`;
}

export default { buildReviewHtml };
