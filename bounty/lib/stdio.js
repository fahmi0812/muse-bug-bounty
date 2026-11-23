// bounty/lib/stdio.js — mode stdio untuk spawn Strix.
//   inherit: Strix menulis langsung ke terminal pemakai — UI live bawaan
//     Strix (Rich) tampil penuh, persis seperti menjalankan `strix`
//     sendiri. Dipakai bila stdout adalah TTY (pemakaian interaktif).
//   pipe: stdout/stderr Strix di-pipe ke wrapper (untuk diparse +
//     spinner + live lines). Dipakai bila bukan TTY (pipe/CI/tes).
// Wrapper TIDAK butuh pipe stdout Strix: sejak v1.1 sumber utama
// temuan/biaya adalah artefak strix_runs/<run>/run.json +
// vulnerabilities.json (+ SARIF); stdout hanya fallback.
// Override paksa: BOUNTY_STRIX_STDIO=inherit|pipe.
export function chooseStrixStdio({ stdoutTTY = false, override = process.env.BOUNTY_STRIX_STDIO } = {}) {
  const o = String(override ?? "").toLowerCase();
  if (o === "inherit" || o === "pipe") return o;
  return stdoutTTY ? "inherit" : "pipe";
}

export default { chooseStrixStdio };
