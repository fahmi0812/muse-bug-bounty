// bounty/lib/spinner.js — status satu baris selagi proses anak jalan.
// Menulis ke stderr, HANYA bila TTY: frame berputar + waktu berjalan +
// baris terakhir output anak (Strix). Di pipe/CI (bukan TTY) diam total
// supaya output tetap bersih untuk diparse/dilog.
const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

function stripAnsi(s) {
  return String(s ?? "").replace(/\x1b\[[0-9;]*[A-Za-z]/g, "");
}

export class Spinner {
  constructor({ stream = process.stderr, enabled = Boolean(stream?.isTTY) } = {}) {
    this.stream = stream;
    this.enabled = Boolean(enabled);
    this.timer = null;
    this.frame = 0;
    this.startedAt = 0;
    this.text = "";
  }

  start(text = "") {
    if (!this.enabled || this.timer) return;
    this.text = stripAnsi(text);
    this.startedAt = Date.now();
    this.frame = 0;
    this.render();
    this.timer = setInterval(() => {
      this.frame += 1;
      this.render();
    }, 100);
  }

  // Simpan teks baru; render dilakukan interval 100 ms (bukan tiap baris,
  // supaya output Strix yang deras tidak membanjiri terminal).
  update(text) {
    if (!this.enabled) return;
    this.text = stripAnsi(text);
  }

  stop() {
    if (!this.enabled) return;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.clear();
  }

  elapsedSeconds() {
    return Math.max(0, Math.floor((Date.now() - this.startedAt) / 1000));
  }

  clear() {
    if (!this.enabled) return;
    this.stream.write("\r\x1b[2K");
  }

  render() {
    if (!this.enabled) return;
    const width = this.stream.columns || process.stdout.columns || 80;
    const suffix = ` (${this.elapsedSeconds()} dtk)`;
    const maxText = Math.max(10, width - 3 - suffix.length);
    const text = this.text.length > maxText ? this.text.slice(0, maxText - 1) + "…" : this.text;
    this.stream.write(`\r${FRAMES[this.frame % FRAMES.length]} ${text}${suffix}`);
  }
}

export default Spinner;
