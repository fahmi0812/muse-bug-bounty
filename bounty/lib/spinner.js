// bounty/lib/spinner.js — status satu baris selagi proses anak jalan.
// Menulis ke stderr, HANYA bila TTY: frame berputar + waktu berjalan +
// baris terakhir output anak (Strix). Di pipe/CI (bukan TTY) diam total
// supaya output tetap bersih untuk diparse/dilog.
const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

function stripAnsi(s) {
  return String(s ?? "").replace(/\x1b\[[0-9;]*[A-Za-z]/g, "");
}

// Layak tampil sebagai teks spinner atau tidak. Output Strix selagi pull
// image Docker / progress bar adalah garis simbol (━, █, ─, ====) yang
// kalau ditampilkan memenuhi satu baris penuh tanpa kata apa pun — persis
// yang Fahmi lihat ("cuma garis doang"). Syarat: cukup huruf dan huruf
// mendominasi isi baris; garis simbol ditolak.
const JUNK_CHARS = /[─━│┃┌┐└┘├┤┬┴┼═║╔╗╚╝█▓▒░]/g;

export function isInformative(line) {
  const text = stripAnsi(line).trim();
  if (text.length < 4) return false;
  const nonSpace = text.replace(/\s/g, "");
  if (nonSpace.length === 0) return false;
  const letters = (text.match(/[a-zA-Z]/g) || []).length;
  if (letters < 4) return false;
  if (letters / nonSpace.length < 0.4) return false;
  const junk = (text.match(JUNK_CHARS) || []).length;
  if (junk / text.length > 0.1) return false;
  return true;
}

// Fase yang dikenali dari baris output — tampilkan pesan yang jelas
// (bukan baris mentahnya yang sering berupa progress bar).
export function phaseText(line) {
  const text = stripAnsi(line);
  if (/pulling|pull image|downloading image/i.test(text)) return "Menarik image Docker Strix…";
  return null;
}

export class Spinner {
  constructor({ stream = process.stderr, enabled = Boolean(stream?.isTTY) } = {}) {
    this.stream = stream;
    this.enabled = Boolean(enabled);
    this.timer = null;
    this.frame = 0;
    this.startedAt = 0;
    this.text = "";
    this.started = false;
  }

  start(text = "") {
    if (!this.enabled || this.timer) return;
    this.text = stripAnsi(text);
    this.startedAt = Date.now();
    this.frame = 0;
    this.started = true;
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

  // Cetak satu baris status sebagai baris sendiri di atas spinner
  // (dipakai untuk baris output anak yang informatif, supaya proses
  // kerja nampak selagi jalan — bukan cuma di baris spinner).
  // Di pipe/CI (bukan TTY) diam total; baris tetap tampil di dump
  // akhir seperti biasa.
  printLine(text) {
    if (!this.enabled) return;
    this.clear();
    this.stream.write(`${stripAnsi(text)}\n`);
    this.render();
  }

  stop() {
    if (!this.enabled || !this.started) return;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.started = false;
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
