// tests/guard-p25.test.js — P2-5: WiFi/C2 dikunci di denylist guard.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkCommand } from "../bounty/lib/guard.js";

for (const cmd of [
  "wifite --all",
  "aircrack-ng capture.cap",
  "bettercap -iface wlan0",
  "sliver",
  "covenant --listen 0.0.0.0",
  "mythic",
  "cobalt strike beacon",
]) {
  test(`guard P2-5 menolak: ${cmd}`, () => {
    const r = checkCommand(cmd);
    assert.equal(r.allowed, false);
    assert.match(r.reason, /di luar scope bounty/);
  });
}

test("guard P2-5: perintah legit tetap lolos", () => {
  for (const cmd of ["strix --target https://example.com", "nuclei -target https://example.com", "ls -la"]) {
    assert.equal(checkCommand(cmd).allowed, true, cmd);
  }
});
