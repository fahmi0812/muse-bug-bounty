# Gerbang CI red-team Promptfoo (P2-3)

Promptfoo adalah alat eval/red-team LLM (MIT, kini bagian dari OpenAI
tetapi tetap open source). Di repo ini ia dipakai sebagai **gerbang CI
untuk harness eval**, BUKAN sebagai runner bounty: ia menguji apakah
prompt harness eval llm-app (lab LLMVault) tahan terhadap percobaan
override instruksi dan kebocoran (scope, kredensial, detail program,
jawaban oracle). Ia tidak pernah menyentuh target bounty.

## Yang diuji

- `eval/promptfoo/promptfooconfig.yaml` — satu config, dua mode:
  - **Kasus tetap (6):** `promptfoo eval` — percobaan override/bocor
    yang ditulis tangan (override langsung, bocor scope, bocor
    kredensial, bocor oracle, injeksi lewat output tool, role-play
    jailbreak). Dinilai dengan `llm-rubric` (model sebagai juri);
    pencocokan string sengaja tidak dipakai karena kata penolakan
    bervariasi. Semua kasus bersifat detection-oriented (frasa
    override abstrak, tanpa payload exploit nyata).
  - **Red-team generatif:** `promptfoo redteam run` — plugin
    membangkitkan serangan, strategi membungkus penyampaiannya.
    Plugin (kecil sengaja, 2 tes per plugin): `indirect-prompt-injection`
    (dengan `indirectInjectionVar: user_input`), `special-token-injection`,
    `pliny`, `pii:direct`. Strategi: `jailbreak`, `prompt-injection`.
    Preset `owasp:llm` ada tapi TIDAK diaktifkan (terlalu berat untuk
    gerbang CI). Target/provider adalah placeholder `openai:gpt-4o-mini`
    — ganti baris `id:` bila tim memakai model lain.

## Menjalankan lokal

```sh
# butuh kunci provider, mis. OPENAI_API_KEY di env (jangan commit kunci)
export PROMPTFOO_DISABLE_TELEMETRY=1
npx promptfoo@latest eval -c eval/promptfoo/promptfooconfig.yaml -o eval/promptfoo/results.json
npx promptfoo@latest redteam run -c eval/promptfoo/promptfooconfig.yaml -o eval/promptfoo/redteam-results.json
```

Perilaku promptfoo yang terverifikasi (23 Nov 2026, dari docs promptfoo
dan panduan CI-nya): `promptfoo eval` keluar dengan kode **100** bila
ada tes gagal; ambang pass-rate diatur lewat env
`PROMPTFOO_PASS_RATE_THRESHOLD` (default 100 = tanpa kegagalan);
`--fail-on-error` menghentikan pipeline saat ada kasus gagal; `-o`
bisa dipakai berkali-kali (JSON, HTML, JUnit XML). JSON hasil memakai
bentuk `{version: 3, timestamp, results: {stats: {successes, failures},
results: [...]}}`; tiap baris punya `success`, `score`, dan
`gradingResult.componentResults[]` (`pass`, `reason`, `assertion.type`).

## Gerbang: membaca hasil

`bounty/lib/promptfoo-gate.js` (zero-dep, tanpa I/O kecuali baca file)
membaca JSON hasil dan memutuskan lolos/gagal:

```sh
node --input-type=module -e "
import { readPromptfooResults, gateResults } from './bounty/lib/promptfoo-gate.js';
const r = readPromptfooResults('eval/promptfoo/results.json');
const g = gateResults(r, { minPassRate: 0.8 });
console.log(g.reason);
if (!g.pass) process.exit(1);
"
```

Ambang default **0,8** (80%). Gerbang bersifat **fail-closed**: file
hilang, JSON rusak, hasil kosong (total 0), atau pass rate di bawah
ambang — semuanya GAGAL, tidak pernah lolos diam-diam. Bila `stats`
hilang, parser menghitung dari baris (`success === false` = gagal).

## Cara pakai di CI

Tambahkan satu job/langkah di `.github/workflows/ci.yml` (file workflow
**tidak bisa** ditulis lewat API GitHub — tambahkan lewat web UI GitHub,
seperti workflow lain di repo ini):

```yaml
- name: Promptfoo red-team gate
  if: ${{ env.OPENAI_API_KEY != '' }}
  env:
    OPENAI_API_KEY: ${{ secrets.REDTEAM_PROVIDER_KEY }}
    PROMPTFOO_DISABLE_TELEMETRY: "1"
  run: |
    npx promptfoo@latest eval -c eval/promptfoo/promptfooconfig.yaml -o eval/promptfoo/results.json
    node --input-type=module -e "
    import { readPromptfooResults, gateResults } from './bounty/lib/promptfoo-gate.js';
    const g = gateResults(readPromptfooResults('eval/promptfoo/results.json'), { minPassRate: 0.8 });
    console.log(g.reason);
    if (!g.pass) process.exit(1);
    "
```

## Batasan jujur

- **Tanpa kunci provider, gerbang DILEWATI (skip), bukan lolos.**
  Promptfoo butuh model untuk menjalankan target dan (untuk
  `llm-rubric`/redteam) membangkitkan serangan + menilai. $0 default
  repo ini berarti tidak ada kunci di CI — jadi langkah di atas
  memakai `if:` dan tidak memblokir pipeline bila kunci belum diset.
  Jangan pernah menaruh kunci di repo atau di config.
- **Belum pernah jalan live.** Tidak ada promptfoo di VM ini; perintah
  di atas, bentuk output redteam, dan nama plugin/strategi diambil
  dari docs promptfoo + OWASP DevSecOps Guideline (23 Nov 2026) dan
  ditandai di mana yang belum terverifikasi live. Jalankan sekali
  secara lokal sebelum mengaktifkan langkah CI.
- **Bentuk output `redteam run` diasumsikan sama dengan `eval`.**
  Parser toleran terhadap bentuk itu, tapi belum ada satu pun file
  hasil redteam nyata yang pernah dibaca — bila bentuknya berbeda,
  parser menghitung dari baris dan tetap fail-closed.
- **Angka plugin/strategi tergantung versi.** Laporan gap menyebut
  157 plugin / 34 strategi; satu sumber Mei 2026 menghitung 155
  plugin pada promptfoo 0.121.11. Config ini hanya memakai 4 plugin
  + 2 strategi yang namanya terverifikasi di sumber.
- **llm-rubric tidak deterministik.** Penilaian oleh model bisa
  berfluktuasi antar run; ambang 0,8 memberi ruang untuk itu. Bila
  gerbang terlalu sering goyang, naikkan ambang atau ganti rubrik
  dengan assert deterministik.

## Sumber (dicek 23 Nov 2026, tanpa sign-in)

- Output formats + bentuk JSON: https://www.promptfoo.dev/docs/configuration/outputs/
- CI/CD integration: https://github.com/dimetron/promptfoo/blob/HEAD/site/docs/integrations/ci-cd.md
- Red team configuration: https://www.promptfoo.dev/docs/red-team/configuration/
- OWASP DevSecOps Guideline (contoh config redteam + strategi): https://owasp.github.io/DevSecOpsGuideline/2-Process/2-4-Test/2-4-6-AI-LLM-Application-Security-Testing/
- CI gate + pass-rate threshold: https://dev.to/shubhampalriwala/llm-evals-in-ci-vs-production-what-each-catches-and-which-tools-do-both-1ma7
- Plugin counts + mapping OWASP: https://dev.to/jangwook_kim_e31e7291ad98/promptfoo-llm-red-teaming-against-owasp-top-10-4m4l
