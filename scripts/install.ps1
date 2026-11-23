# Installer muse-bug-bounty (Windows PowerShell). Idempotent.
# Pilihan Docker: param -Docker / -NoDocker, env BOUNTY_DOCKER=1/0,
# atau tanya interaktif [1] Ya / [2] Tidak (default 1).
param(
    [switch]$Docker,
    [switch]$NoDocker
)

$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host '== muse-bug-bounty installer =='

# 1. Node >= 20
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    Write-Error 'Node.js tidak ditemukan. Instal Node >= 20 dulu (https://nodejs.org).'
    exit 1
}
$nodeMajor = [int]((node -p 'process.versions.node.split(".")[0]'))
if ($nodeMajor -lt 20) {
    Write-Error "Node $(node -v) terlalu lama - butuh Node >= 20."
    exit 1
}
Write-Host "Node $(node -v) OK"

# 2. Pilihan Docker
$dockerChoice = $null
if ($Docker) { $dockerChoice = 1 }
elseif ($NoDocker) { $dockerChoice = 0 }
elseif ($env:BOUNTY_DOCKER) { $dockerChoice = [int]$env:BOUNTY_DOCKER }
else {
    Write-Host 'Pakai Docker untuk lab eval lokal (Juice Shop/DVWA/VAmPI)?'
    Write-Host '  [1] Ya (default)'
    Write-Host '  [2] Tidak - bench jalan mode no-docker'
    $ans = Read-Host 'Pilihan [1/2]'
    if ($ans -eq '2') { $dockerChoice = 0 } else { $dockerChoice = 1 }
}

if ($dockerChoice -eq 1) {
    Write-Host 'Docker: Ya'
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($docker) { Write-Host "Docker ditemukan: $(docker --version)" }
    else {
        Write-Host 'PERINGATAN: Docker dipilih tapi tidak ditemukan di PATH.'
        Write-Host 'Instal Docker Desktop atau jalankan ulang dengan -NoDocker.'
    }
} else {
    Write-Host 'Docker: Tidak - bench jalan mode no-docker (lab Docker di-skip).'
}

# 3. Simpan pilihan (idempotent)
$bountyDir = Join-Path $RepoDir '.bounty'
New-Item -ItemType Directory -Force -Path $bountyDir | Out-Null
$dockerJson = if ($dockerChoice -eq 1) { 'true' } else { 'false' }
$installedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
"{
  `"docker`": $dockerJson,
  `"installed_at`": `"$installedAt`"
}" | Set-Content -Path (Join-Path $bountyDir 'config.json') -Encoding UTF8
Write-Host 'Pilihan disimpan di .bounty/config.json'

# 4. npm install global bila package.json ada
if (Test-Path (Join-Path $RepoDir 'package.json')) {
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if ($npm) {
        Write-Host 'Instal CLI bounty (npm install -g)...'
        Push-Location $RepoDir
        try { npm install -g --ignore-scripts } catch {
            Write-Host "PERINGATAN: npm install -g gagal - coba manual: npm install -g (dari $RepoDir)"
        }
        Pop-Location
    } else {
        Write-Host 'PERINGATAN: npm tidak ditemukan - lewati instal global.'
    }
}

Write-Host ''
Write-Host '== Selesai =='
Write-Host 'Langkah berikutnya:'
Write-Host '  1. Instal Strix (bukan bagian repo ini):'
Write-Host '     curl -sSL https://strix.ai/install | bash'
Write-Host '  2. Mode 2 (Standalone CLI) - wizard provider sekali saja:'
Write-Host '     bounty install'
Write-Host '  3. Coba kering dulu:'
Write-Host '     bounty run --target https://example.com/api/users --program programs/example.md --dry-run'
Write-Host '  4. Test & bench:'
Write-Host '     npm test; npm run bench'
