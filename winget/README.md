# Winget — muse-bug-bounty

## Status

**Belum live di winget.** Manifest di folder ini siap diajukan, tapi
`winget install fahmi0812.muse-bug-bounty` baru jalan setelah:

1. Release GitHub v1.0.0 dibuat dengan asset
   `muse-bug-bounty-1.0.0.zip` (berisi repo + `bounty.cmd` di root).
2. `InstallerSha256` di `fahmi0812.muse-bug-bounty.installer.yaml`
   diganti hash asli asset itu
   (`Get-FileHash muse-bug-bounty-1.0.0.zip -Algorithm SHA256`).
3. Manifest diajukan sebagai PR ke `microsoft/winget-pkgs` dan di-merge
   (review Microsoft).

## Cara pakai setelah live

```powershell
winget install fahmi0812.muse-bug-bounty
bounty --help
```

## Sementara ini (sebelum winget live)

Pakai installer yang sudah jalan:

```powershell
.\scripts\install.ps1
# atau
npm install -g muse-bug-bounty
```
