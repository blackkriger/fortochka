#   .\build.ps1              build the self-contained exe + refresh its sha256 (stamps the version)
#   .\build.ps1 -Resources   also regenerate icons + the .syso (icon/manifest) first

param([switch]$Resources)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$version = "0.4.1"

if ($Resources) {
  pwsh -NoProfile -File .\tools\genicons.ps1 -OutDir "cmd\fortochka"
  go run ./tools/mksyso cmd/fortochka/fortochka.ico cmd/fortochka/fortochka.syso cmd/fortochka/fortochka.manifest
}

go build -ldflags "-H=windowsgui -X main.version=$version" -o fortochka.exe ./cmd/fortochka
Write-Output ("built fortochka {0} -> fortochka.exe (self-contained)" -f $version)

$hash = (Get-FileHash fortochka.exe -Algorithm SHA256).Hash.ToLower()
"$hash  fortochka.exe" | Out-File -Encoding ascii fortochka.exe.sha256
Write-Output ("sha256 {0} -> fortochka.exe.sha256" -f $hash) 