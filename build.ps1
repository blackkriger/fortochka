#   .\build.ps1              build the self-contained exe + refresh its sha256 (stamps the version)
#   .\build.ps1 -Resources   also regenerate icons + the .syso (icon/manifest) first

param([switch]$Resources)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$version = "0.5.0"
$exe = "fortochka-$version.exe"

if ($Resources) {
  pwsh -NoProfile -File .\tools\genicons.ps1 -OutDir "cmd\fortochka"
  go run ./tools/mksyso cmd/fortochka/fortochka.ico cmd/fortochka/fortochka.syso cmd/fortochka/fortochka.manifest
}

go build -ldflags "-H=windowsgui -X main.version=$version" -o $exe ./cmd/fortochka
Write-Output ("built {0} (self-contained)" -f $exe)

$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
"$hash  $exe" | Out-File -Encoding ascii "$exe.sha256"
Write-Output ("sha256 {0} -> {1}.sha256" -f $hash, $exe) 