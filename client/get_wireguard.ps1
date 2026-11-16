# Скачивает официальный установщик WireGuard (wireguard-amd64-<версия>.msi) в client\wireguard\
# и проверяет его цифровую подпись (WireGuard LLC). Его кладёт в установщик Retix Hub build.bat.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$dir = Join-Path $PSScriptRoot 'wireguard'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$have = Get-ChildItem -Path $dir -Filter 'wireguard-amd64-*.msi' -ErrorAction SilentlyContinue
if ($have) { Write-Host "WireGuard уже скачан: $($have[-1].Name)"; exit 0 }

$base = 'https://download.wireguard.com/windows-client/'
$html = (Invoke-WebRequest -UseBasicParsing -Uri $base).Content
$ver = [regex]::Matches($html, 'wireguard-amd64-([0-9.]+)\.msi') |
    ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique |
    Sort-Object { [version]$_ } | Select-Object -Last 1
if (-not $ver) { throw "Не найден wireguard-amd64-*.msi на $base" }

$name = "wireguard-amd64-$ver.msi"
$out = Join-Path $dir $name
Write-Host "Скачиваю $base$name"
Invoke-WebRequest -UseBasicParsing -Uri ($base + $name) -OutFile $out

$sig = Get-AuthenticodeSignature -FilePath $out
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
    Remove-Item $out -Force
    throw "Подпись $name не прошла проверку: $($sig.Status) $($sig.SignerCertificate.Subject)"
}
Write-Host "OK: $name, подпись WireGuard LLC"
