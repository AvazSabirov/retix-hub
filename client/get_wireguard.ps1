# Скачивает официальные установщики WireGuard и проверяет их цифровую подпись (WireGuard LLC).
# Их кладёт в установщик Retix Hub build.bat:
#   client\wireguard\wireguard-amd64-<последняя>.msi  — для Windows 10/11;
#   client\wireguard81\wireguard-amd64-0.5.3.msi       — для Windows 8.1: WireGuard for Windows 0.6 и новее
#     требует Windows 10 (WIREGUARD_WIN81=<версия> — другая версия для 8.1).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$base = 'https://download.wireguard.com/windows-client/'

function Get-WireGuard([string]$sub, [string]$ver) {
    $dir = Join-Path $PSScriptRoot $sub
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $have = Get-ChildItem -Path $dir -Filter 'wireguard-amd64-*.msi' -ErrorAction SilentlyContinue
    if ($have) { Write-Host "WireGuard уже скачан: $sub\$($have[-1].Name)"; return }

    if (-not $ver) {   # последняя версия из списка на сайте
        $html = (Invoke-WebRequest -UseBasicParsing -Uri $base).Content
        $ver = [regex]::Matches($html, 'wireguard-amd64-([0-9.]+)\.msi') |
            ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique |
            Sort-Object { [version]$_ } | Select-Object -Last 1
        if (-not $ver) { throw "Не найден wireguard-amd64-*.msi на $base" }
    }

    $name = "wireguard-amd64-$ver.msi"
    $out = Join-Path $dir $name
    Write-Host "Скачиваю $base$name"
    Invoke-WebRequest -UseBasicParsing -Uri ($base + $name) -OutFile $out

    $sig = Get-AuthenticodeSignature -FilePath $out
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
        Remove-Item $out -Force
        throw "Подпись $name не прошла проверку: $($sig.Status) $($sig.SignerCertificate.Subject)"
    }
    Write-Host "OK: $sub\$name, подпись WireGuard LLC"
}

Get-WireGuard 'wireguard' ''
$win81 = if ($env:WIREGUARD_WIN81) { $env:WIREGUARD_WIN81 } else { '0.5.3' }
Get-WireGuard 'wireguard81' $win81
