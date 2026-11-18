# Скачивает официальный RustDesk для Windows (rustdesk-<версия>-x86_64.exe) из релиза GitHub rustdesk/rustdesk
# в client\rustdesk\ и проверяет его. Его кладёт в установщик Retix Hub build.bat; ставит клиент Retix Hub,
# когда в кабинете компании включено удалённое управление. Код RustDesk не меняется.
#   RUSTDESK_VERSION=1.4.4 — взять эту версию, иначе последний стабильный релиз.
#   GITHUB_TOKEN — если задан (GitHub Actions), запросы к API GitHub не упираются в лимит.
# Проверка: SHA-256 совпадает с тем, что GitHub публикует для файла релиза (digest), и цифровая подпись —
# действительная подпись PURSLANE (разработчик RustDesk). Без подписи файл берётся, только если GitHub
# дал SHA-256 и он совпал; любая другая подпись или испорченная — ошибка сборки.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$dir = Join-Path $PSScriptRoot 'rustdesk'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$have = Get-ChildItem -Path $dir -Filter 'rustdesk-*-x86_64.exe' -ErrorAction SilentlyContinue
if ($have) { Write-Host "RustDesk уже скачан: $($have[-1].Name)"; exit 0 }

$headers = @{ 'User-Agent' = 'retixhub-build'; 'Accept' = 'application/vnd.github+json' }
if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
$api = 'https://api.github.com/repos/rustdesk/rustdesk/releases/'
$url = if ($env:RUSTDESK_VERSION) { $api + 'tags/' + $env:RUSTDESK_VERSION } else { $api + 'latest' }
$rel = Invoke-RestMethod -Uri $url -Headers $headers
$asset = $rel.assets | Where-Object { $_.name -match '^rustdesk-[0-9.]+-x86_64\.exe$' } | Select-Object -First 1
if (-not $asset) { throw "В релизе RustDesk $($rel.tag_name) нет rustdesk-*-x86_64.exe" }

$out = Join-Path $dir $asset.name
Write-Host "Скачиваю $($asset.browser_download_url)"
Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $out

$sha = (Get-FileHash -Algorithm SHA256 -Path $out).Hash.ToLower()
$digest = "$($asset.digest)".ToLower()
$shaOk = $false
if ($digest -match '^sha256:([0-9a-f]{64})$') {
    if ($Matches[1] -ne $sha) {
        Remove-Item $out -Force
        throw "SHA-256 $($asset.name) не совпал с релизом GitHub: $sha"
    }
    $shaOk = $true
}

$sig = Get-AuthenticodeSignature -FilePath $out
if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'PURSLANE') {
    Write-Host "OK: $($asset.name), подпись $($sig.SignerCertificate.Subject), SHA-256 $sha"
} elseif ($sig.Status -eq 'NotSigned' -and $shaOk) {
    Write-Warning "$($asset.name) без цифровой подписи; SHA-256 совпал с релизом GitHub ($sha)"
} else {
    Remove-Item $out -Force
    throw "Проверка $($asset.name) не пройдена: подпись $($sig.Status) $($sig.SignerCertificate.Subject), SHA-256 с релизом: $shaOk"
}
