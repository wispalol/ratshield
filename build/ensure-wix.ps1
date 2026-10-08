param([string]$Dir = "")

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Dir)) {
    $root = Split-Path -Parent $PSScriptRoot
    $wix = Join-Path $root "target\wix"
} else {
    $wix = $Dir
}

$candle = Join-Path $wix "candle.exe"
$light = Join-Path $wix "light.exe"

if ((Test-Path -LiteralPath $candle) -and (Test-Path -LiteralPath $light)) {
    Write-Output "wix-ready:$wix"
    exit 0
}

if (-not [string]::IsNullOrWhiteSpace($env:WIX)) {
    $cand = Join-Path $env:WIX "candle.exe"
    if (Test-Path $cand) {
        Write-Output "wix-ready:$env:WIX"
        exit 0
    }
}

if (Get-Command candle.exe -ErrorAction SilentlyContinue) {
    $candleCmd = (Get-Command candle.exe).Source
    $wixFromCmd = Split-Path -Parent $candleCmd
    Write-Output "wix-ready:$wixFromCmd"
    exit 0
}

Write-Output "Downloading WiX 3.14 tools for jpackage --type exe ..."
New-Item -ItemType Directory -Path $wix -Force | Out-Null
$urls = @(
    "https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip",
    "https://netcologne.dl.sourceforge.net/project/wix/wixtoolset/3.14.1.5542/wix314-binaries.zip"
)
$zip = Join-Path $wix "wix314.zip"
$success = $false
foreach ($u in $urls) {
    try {
        Invoke-WebRequest -Uri $u -OutFile $zip -UseBasicParsing -TimeoutSec 120
        expand-archive -LiteralPath $zip -DestinationPath $wix -Force
        Remove-Item -LiteralPath $zip -Force
        $success = $true
        break
    } catch {
        Write-Warning "Failed to download from $u : $($_.Exception.Message)"
        if (Test-Path $zip) { Remove-Item $zip -Force }
    }
}
if (-not $success -or -not (Test-Path -LiteralPath $candle)) {
    Write-Error "WiX download failed: candle.exe not found under $wix"
    exit 1
}
Write-Output "wix-ready:$wix"
