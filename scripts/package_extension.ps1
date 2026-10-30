# PowerShell script: Package the PrivacyLens browser extension into a distributable zip archive.
# Output artifact: dist/privacylens-extension-v0.1.0.zip

$ErrorActionPreference = "Stop"

Write-Host "Packaging PrivacyLens Browser Extension..." -ForegroundColor Cyan

$distDir = "dist"
if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

$zipPath = Join-Path $distDir "privacylens-extension-v0.1.0.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

# Ensure capture_dom.js is synchronized before packaging
Write-Host "Syncing capture_dom.js..." -ForegroundColor Gray
& powershell -ExecutionPolicy Bypass -File scripts/sync_extension.ps1

Write-Host "Compressing extension/ directory into $zipPath..." -ForegroundColor Yellow
Compress-Archive -Path "extension/*" -DestinationPath $zipPath -Force

$zipItem = Get-Item $zipPath
$sizeKb = [math]::Round($zipItem.Length / 1KB, 2)
Write-Host "[OK] Packaged extension successfully: $zipPath ($sizeKb KB)" -ForegroundColor Green
