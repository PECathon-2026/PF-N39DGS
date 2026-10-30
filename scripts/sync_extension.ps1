# PowerShell script: Synchronize core capture JS to browser extension
# Single source of truth: privacylens/js/capture_dom.js -> extension/capture_dom.js

$ErrorActionPreference = "Stop"

$src = "privacylens/js/capture_dom.js"
$dst = "extension/capture_dom.js"

if (-not (Test-Path $src)) {
    Write-Error "Source file '$src' not found!"
    exit 1
}

if (-not (Test-Path "extension")) {
    New-Item -ItemType Directory -Path "extension" | Out-Null
}

Copy-Item -Path $src -Destination $dst -Force
Write-Host "[OK] Synced $src -> $dst" -ForegroundColor Green
