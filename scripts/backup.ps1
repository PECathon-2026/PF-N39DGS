# PowerShell script: Safety check and secure multi-remote backup

$ErrorActionPreference = "Stop"

Write-Host "Executing pre-push automated checks..." -ForegroundColor Cyan
& powershell.exe -ExecutionPolicy Bypass -File scripts/check.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Automated checks failed. Aborting backup push."
    exit 1
}

Write-Host "`nPushing to origin main..." -ForegroundColor Green
git push origin main
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to push to origin main."
    exit 1
}

# Check if remote 'hackathon' exists
$remotes = git remote
if ($remotes -contains "hackathon") {
    Write-Host "`nPushing to hackathon remote (main:aaditya-privacylens)..." -ForegroundColor Green
    git push hackathon main:aaditya-privacylens
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to push to hackathon remote."
        exit 1
    }
} else {
    Write-Host "`nNo 'hackathon' remote configured. Skipping hackathon push." -ForegroundColor Yellow
}

Write-Host "`nBackup completed successfully." -ForegroundColor Green
