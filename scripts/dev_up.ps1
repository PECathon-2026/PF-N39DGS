# PowerShell script: Development stack startup for PrivacyLens companion and testsite
# Starts the companion API server and testsite, copies pairing token to clipboard, and opens dev page.

$ErrorActionPreference = "Continue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "    PrivacyLens Dev Stack Initializer     " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Start Testsite HTTP Server (Background job on 8765)
Write-Host "Starting Testsite Server on http://127.0.0.1:8765..." -ForegroundColor Yellow
$testsiteProcess = Start-Process -FilePath ".\.venv\Scripts\python.exe" `
    -ArgumentList "testsite/serve.py" `
    -PassThru `
    -WindowStyle Hidden

# 2. Start PrivacyLens Companion API Server (Background job on 8000)
Write-Host "Starting Companion API on http://127.0.0.1:8000..." -ForegroundColor Yellow
$apiProcess = Start-Process -FilePath ".\.venv\Scripts\python.exe" `
    -ArgumentList "-m", "uvicorn", "privacylens.api.app:app", "--host", "127.0.0.1", "--port", "8000" `
    -PassThru `
    -WindowStyle Hidden

Start-Sleep -Seconds 2

# 3. Copy Token to Clipboard (Never print token to stdout)
Write-Host "Copying pairing token to system clipboard..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -m privacylens token --copy

$tokenPath = [System.IO.Path]::GetFullPath(".pl_token")
Write-Host "[OK] Pairing token copied to clipboard." -ForegroundColor Green
Write-Host "     Token file path: $tokenPath" -ForegroundColor Gray
Write-Host "     (Raw token is never printed to console)" -ForegroundColor Gray

# 4. Open Developer Settings Page
$devUrl = "http://127.0.0.1:8765/devsettings.html?empty=1"
Write-Host "Opening dev settings page: $devUrl" -ForegroundColor Cyan
Start-Process $devUrl

Write-Host "`nDev stack running!" -ForegroundColor Green
Write-Host "API Process ID: $($apiProcess.Id)" -ForegroundColor Gray
Write-Host "Testsite Process ID: $($testsiteProcess.Id)" -ForegroundColor Gray
Write-Host "To terminate background processes when done:" -ForegroundColor Gray
Write-Host "  Stop-Process -Id $($apiProcess.Id), $($testsiteProcess.Id)" -ForegroundColor Gray
