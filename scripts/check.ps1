# PowerShell script: Automated safety, lint, unit test, and environment check

$ErrorActionPreference = "Continue"

Write-Host "Running PrivacyLens Automated Checks..." -ForegroundColor Cyan

$results = [ordered]@{}

# 1. Secrets Check
Write-Host "1/4 Running Secrets Safety Check..."
& .\.venv\Scripts\python.exe scripts/check_secrets.py
if ($LASTEXITCODE -eq 0) {
    $results["Secrets Check"] = "PASS"
} else {
    $results["Secrets Check"] = "FAIL"
}

# 2. Ruff Linter Check
Write-Host "2/4 Running Ruff Linter..."
& .\.venv\Scripts\ruff.exe check .
if ($LASTEXITCODE -eq 0) {
    $results["Ruff Linter"] = "PASS"
} else {
    $results["Ruff Linter"] = "FAIL"
}

# 3. Pytest (Excluding Slow Tests)
Write-Host "3/4 Running Pytest Unit Tests..."
& .\.venv\Scripts\pytest.exe -q
if ($LASTEXITCODE -eq 0) {
    $results["Pytest Unit Tests"] = "PASS"
} else {
    $results["Pytest Unit Tests"] = "FAIL"
}

# 4. Smoke Check (Environment & Browser)
Write-Host "4/4 Running Runtime Smoke Check..."
& .\.venv\Scripts\python.exe scripts/smoke_check.py
if ($LASTEXITCODE -eq 0) {
    $results["Runtime Smoke Check"] = "PASS"
} else {
    $results["Runtime Smoke Check"] = "FAIL"
}

# Print Summary Table
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       PRIVACYLENS CHECK RESULTS          " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ("{0,-28} | {1,-8}" -f "Check", "Status")
Write-Host "-----------------------------+------------"

$failed = $false
foreach ($key in $results.Keys) {
    $status = $results[$key]
    if ($status -eq "PASS") {
        Write-Host ("{0,-28} | " -f $key) -NoNewline
        Write-Host ("{0,-8}" -f $status) -ForegroundColor Green
    } else {
        Write-Host ("{0,-28} | " -f $key) -NoNewline
        Write-Host ("{0,-8}" -f $status) -ForegroundColor Red
        $failed = $true
    }
}
Write-Host "==========================================" -ForegroundColor Cyan

if ($failed) {
    Write-Host "`nResult: One or more checks FAILED." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nResult: All checks PASSED." -ForegroundColor Green
    exit 0
}
