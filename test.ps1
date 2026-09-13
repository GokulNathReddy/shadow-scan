$ErrorActionPreference = 'Stop'

Write-Host "Running ShadowScan Tests..." -ForegroundColor Cyan

# Fix for incorrect JAVA_HOME on Windows
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21"

# Use gradlew to run the tests
.\gradlew.bat test

if ($LASTEXITCODE -eq 0) {
    Write-Host "All tests passed successfully!" -ForegroundColor Green
} else {
    Write-Host "Some tests failed. Check the reports in build/reports/tests/test/index.html" -ForegroundColor Red
}
