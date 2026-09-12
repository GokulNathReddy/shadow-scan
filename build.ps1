$ErrorActionPreference = "Stop"

# Create directories
New-Item -ItemType Directory -Force -Path "lib" | Out-Null
New-Item -ItemType Directory -Force -Path "out" | Out-Null

# Download dependencies if missing
$bcprovUrl = "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar"
$gsonUrl = "https://repo1.maven.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar"

if (-not (Test-Path "lib\bcprov-jdk18on-1.78.1.jar")) {
    Write-Host "Downloading BouncyCastle..."
    Invoke-WebRequest -Uri $bcprovUrl -OutFile "lib\bcprov-jdk18on-1.78.1.jar" -UseBasicParsing
}

if (-not (Test-Path "lib\gson-2.11.0.jar")) {
    Write-Host "Downloading Gson..."
    Invoke-WebRequest -Uri $gsonUrl -OutFile "lib\gson-2.11.0.jar" -UseBasicParsing
}

# Compile
Write-Host "Compiling source files..."
$sources = Get-ChildItem -Path "src\main\java" -Filter "*.java" -Recurse | Select-Object -ExpandProperty FullName
$classpath = "lib\*"
javac -d out -cp $classpath $sources

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful. Run with .\run.ps1" -ForegroundColor Green
} else {
    Write-Host "Build failed." -ForegroundColor Red
    exit 1
}
