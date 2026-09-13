[console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Load .env file if it exists
if (Test-Path ".env") {
    foreach ($line in Get-Content ".env") {
        # Match lines like KEY=VALUE and ignore comments
        if ($line -match "^([^#\s][^=]*)=(.*)$") {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            Set-Item -Path "Env:$name" -Value $value
        }
    }
}
$classpath = "out;lib\*"
java "-Dfile.encoding=UTF-8" -cp $classpath shadowscan.ShadowScan
