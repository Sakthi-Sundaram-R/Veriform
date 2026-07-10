# Start the full Veriform demo locally on Windows (no Docker needed).
# Uses the dev shim as a stand-in enclave. Open http://localhost:3000 after.
#
#   powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1
#
# Reads GEMINI_API_KEY from .env if present (falls back to rules-only judging).

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# Load .env
$geminiKey = ""
$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*GEMINI_API_KEY=(.+)$') { $geminiKey = $Matches[1].Trim() }
    }
}
$judge = if ($geminiKey) { "gemini" } else { "none" }

function Start-Svc($name, $dir, $port, $extraEnv) {
    $env:GEMINI_API_KEY = $geminiKey
    foreach ($kv in $extraEnv.GetEnumerator()) { Set-Item "env:$($kv.Key)" $kv.Value }
    Start-Process -WindowStyle Minimized -WorkingDirectory (Join-Path $root $dir) `
        -FilePath "python" `
        -ArgumentList "-X","utf8","-m","uvicorn","app.main:app","--port",$port,"--log-level","warning"
    Write-Host "  started $name on :$port"
}

Write-Host "Starting Veriform (judge provider: $judge)…"
Start-Process -WindowStyle Minimized -WorkingDirectory (Join-Path $root "dev-sim") `
    -FilePath "python" -ArgumentList "-X","utf8","-m","uvicorn","sim:app","--port","8090","--log-level","warning"
Write-Host "  started dev-sim (enclave shim) on :8090"
Start-Sleep -Seconds 2

Start-Svc "agent"      "agent"      8001 @{ JUDGE_PROVIDER=$judge; DSTACK_SIMULATOR_ENDPOINT="http://localhost:8090" }
Start-Svc "evil-agent" "evil-agent" 8002 @{ EVIL_MODE="none" }
Start-Svc "verifier"   "verifier"   3000 @{ AGENT_URL="http://localhost:8001"; EVIL_AGENT_URL="http://localhost:8002" }

Write-Host ""
Write-Host "Veriform is up. Open http://localhost:3000"
Write-Host "Stop everything with: Get-Process python | Stop-Process"
