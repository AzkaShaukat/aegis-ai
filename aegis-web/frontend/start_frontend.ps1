# start_frontend.ps1 — Bootstrap and run the Aegis AI frontend (Windows)
# Run from aegis-web\frontend\ in PowerShell

Write-Host ""
Write-Host "Aegis AI — Frontend Dev Server" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check Node.js
try {
    $nodeVer = node --version 2>&1
    Write-Host "[OK] Node.js $nodeVer" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Node.js not found. Install from https://nodejs.org/ (LTS)" -ForegroundColor Red
    exit 1
}

# Install dependencies if node_modules missing
if (-not (Test-Path "node_modules")) {
    Write-Host "[1/2] Installing dependencies..." -ForegroundColor Yellow
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] npm install failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "[OK] Dependencies already installed" -ForegroundColor Green
}

Write-Host ""
Write-Host "[2/2] Starting Vite dev server..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  App URL:  http://localhost:5173" -ForegroundColor White
Write-Host "  Backend:  http://localhost:8007 (must be running)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press Ctrl+C to stop" -ForegroundColor Gray
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

npm run dev
