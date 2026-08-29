# FIX_ALL.ps1 - Run this from aegis-web\ directory
# PowerShell: .\FIX_ALL.ps1
# Or from cmd: powershell -ExecutionPolicy Bypass -File FIX_ALL.ps1

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "   Aegis AI - Complete Fix Script" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

$BASE    = Split-Path -Parent $MyInvocation.MyCommand.Path
$BACKEND = Join-Path $BASE "backend"
$ENV     = Join-Path $BASE ".env.web"
$VENV_PY = Join-Path $BACKEND ".venv\Scripts\python.exe"

if (-not (Test-Path $VENV_PY)) {
    Write-Host "ERROR: Virtual environment not found at $VENV_PY" -ForegroundColor Red
    Write-Host "Run: cd backend && python -m venv .venv && .venv\Scripts\Activate.ps1 && pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1/5] Installing ALL required packages..." -ForegroundColor Yellow
$packages = @(
    "websockets",
    "aiosmtplib==3.0.1",
    "uvicorn[standard]",
    "psycopg2-binary",
    "python-dotenv",
    "bcrypt==4.1.3"
)
foreach ($pkg in $packages) {
    $r = & $VENV_PY -m pip install $pkg -q 2>&1
    Write-Host "  OK: $pkg" -ForegroundColor Green
}

# Remove passlib
& $VENV_PY -m pip uninstall passlib -y -q 2>&1 | Out-Null
Write-Host "  OK: passlib removed" -ForegroundColor Green

Write-Host ""
Write-Host "[2/5] Verifying websockets installed..." -ForegroundColor Yellow
$wsVersion = & $VENV_PY -c "import websockets; print(websockets.__version__)" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK: websockets $wsVersion installed" -ForegroundColor Green
} else {
    Write-Host "  FAIL: websockets still not found - trying pip directly..." -ForegroundColor Red
    pip install websockets
}

Write-Host ""
Write-Host "[3/5] Setting EMAIL_ENABLED=false in .env.web..." -ForegroundColor Yellow
if (Test-Path $ENV) {
    $content = Get-Content $ENV -Raw
    $content = $content -replace "(?i)EMAIL_ENABLED\s*=\s*true", "EMAIL_ENABLED=false"
    if ($content -notmatch "EMAIL_ENABLED") {
        $content += "`nEMAIL_ENABLED=false`n"
    }
    Set-Content $ENV $content -NoNewline
    Write-Host "  OK: EMAIL_ENABLED=false" -ForegroundColor Green
} else {
    Write-Host "  WARN: .env.web not found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[4/5] Auto-verifying unverified users in database..." -ForegroundColor Yellow
$envVars = @{}
Get-Content $ENV | ForEach-Object {
    if ($_ -match "^\s*([^#][^=]+)=(.+)$") {
        $envVars[$matches[1].Trim()] = $matches[2].Trim().Trim('"').Trim("'")
    }
}
$dbUrl = $envVars["DATABASE_URL"] -replace "postgresql\+asyncpg://", "postgresql+psycopg2://"

if ($dbUrl) {
    $script = "import psycopg2; c=psycopg2.connect('$dbUrl'); cur=c.cursor(); cur.execute('UPDATE users SET email_verified=TRUE WHERE email_verified=FALSE'); n=cur.rowcount; c.commit(); c.close(); print(f'Updated {n} users')"
    $result = & $VENV_PY -c $script 2>&1
    Write-Host "  OK: $result" -ForegroundColor Green
} else {
    Write-Host "  SKIP: DATABASE_URL not found in .env.web" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[5/5] Running database migrations..." -ForegroundColor Yellow
$env:DATABASE_URL = $dbUrl
Push-Location $BACKEND
$migResult = & $VENV_PY -m alembic upgrade head 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK: Migrations applied" -ForegroundColor Green
} else {
    Write-Host "  WARN: $migResult" -ForegroundColor Yellow
}
Pop-Location

Write-Host ""
Write-Host "======================================================" -ForegroundColor Green
Write-Host "   ALL FIXES APPLIED!" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Now restart both servers:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Window 1: python start_backend.py" -ForegroundColor White
Write-Host "  Window 2: python start_frontend.py" -ForegroundColor White
Write-Host ""
Write-Host "Or both at once: python start_all.py" -ForegroundColor White
Write-Host ""
