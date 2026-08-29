#!/usr/bin/env python
"""
run_backend_noping.py  — use instead of start_backend.py
Disables WS keepalive pings (fixes "Connecting to server" hang).
"""
import os, sys, pathlib, subprocess

HERE    = pathlib.Path(__file__).parent.resolve()
BACKEND = HERE / "backend"
VENV_PY = BACKEND / ".venv" / "Scripts" / "python.exe"   # Windows
if not VENV_PY.exists():
    VENV_PY = BACKEND / ".venv" / "bin" / "python"        # Linux/Mac

# ── Re-launch with the backend venv if we're not already in it ──
if not str(sys.executable).startswith(str(BACKEND / ".venv")):
    if not VENV_PY.exists():
        print(f"ERROR: backend venv not found at {VENV_PY}")
        sys.exit(1)
    print(f"Switching to backend venv: {VENV_PY}")
    os.execv(str(VENV_PY), [str(VENV_PY), __file__] + sys.argv[1:])

# ── From here we're running inside the correct venv ─────────────
os.chdir(BACKEND)
sys.path.insert(0, str(BACKEND))

# Load .env.web
env_path = HERE / ".env.web"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
    print("✅ .env.web loaded")

# Run migrations via alembic CLI (not __main__)
print("Running migrations…")
result = subprocess.run(
    [sys.executable, "-m", "alembic", "upgrade", "head"],
    capture_output=True, text=True, cwd=str(BACKEND)
)
if "alembic" in (result.stderr or "").lower() and "error" in (result.stderr or "").lower():
    # Try alternate: alembic binary
    alembic_bin = BACKEND / ".venv" / "Scripts" / "alembic.exe"
    if alembic_bin.exists():
        result = subprocess.run(
            [str(alembic_bin), "upgrade", "head"],
            capture_output=True, text=True, cwd=str(BACKEND)
        )
if result.returncode == 0:
    print("✅ Database schema up to date")
else:
    print(f"⚠️  Migration note: {(result.stderr or result.stdout or '')[:120]}")

print()
print("=" * 52)
print("  🛡️  Aegis AI Backend  (WS pings disabled)")
print("=" * 52)
print("  API:   http://localhost:8007")
print("  Docs:  http://localhost:8007/docs")
print("  WS pings: DISABLED (fixes Vite proxy timeout)")
print("=" * 52)
print()

import uvicorn
uvicorn.run(
    "app.main:app",
    host="0.0.0.0",
    port=8007,
    reload=True,
    reload_dirs=[str(BACKEND)],
    log_level="info",
    ws_ping_interval=None,
    ws_ping_timeout=None,
)
