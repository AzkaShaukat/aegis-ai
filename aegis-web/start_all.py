"""
start_all.py — Start backend + frontend together.

Usage:
    python start_all.py             # localhost only
    python start_all.py --network   # expose frontend on local network too
"""
import os, re, sys, time, signal, socket, pathlib, subprocess, threading, webbrowser

BASE     = pathlib.Path(__file__).parent.resolve()
BACKEND  = BASE / "backend"
FRONTEND = BASE / "frontend"
ENV_FILE = BASE / ".env.web"
NETWORK  = "--network" in sys.argv

def c(code, s): return f"\033[{code}m{s}\033[0m"
ok   = lambda s: print(c(92, f"  ✅ {s}"))
warn = lambda s: print(c(93, f"  ⚠️  {s}"))
err  = lambda s: print(c(91, f"  ❌ {s}"))
inf  = lambda s: print(c(96, f"  → {s}"))
hdr  = lambda s: print(f"\n\033[1m{s}\033[0m")
bold = lambda s: print(c(1, s))

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "unknown"

print()
bold("=" * 55)
bold("    🛡️  AEGIS AI WEB — Starting All Services")
bold("=" * 55)

# Find venv python
venv_py = BACKEND / ".venv" / "Scripts" / "python.exe"
if not venv_py.exists():
    venv_py = BACKEND / ".venv" / "bin" / "python"
if not venv_py.exists():
    err("Virtual environment not found!")
    inf("Run: cd backend && python -m venv .venv")
    inf("     .venv\\Scripts\\Activate.ps1")
    inf("     pip install -r requirements.txt")
    sys.exit(1)

if not ENV_FILE.exists():
    err(".env.web not found!")
    inf("Copy .env.web.example → .env.web and configure it")
    sys.exit(1)

if not (FRONTEND / "node_modules").exists():
    err("node_modules not found!")
    inf("Run: cd frontend && npm install")
    sys.exit(1)

hdr("[1/3] Running database migrations…")
env_vars = {}
with open(ENV_FILE) as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env_vars[k.strip()] = v.strip().strip('"').strip("'")

db_url = env_vars.get("DATABASE_URL", "")
if db_url:
    sync_url = re.sub(r"postgresql\+asyncpg://", "postgresql+psycopg2://", db_url)
    mig_env  = os.environ.copy()
    mig_env.update(env_vars)
    mig_env["DATABASE_URL"] = sync_url
    r = subprocess.run(
        [str(venv_py), "-m", "alembic", "--config",
         str(BACKEND / "alembic.ini"), "upgrade", "head"],
        cwd=str(BACKEND), capture_output=True, text=True, env=mig_env, timeout=60,
    )
    if r.returncode == 0:
        ok("Database migrations applied")
    else:
        warn(f"Migration warning: {r.stderr.strip()[-200:]}")
else:
    warn("DATABASE_URL not set — skipping migrations")

hdr("[2/3] Starting backend (port 8007)…")
backend_proc = subprocess.Popen(
    [str(venv_py), "-m", "uvicorn", "app.main:app",
     "--host", "0.0.0.0", "--port", "8007", "--reload",
     "--log-level", "info", "--env-file", str(ENV_FILE)],
    cwd=str(BACKEND),
)
ok(f"Backend PID {backend_proc.pid}")

time.sleep(2)  # give backend a moment to start

hdr("[3/3] Starting frontend…")
npm_cmd   = "npm.cmd" if sys.platform == "win32" else "npm"
vite_args = [npm_cmd, "run", "dev"]
if NETWORK:
    vite_args += ["--", "--host", "0.0.0.0"]

frontend_proc = subprocess.Popen(vite_args, cwd=str(FRONTEND))
ok(f"Frontend PID {frontend_proc.pid}")

local_ip = get_local_ip()

print()
bold("=" * 55)
print(c(92, "  🚀 Aegis AI is running!"))
print()
print(f"  App:      {c(96, 'http://localhost:5174')}")
if NETWORK:
    print(f"  Network:  {c(96, f'http://{local_ip}:5174')}  ← share with other devices")
print(f"  API docs: {c(96, 'http://localhost:8007/docs')}")
print(f"  Health:   {c(96, 'http://localhost:8007/health')}")
print()
print(c(93, "  Press Ctrl+C to stop both servers"))
bold("=" * 55)
print()

def _open_browser():
    time.sleep(4)
    try: webbrowser.open("http://localhost:5174")
    except Exception: pass

threading.Thread(target=_open_browser, daemon=True).start()

def _shutdown(sig, frame):
    print()
    print(c(93, "\n🛑 Shutting down…"))
    try: backend_proc.terminate();  ok("Backend stopped")
    except Exception: pass
    try: frontend_proc.terminate(); ok("Frontend stopped")
    except Exception: pass
    sys.exit(0)

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)

try:
    while True:
        if backend_proc.poll() is not None:
            err("Backend process died! Check logs above.")
            frontend_proc.terminate()
            sys.exit(1)
        time.sleep(2)
except KeyboardInterrupt:
    _shutdown(None, None)
