"""start_backend.py — Start the FastAPI backend with auto-setup."""
import os, sys, re, pathlib, subprocess, textwrap

BASE     = pathlib.Path(__file__).parent.resolve()
BACKEND  = BASE / "backend"
ENV_FILE = BASE / ".env.web"

def c(code, s): return f"\033[{code}m{s}\033[0m"
green  = lambda s: c(92, s)
yellow = lambda s: c(93, s)
red    = lambda s: c(91, s)
cyan   = lambda s: c(96, s)
bold   = lambda s: c(1, s)

print()
print(bold("=" * 55))
print(bold("    🛡️  Aegis AI — Backend Launcher"))
print(bold("=" * 55))
print()

# ── Find venv Python ──────────────────────────────────────────
venv_py = BACKEND / ".venv" / "Scripts" / "python.exe"
if not venv_py.exists():
    venv_py = BACKEND / ".venv" / "bin" / "python"
if not venv_py.exists():
    print(red("❌ Virtual environment not found at backend/.venv/"))
    sys.exit(1)
print(green(f"✅ venv: {venv_py}"))

if not ENV_FILE.exists():
    print(red(f"❌ .env.web not found")); sys.exit(1)

# ── Load .env.web ────────────────────────────────────────────
env_vars = {}
with open(ENV_FILE) as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env_vars[k.strip()] = v.strip().strip('"').strip("'")
print(green("✅ .env.web loaded"))

# ── Remove passlib (breaks bcrypt) ───────────────────────────
print()
print(cyan("Checking for passlib conflicts…"))
if "found" in subprocess.run(
    [str(venv_py), "-c", "import passlib; print('found')"],
    capture_output=True, text=True,
).stdout:
    subprocess.run([str(venv_py), "-m", "pip", "uninstall", "passlib", "-y"], capture_output=True)
    print(green("   ✅ passlib removed"))

# ── Install / update deps ────────────────────────────────────
print(cyan("Verifying dependencies…"))
r = subprocess.run(
    [str(venv_py), "-m", "pip", "install", "-r", str(BACKEND / "requirements.txt"), "-q"],
    capture_output=True, text=True,
)
if r.returncode != 0:
    print(yellow(f"⚠️  pip warning: {r.stderr.strip()[:200]}"))

# ── Run migrations ───────────────────────────────────────────
print()
print(cyan("Running database migrations…"))
db_url = env_vars.get("DATABASE_URL", "")
if db_url:
    sync_url = re.sub(r"postgresql\+asyncpg://", "postgresql+psycopg2://", db_url)
    mig_env  = {**os.environ, **env_vars, "DATABASE_URL": sync_url}
    r = subprocess.run(
        [str(venv_py), "-m", "alembic", "--config",
         str(BACKEND / "alembic.ini"), "upgrade", "head"],
        cwd=str(BACKEND), capture_output=True, text=True, env=mig_env, timeout=60,
    )
    if r.returncode == 0:
        print(green("✅ Database schema up to date"))
    else:
        print(yellow(f"⚠️  Migration warning: {r.stderr.strip()[-300:]}"))
else:
    print(yellow("⚠️  DATABASE_URL not set — skipping migrations"))

print()
print(bold("─" * 55))
print(f"  App:      {cyan('http://localhost:5173')}  (frontend)")
print(f"  API:      {cyan('http://localhost:8007')}")
print(f"  Docs:     {cyan('http://localhost:8007/docs')}")
print(f"  Health:   {cyan('http://localhost:8007/health')}")
print(bold("─" * 55))
print(yellow("  Ctrl+C to stop"))
print()

# ── Write launcher with proper Windows __main__ guard ────────
# ws_ping_interval=None DISABLES server-side WS pings.
# --ws-ping-interval 0 does NOT disable them (sets 0s interval).
# The __name__ guard is REQUIRED on Windows for multiprocessing.
_lpath = BACKEND / ".uvicorn_launcher.py"
_lpath.write_text(textwrap.dedent(f"""
    # Auto-generated — do not edit manually
    import os, sys
    sys.path.insert(0, r'{BACKEND}')

    # Load env
    _ef = r'{ENV_FILE}'
    if os.path.exists(_ef):
        with open(_ef) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _k, _, _v = _line.partition('=')
                    os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

    if __name__ == '__main__':
        import uvicorn
        uvicorn.run(
            'app.main:app',
            host='0.0.0.0',
            port=8007,
            reload=True,
            reload_dirs=[r'{BACKEND}'],
            log_level='info',
            ws_ping_interval=None,   # Disables WS pings (Vite proxy fix)
            ws_ping_timeout=None,
        )
""").lstrip(), encoding="utf-8")

try:
    subprocess.run([str(venv_py), str(_lpath)], cwd=str(BACKEND))
except KeyboardInterrupt:
    print(yellow("\nBackend stopped."))
