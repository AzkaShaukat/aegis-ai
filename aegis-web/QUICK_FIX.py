"""
QUICK_FIX.py — Fixes WebSocket, email verification blocking, and auth messages.

Run ONCE from aegis-web\ directory:
    python QUICK_FIX.py

Then restart:
    python start_backend.py   (Window 1)
    python start_frontend.py  (Window 2)
"""
import os, re, sys, pathlib, subprocess

BASE    = pathlib.Path(__file__).parent.resolve()
BACKEND = BASE / "backend"
ENV     = BASE / ".env.web"

def c(code, s): return f"\033[{code}m{s}\033[0m"
ok   = lambda s: print(c(92, f"  ✅ {s}"))
warn = lambda s: print(c(93, f"  ⚠️  {s}"))
err  = lambda s: print(c(91, f"  ❌ {s}"))
inf  = lambda s: print(c(96, f"  → {s}"))
hdr  = lambda s: print(f"\n\033[1m{s}\033[0m")

print()
print(c(1,"="*55))
print(c(1,"    🛡️  Aegis AI — Quick Fix"))
print(c(1,"="*55))

# Find Python in venv
venv_py = BACKEND / ".venv" / "Scripts" / "python.exe"
if not venv_py.exists():
    venv_py = BACKEND / ".venv" / "bin" / "python"
if not venv_py.exists():
    err("Virtual environment not found!")
    sys.exit(1)
ok(f"venv: {venv_py.name}")

# ── Install missing packages ──────────────────────────────────────────────────
hdr("[1/4] Installing required packages…")

packages = {
    "websockets":           "WebSocket support (fixes Reconnecting...)",
    "aiosmtplib==3.0.1":    "Async email",
    "uvicorn[standard]":    "Full uvicorn with WebSocket",
    "psycopg2-binary":      "Sync DB driver for migrations",
    "python-dotenv":        "Env file loading",
}

for pkg, desc in packages.items():
    r = subprocess.run(
        [str(venv_py), "-m", "pip", "install", pkg, "-q"],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        ok(f"{pkg.split('[')[0].split('=')[0]} — {desc}")
    else:
        warn(f"Could not install {pkg}: {r.stderr.strip()[:80]}")

# Remove passlib if still present
r = subprocess.run([str(venv_py), "-m", "pip", "uninstall", "passlib", "-y"],
                   capture_output=True, text=True)
if "Successfully uninstalled" in r.stdout:
    ok("passlib removed (was causing 72-byte error)")

# ── Set EMAIL_ENABLED=false ───────────────────────────────────────────────────
hdr("[2/4] Configuring email settings…")

if not ENV.exists():
    err(f".env.web not found at {ENV}")
    sys.exit(1)

content = ENV.read_text(encoding="utf-8")
if re.search(r"(?i)EMAIL_ENABLED\s*=\s*true", content):
    content = re.sub(r"(?i)EMAIL_ENABLED\s*=\s*true", "EMAIL_ENABLED=false", content)
    ENV.write_text(content, encoding="utf-8")
    ok("EMAIL_ENABLED set to false — users can register/login without email verification")
    inf("To enable real email: set EMAIL_ENABLED=true + configure SMTP_* in .env.web")
else:
    ok("EMAIL_ENABLED=false already set (good)")

# ── Auto-verify existing users in DB ─────────────────────────────────────────
hdr("[3/4] Auto-verifying unverified users in database…")

env_vars = {}
with open(ENV) as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env_vars[k.strip()] = v.strip().strip('"').strip("'")

db_url = env_vars.get("DATABASE_URL", "")
if db_url:
    sync_url = re.sub(r"postgresql\+asyncpg://", "postgresql+psycopg2://", db_url)
    script = f"""
import psycopg2
try:
    c = psycopg2.connect("{sync_url}")
    cur = c.cursor()
    cur.execute("UPDATE users SET email_verified = TRUE WHERE email_verified = FALSE")
    n = cur.rowcount
    c.commit()
    cur.close(); c.close()
    print(f"OK:{{n}}")
except Exception as e:
    print(f"ERR:{{e}}")
"""
    r = subprocess.run([str(venv_py), "-c", script], capture_output=True, text=True)
    out = r.stdout.strip()
    if out.startswith("OK:"):
        n = out[3:]
        ok(f"Verified {n} existing user(s) — they can now log in")
    elif out.startswith("ERR:"):
        warn(f"DB update failed: {out[4:]} — is PostgreSQL running?")
    else:
        warn(f"DB check skipped: {out}{r.stderr[:80]}")
else:
    warn("DATABASE_URL not in .env.web — skipping DB fix")

# ── Verify WebSocket library installed ────────────────────────────────────────
hdr("[4/4] Verifying WebSocket library…")
r = subprocess.run([str(venv_py), "-c", "import websockets; print(websockets.__version__)"],
                   capture_output=True, text=True)
if r.returncode == 0:
    ok(f"websockets {r.stdout.strip()} ✅ — WebSocket connections will work")
else:
    err("websockets import FAILED")
    inf("Try manually: pip install websockets")

# ── Final summary ─────────────────────────────────────────────────────────────
print()
print(c(1,"="*55))
print(c(92,"  ✅ Done! Now:"))
print()
print(c(93,"  IMPORTANT: Restart both servers for changes to take effect"))
print()
print(c(96,"  Window 1 (backend):"))
print(c(97,"      cd 'D:\\Aegis AI\\aegis-web'"))
print(c(97,"      python start_backend.py"))
print()
print(c(96,"  Window 2 (frontend):"))
print(c(97,"      python start_frontend.py"))
print()
print(c(96,"  Or both at once:"))
print(c(97,"      python start_all.py"))
print(c(1,"="*55))
print()
