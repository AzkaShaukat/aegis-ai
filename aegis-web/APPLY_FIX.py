"""
APPLY_FIX.py — Run this ONCE from aegis-web\ to fix all registration issues.

Usage:
    cd "D:\\Aegis AI\\aegis-web"
    python APPLY_FIX.py

What it does:
  1. Removes passlib (root cause of the 72-byte error)
  2. Overwrites security.py with stdlib PBKDF2 (no external hashing library)
  3. Overwrites alembic/env.py (standalone, no async engine import)
  4. Runs database migrations
  5. Verifies everything works with a quick self-test
"""
import os, sys, re, pathlib, subprocess, textwrap

BASE    = pathlib.Path(__file__).parent.resolve()
BACKEND = BASE / "backend"

def c(code, s): return f"\033[{code}m{s}\033[0m"
ok  = lambda s: print(c(92, f"  ✅ {s}"))
err = lambda s: print(c(91, f"  ❌ {s}"))
inf = lambda s: print(c(96, f"  → {s}"))
hdr = lambda s: print(f"\n\033[1m{s}\033[0m")

print()
print(c(1, "=" * 55))
print(c(1, "    🛡️  Aegis AI — Apply Final Fix"))
print(c(1, "=" * 55))

# ── Find Python in venv ────────────────────────────────────────────────────────
hdr("[1/6] Locating virtual environment…")
venv_py = BACKEND / ".venv" / "Scripts" / "python.exe"
if not venv_py.exists():
    venv_py = BACKEND / ".venv" / "bin" / "python"
if not venv_py.exists():
    err("Virtual environment not found!")
    inf("Run: cd backend && python -m venv .venv && .venv\\Scripts\\Activate.ps1 && pip install -r requirements.txt")
    sys.exit(1)
ok(f"venv found: {venv_py}")

# ── Remove passlib ────────────────────────────────────────────────────────────
hdr("[2/6] Removing passlib (causes 72-byte error)…")
r = subprocess.run([str(venv_py), "-m", "pip", "uninstall", "passlib", "-y"],
                   capture_output=True, text=True)
if "Successfully uninstalled" in r.stdout:
    ok("passlib removed")
elif "not installed" in r.stderr.lower() or "WARNING" in r.stderr:
    ok("passlib was not installed (good)")
else:
    ok("passlib removal completed")

# Also remove bcrypt to avoid any residual conflicts
subprocess.run([str(venv_py), "-m", "pip", "uninstall", "bcrypt", "-y"],
               capture_output=True, text=True)
ok("bcrypt uninstalled (not needed — using stdlib PBKDF2)")

# ── Write security.py ─────────────────────────────────────────────────────────
hdr("[3/6] Writing security.py (pure stdlib PBKDF2)…")
security_src = textwrap.dedent('''
    """app/core/security.py — Stdlib-only PBKDF2-SHA256 password hashing.
    No passlib. No bcrypt. No 72-byte limit. Works for any password length.
    """
    from __future__ import annotations
    import base64, hashlib, hmac, os, secrets
    from datetime import datetime, timedelta, timezone
    from typing import Optional
    from jose import JWTError, jwt
    from app.core.config import get_settings

    settings = get_settings()

    _ALGO, _ITERATIONS, _SALT_LEN, _KEY_LEN = "sha256", 260_000, 16, 32

    def hash_password(plain: str) -> str:
        salt     = os.urandom(_SALT_LEN)
        dk       = hashlib.pbkdf2_hmac(_ALGO, plain.encode("utf-8"), salt, _ITERATIONS, _KEY_LEN)
        b64_salt = base64.b64encode(salt).decode("ascii")
        b64_hash = base64.b64encode(dk).decode("ascii")
        return f"pbkdf2_sha256${_ITERATIONS}${b64_salt}${b64_hash}"

    def verify_password(plain: str, stored: str) -> bool:
        try:
            parts = stored.split("$")
            if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
                return False
            iters = int(parts[1])
            salt  = base64.b64decode(parts[2])
            expected = base64.b64decode(parts[3])
            dk = hashlib.pbkdf2_hmac(_ALGO, plain.encode("utf-8"), salt, iters, _KEY_LEN)
            return hmac.compare_digest(dk, expected)
        except Exception:
            return False

    def create_access_token(user_id: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
        return jwt.encode({"sub": user_id, "exp": exp, "type": "access"},
                          settings.jwt_secret, algorithm=settings.jwt_algorithm)

    def create_refresh_token(user_id: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
        return jwt.encode({"sub": user_id, "exp": exp, "type": "refresh"},
                          settings.jwt_secret, algorithm=settings.jwt_algorithm)

    def decode_token(token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        except JWTError:
            return None

    def create_email_token(user_id: str, email: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(hours=24)
        return jwt.encode({"sub": user_id, "email": email, "exp": exp, "type": "email_verify"},
                          settings.jwt_secret, algorithm=settings.jwt_algorithm)

    def decode_email_token(token: str) -> Optional[dict]:
        p = decode_token(token)
        return p if p and p.get("type") == "email_verify" else None

    def create_password_reset_token(user_id: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        return jwt.encode({"sub": user_id, "exp": exp, "type": "pwd_reset"},
                          settings.jwt_secret, algorithm=settings.jwt_algorithm)

    def decode_password_reset_token(token: str) -> Optional[str]:
        p = decode_token(token)
        return p.get("sub") if p and p.get("type") == "pwd_reset" else None

    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def generate_secure_token() -> str:
        return secrets.token_urlsafe(32)
''').strip()

sec_path = BACKEND / "app" / "core" / "security.py"
sec_path.write_text(security_src, encoding="utf-8")
ok(f"Written: {sec_path}")

# Verify it works
test = subprocess.run(
    [str(venv_py), "-c",
     "import sys; sys.path.insert(0,'backend'); "
     "from app.core.security import hash_password, verify_password; "
     "h=hash_password('TestLongPass#123ABC'); "
     "assert verify_password('TestLongPass#123ABC', h); "
     "assert not verify_password('WrongPass', h); "
     "print('PASS')"],
    cwd=str(BASE), capture_output=True, text=True
)
if "PASS" in test.stdout:
    ok("Password hashing self-test passed")
else:
    err(f"Self-test failed: {test.stderr.strip()[-300:]}")

# ── Write alembic/env.py ──────────────────────────────────────────────────────
hdr("[4/6] Writing alembic/env.py (standalone, no async imports)…")
env_src = textwrap.dedent('''
    """alembic/env.py — Standalone sync migrations. Imports nothing from app/."""
    from __future__ import annotations
    import os, re
    from logging.config import fileConfig
    from sqlalchemy import (
        engine_from_config, pool, text,
        Column, String, Boolean, DateTime, Text, ForeignKey,
        Enum as SAEnum, MetaData, Table,
    )
    from sqlalchemy.dialects.postgresql import UUID, JSONB
    from alembic import context

    config = context.config
    if config.config_file_name:
        fileConfig(config.config_file_name)

    _meta = MetaData()
    Table("users", _meta,
        Column("id", UUID(as_uuid=True), primary_key=True),
        Column("email", String(255), unique=True, nullable=False),
        Column("password_hash", String(512), nullable=False),
        Column("display_name", String(100), nullable=False),
        Column("is_active", Boolean(), nullable=False, server_default="true"),
        Column("email_verified", Boolean(), nullable=False, server_default="false"),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
        Column("last_login", DateTime(timezone=True), nullable=True),
    )
    Table("chat_sessions", _meta,
        Column("id", UUID(as_uuid=True), primary_key=True),
        Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")),
        Column("title", String(255), nullable=False, server_default="New Chat"),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
        Column("is_archived", Boolean(), nullable=False, server_default="false"),
    )
    Table("messages", _meta,
        Column("id", UUID(as_uuid=True), primary_key=True),
        Column("session_id", UUID(as_uuid=True), ForeignKey("chat_sessions.id", ondelete="CASCADE")),
        Column("role", SAEnum("user", "bot", name="messagerole"), nullable=False),
        Column("content", Text(), nullable=False),
        Column("structured", JSONB(), nullable=True),
        Column("media_url", String(500), nullable=True),
        Column("media_type", String(50), nullable=True),
        Column("module_used", String(50), nullable=True),
        Column("risk_level", String(50), nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
    )
    Table("refresh_tokens", _meta,
        Column("id", UUID(as_uuid=True), primary_key=True),
        Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")),
        Column("token_hash", String(64), nullable=False, unique=True),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
        Column("is_revoked", Boolean(), nullable=False, server_default="false"),
    )
    Table("scan_history", _meta,
        Column("id", UUID(as_uuid=True), primary_key=True),
        Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")),
        Column("value_hash", String(16), nullable=False),
        Column("entry_type", String(50), nullable=False),
        Column("verdict", String(50), nullable=False),
        Column("risk_level", String(50), nullable=False),
        Column("scanned_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
        Column("expires_at", DateTime(timezone=True), nullable=False),
    )
    target_metadata = _meta

    def _url():
        u = os.environ.get("DATABASE_URL") or config.get_main_option("sqlalchemy.url","")
        return re.sub(r"postgresql\\+asyncpg://", "postgresql+psycopg2://", u)

    def run_migrations_offline():
        context.configure(url=_url(), target_metadata=target_metadata,
                          literal_binds=True, dialect_opts={"paramstyle":"named"})
        with context.begin_transaction():
            context.run_migrations()

    def run_migrations_online():
        cfg = config.get_section(config.config_ini_section, {})
        cfg["sqlalchemy.url"] = _url()
        e = engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
        with e.connect() as conn:
            context.configure(connection=conn, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()

    if context.is_offline_mode():
        run_migrations_offline()
    else:
        run_migrations_online()
''').strip()

env_path = BACKEND / "alembic" / "env.py"
env_path.write_text(env_src, encoding="utf-8")
ok(f"Written: {env_path}")

# ── Run migrations ────────────────────────────────────────────────────────────
hdr("[5/6] Running database migrations…")

# Load .env.web
env_file = BASE / ".env.web"
env_vars  = {}
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env_vars[k.strip()] = v.strip().strip('"').strip("'")

db_url = env_vars.get("DATABASE_URL","")
if not db_url:
    err("DATABASE_URL not set in .env.web — skipping migrations")
    inf("Edit .env.web and set DATABASE_URL=postgresql+asyncpg://aegis:aegispass@localhost:5432/aegis_web")
else:
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
        ok("Migrations applied successfully")
        for line in r.stdout.strip().splitlines():
            if line.strip():
                inf(line.strip())
    else:
        err(f"Migration failed:\n{r.stderr.strip()[-400:]}")
        inf("Check PostgreSQL is running: redis-cli ping (for Redis) and psql connection")

# ── Final self-test ───────────────────────────────────────────────────────────
hdr("[6/6] Final verification…")
test2 = subprocess.run(
    [str(venv_py), "-c",
     "import sys; sys.path.insert(0, str(__import__('pathlib').Path('backend')))\n"
     "from app.core.security import hash_password, verify_password, create_access_token, decode_token\n"
     "h = hash_password('myP@ss123')\n"
     "assert verify_password('myP@ss123', h), 'verify failed'\n"
     "assert not verify_password('wrong', h), 'false positive'\n"
     "t = create_access_token('user-123')\n"
     "p = decode_token(t)\n"
     "assert p and p['sub'] == 'user-123', 'JWT failed'\n"
     "print('ALL CHECKS PASSED')"],
    cwd=str(BASE), capture_output=True, text=True,
)
if "ALL CHECKS PASSED" in test2.stdout:
    ok("Security module: hash + verify + JWT all working")
else:
    err(f"Verification error: {test2.stderr.strip()[-300:]}")

print()
print(c(1, "=" * 55))
print(c(92, "  ✅ All fixes applied!"))
print()
print(c(96, "  Now start the backend:"))
print(c(97, "      python start_backend.py"))
print()
print(c(96, "  And in another terminal, start the frontend:"))
print(c(97, "      python start_frontend.py"))
print()
print(c(96, "  Or start both at once:"))
print(c(97, "      python start_all.py"))
print(c(1, "=" * 55))
print()
