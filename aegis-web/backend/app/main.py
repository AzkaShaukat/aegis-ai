"""app/main.py — Aegis AI Web Backend (Port 8007)."""
from __future__ import annotations
import logging, os, pathlib, subprocess, sys

# ── Load .env.web FIRST before any settings import ───────────────────────────
try:
    from dotenv import load_dotenv
    for _p in [
        pathlib.Path(__file__).parent.parent.parent / ".env.web",   # aegis-web/.env.web
        pathlib.Path(__file__).parent.parent / ".env.web",          # backend/.env.web
    ]:
        if _p.exists():
            load_dotenv(str(_p), override=True)
            break
except ImportError:
    pass

from app.core.config import get_settings
get_settings.cache_clear()
settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


def _run_migrations() -> None:
    """Run alembic upgrade head in subprocess (avoids event-loop conflict)."""
    import re
    backend_dir = pathlib.Path(__file__).parent.parent
    alembic_ini = backend_dir / "alembic.ini"
    if not alembic_ini.exists():
        logger.warning("alembic.ini not found — skipping migrations")
        return

    # Convert asyncpg URL → psycopg2 for sync alembic
    sync_url = re.sub(r"postgresql\+asyncpg://", "postgresql+psycopg2://", settings.database_url)

    env = os.environ.copy()
    env["DATABASE_URL"] = sync_url

    r = subprocess.run(
        [sys.executable, "-m", "alembic", "--config", str(alembic_ini), "upgrade", "head"],
        cwd=str(backend_dir),
        capture_output=True, text=True, env=env, timeout=60,
    )
    if r.returncode == 0:
        out = r.stdout.strip()
        if out:
            for line in out.splitlines():
                logger.info("  alembic: %s", line)
        logger.info("✅ Migrations applied (alembic upgrade head)")
    else:
        logger.error("❌ alembic failed:\n%s", r.stderr.strip()[-800:])
        logger.warning("⚠️  Falling back to create_all …")
        # Fallback: ensure tables exist via SQLAlchemy create_all
        import asyncio
        asyncio.get_event_loop().run_until_complete(_create_all_sync())


async def _create_all_sync():
    from app.core.database import init_db
    await init_db()
    logger.info("✅ Tables ensured via create_all (alembic fallback)")


from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡️  Aegis Web starting on port %d", settings.web_port)
    os.makedirs(settings.upload_dir, exist_ok=True)

    # Run migrations BEFORE accepting requests
    try:
        _run_migrations()
    except Exception as e:
        logger.error("Migration error: %s — using create_all fallback", e)
        from app.core.database import init_db
        await init_db()

    # Redis
    try:
        import redis.asyncio as aioredis
        r = await aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        logger.info("✅ Redis connected")
    except Exception as e:
        logger.warning("⚠️  Redis unavailable: %s", e)

    # Ollama
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as c:
            resp = await c.get(f"{settings.ollama_host}/api/tags")
            if resp.status_code == 200:
                logger.info("✅ Ollama available (%s)", settings.ollama_model)
    except Exception:
        logger.warning("⚠️  Ollama not reachable — AI explanations disabled")

    # Analysis modules (warnings only — app still works without them)
    try:
        from app.router.health_check import check_all_modules
        results = await check_all_modules()
        up = sum(v for v in results.values())
        logger.info("📡 Analysis modules: %d/%d reachable", up, len(results))
    except ImportError:
        logger.warning("⚠️  health_check.py not copied yet — skipping module check")

    # Email
    if settings.email_enabled and settings.smtp_user:
        logger.info("✅ Email enabled via %s", settings.smtp_host)
    else:
        logger.info("ℹ️  Email disabled — users auto-verified on register")

    logger.info("📖 Docs: http://localhost:%d/docs", settings.web_port)
    logger.info("🚀 Ready!")
    yield
    logger.info("Shutdown complete.")


app = FastAPI(title="Aegis AI", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

from app.api.auth   import router as auth_router

from app.api.health import router as health_router
from app.api.upload import router as upload_router
from app.api.chat import router as chat_router  # WS + REST
from app.api.ws_handler  import router as ws_router
from app.api.chat_extra   import router as chat_extra_router

app.include_router(ws_router)  # /ws/chat WebSocket
app.include_router(chat_extra_router)
app.include_router(auth_router)
app.include_router(health_router)
app.include_router(upload_router)
app.include_router(chat_router)  # registers /ws/chat + /api/chat/* + /api/history/*

@app.get("/")
async def root():
    return {"service": "Aegis AI", "docs": f"http://localhost:{settings.web_port}/docs"}
