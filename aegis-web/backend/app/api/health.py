"""app/api/health.py — Health and module connectivity check."""
from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health")
async def health():
    """Overall service health check."""
    redis_ok  = False
    db_ok     = False
    ollama_ok = False

    # Redis
    try:
        import redis.asyncio as aioredis
        r = await aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        redis_ok = True
    except Exception:
        pass

    # PostgreSQL
    try:
        from app.core.database import engine
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    # Ollama
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{settings.ollama_host}/api/tags")
            ollama_ok = r.status_code == 200
    except Exception:
        pass

    return {
        "status": "healthy",
        "service": "aegis-web",
        "port": settings.web_port,
        "environment": settings.environment,
        "dependencies": {
            "postgresql": "connected" if db_ok   else "disconnected",
            "redis":      "connected" if redis_ok else "disconnected",
            "ollama":     "connected" if ollama_ok else "disconnected",
        },
    }


@router.get("/health/modules")
async def module_health():
    """Check connectivity to all 4 analysis microservices."""
    from app.router.health_check import check_all_modules
    results = await check_all_modules()
    return {
        "modules": results,
        "all_healthy": all(results.values()),
        "urls": {
            "link_analyzer":       settings.link_analyzer_url,
            "qr_scanner":          settings.qr_scanner_url,
            "credential_analyzer": settings.credential_analyzer_url,
            "profile_analyzer":    settings.profile_analyzer_url,
        },
    }
