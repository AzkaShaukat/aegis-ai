"""Async Redis client — Aegis AI."""
import json, hashlib, logging
from typing import Any, Optional
import redis.asyncio as aioredis
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()
_pool: Optional[aioredis.Redis] = None


def _h(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()


async def get_redis() -> aioredis.Redis:
    global _pool
    if _pool is None:
        _pool = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _pool


async def cache_get(key: str) -> Optional[Any]:
    try:
        r = await get_redis()
        raw = await r.get(_h(key))
        return json.loads(raw) if raw else None
    except Exception as e:
        logger.debug(f"[redis:get] {e}")
        return None


async def cache_set(key: str, value: Any, ttl: int = 3600) -> None:
    try:
        r = await get_redis()
        await r.setex(_h(key), ttl, json.dumps(value, default=str))
    except Exception as e:
        logger.debug(f"[redis:set] {e}")


async def redis_health() -> str:
    try:
        r = await get_redis()
        await r.ping()
        return "healthy"
    except Exception:
        return "unavailable"
