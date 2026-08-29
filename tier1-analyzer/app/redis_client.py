"""Redis client — falls back silently if Redis is unavailable."""
import logging
import redis.asyncio as aioredis
from app.config import settings

logger = logging.getLogger(__name__)
_redis = None


async def get_redis():
    global _redis
    if _redis is None:
        try:
            _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True,
                                       socket_connect_timeout=2, socket_timeout=2)
            await _redis.ping()
        except Exception as e:
            logger.warning(f"Redis unavailable: {e} — running without cache")
            _redis = None
    return _redis


async def cache_get(key: str):
    r = await get_redis()
    if not r:
        return None
    try:
        return await r.get(key)
    except Exception:
        return None


async def cache_set(key: str, value: str, ttl: int = 3600):
    r = await get_redis()
    if not r:
        return
    try:
        await r.setex(key, ttl, value)
    except Exception:
        pass


async def redis_status() -> str:
    r = await get_redis()
    if r is None:
        return "unavailable"
    try:
        await r.ping()
        return "healthy"
    except Exception:
        return "unavailable"
