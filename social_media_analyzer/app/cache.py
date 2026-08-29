import json, hashlib, logging
from typing import Optional
import redis.asyncio as aioredis
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()
TTL      = 86400

def _key(value: str, kind: str) -> str:
    h = hashlib.sha256(f"{kind}:{value.lower()}".encode()).hexdigest()[:16]
    return f"aegis:v4:{h}"

class Cache:
    def __init__(self):
        self._r = None

    async def _conn(self):
        if self._r is None:
            try:
                self._r = aioredis.from_url(settings.redis_url, decode_responses=True,
                                             socket_connect_timeout=3)
                await self._r.ping()
            except Exception as e:
                logger.warning(f"[Cache] Redis unavailable: {e}"); self._r = None
        return self._r

    async def get(self, value: str, kind: str) -> Optional[dict]:
        r = await self._conn()
        if not r: return None
        try:
            raw = await r.get(_key(value, kind))
            if raw:
                logger.info(f"[Cache] HIT {kind}:{value[:30]}")
                return json.loads(raw)
        except Exception: pass
        return None

    async def set(self, value: str, kind: str, result) -> None:
        r = await self._conn()
        if not r: return
        try:
            data = (result.model_dump_json() if hasattr(result, "model_dump_json")
                    else json.dumps(result))
            await r.setex(_key(value, kind), TTL, data)
        except Exception: pass

    async def delete(self, value: str, kind: str) -> None:
        r = await self._conn()
        if not r: return
        try: await r.delete(_key(value, kind))
        except Exception: pass

    async def ping(self) -> bool:
        r = await self._conn()
        if not r: return False
        try: return bool(await r.ping())
        except Exception: return False

cache = Cache()
