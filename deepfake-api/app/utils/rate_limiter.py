"""
Phase 3: Redis sliding window rate limiter.
Disabled automatically when RATE_LIMIT_ENABLED=false (for tests).
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import Lock

from app.config import get_settings
from app.utils.redis_client import get_redis

logger = logging.getLogger(__name__)
settings = get_settings()

_memory_counts: dict = defaultdict(list)
_lock = Lock()

RATE_LIMITS = {
    "/analyze/image":         30,
    "/analyze/image-url":     20,
    "/analyze/video":         5,
    "/analyze/video-async":   10,
    "/analyze/batch":         10,
    "/analyze/image/explain": 10,
    "/analyze/video/timeline":5,
    "default":                60,
}


def check_rate_limit(client_ip: str, endpoint: str) -> tuple:
    """
    Returns (allowed: bool, remaining: int, reset_in: int).
    Returns (True, 999, 60) when rate limiting is disabled.
    """
    if not settings.RATE_LIMIT_ENABLED:
        return True, 999, 60

    limit = RATE_LIMITS.get(endpoint, RATE_LIMITS["default"])
    window = 60
    key = f"aegis:rate:{client_ip}:{endpoint}"
    now = time.time()

    r = get_redis()
    if r is not None:
        try:
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, window)
            results = pipe.execute()
            count = results[2]
            return count <= limit, max(0, limit - count), window
        except Exception as e:
            logger.warning(f"Rate limit Redis error: {e}")

    with _lock:
        timestamps = _memory_counts[key]
        cutoff = now - window
        timestamps[:] = [t for t in timestamps if t > cutoff]
        timestamps.append(now)
        count = len(timestamps)
        if len(_memory_counts) > 10000:
            old = sorted(_memory_counts.keys())[:2000]
            for k in old:
                del _memory_counts[k]

    return count <= limit, max(0, limit - count), window
