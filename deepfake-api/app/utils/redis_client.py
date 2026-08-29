"""
Redis client — Phase 2+3.
Graceful degradation: if Redis unavailable, API continues without caching.
Connection is attempted lazily and retried with backoff.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_redis_client = None
_last_attempt: float = 0.0
_RETRY_COOLDOWN = 30.0  # only retry Redis connection every 30 seconds


def get_redis():
    """Return Redis client or None. Retries at most once per 30 seconds."""
    global _redis_client, _last_attempt
    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_client = None

    now = time.time()
    if now - _last_attempt < _RETRY_COOLDOWN:
        return None
    _last_attempt = now

    try:
        import redis
        client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        _redis_client = client
        logger.info(f"Redis connected: {settings.REDIS_URL}")
        return _redis_client
    except Exception as e:
        logger.debug(f"Redis unavailable ({e}) — caching disabled")
        return None


# ── In-memory fallback ────────────────────────────────────────────────────────
_memory_jobs: dict = {}


# ── Image scan caching ────────────────────────────────────────────────────────

def _image_key(image_bytes: bytes) -> str:
    return f"aegis:scan:{hashlib.sha256(image_bytes).hexdigest()}"


def get_cached_image_result(image_bytes: bytes) -> Optional[dict]:
    r = get_redis()
    if r is None:
        return None
    try:
        val = r.get(_image_key(image_bytes))
        return json.loads(val) if val else None
    except Exception:
        return None


def set_cached_image_result(image_bytes: bytes, result: dict) -> None:
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(_image_key(image_bytes), settings.CACHE_TTL_SECONDS, json.dumps(result))
    except Exception as e:
        logger.debug(f"Redis cache set failed: {e}")


# ── Async job management ──────────────────────────────────────────────────────

def create_job(job_id: str) -> dict:
    job = {
        "job_id": job_id, "status": "queued",
        "progress_message": "Job queued",
        "created_at": time.time(), "started_at": None,
        "completed_at": None, "result": None, "error": None,
    }
    _save_job(job_id, job)
    return job


def update_job_status(job_id: str, status: str, message: str,
                       result: dict = None, error: str = None) -> None:
    job = get_job(job_id)
    if job is None:
        return
    job["status"] = status
    job["progress_message"] = message
    if status not in ("queued",) and job["started_at"] is None:
        job["started_at"] = time.time()
    if status in ("complete", "failed"):
        job["completed_at"] = time.time()
    if result is not None:
        job["result"] = result
    if error is not None:
        job["error"] = error
    _save_job(job_id, job)


def get_job(job_id: str) -> Optional[dict]:
    r = get_redis()
    if r is not None:
        try:
            val = r.get(f"aegis:job:{job_id}")
            if val:
                return json.loads(val)
        except Exception:
            pass
    return _memory_jobs.get(job_id)


def _save_job(job_id: str, job: dict) -> None:
    r = get_redis()
    if r is not None:
        try:
            r.setex(f"aegis:job:{job_id}", settings.JOB_TTL_SECONDS, json.dumps(job))
            return
        except Exception:
            pass
    _memory_jobs[job_id] = job
    if len(_memory_jobs) > 500:
        for k in list(_memory_jobs.keys())[:100]:
            del _memory_jobs[k]


# ── Cache stats + purge ───────────────────────────────────────────────────────

def get_cache_stats() -> dict:
    r = get_redis()
    if r is None:
        return {
            "redis_available": False,
            "message": "Redis not connected — running without caching",
            "redis_url": settings.REDIS_URL,
        }
    try:
        info = r.info("memory")
        scan_keys = len(r.keys("aegis:scan:*"))
        job_keys  = len(r.keys("aegis:job:*"))
        return {
            "redis_available": True,
            "redis_url": settings.REDIS_URL,
            "used_memory_human": info.get("used_memory_human"),
            "cached_scan_results": scan_keys,
            "active_jobs": job_keys,
        }
    except Exception as e:
        return {"redis_available": False, "error": str(e)}


def purge_cache() -> dict:
    r = get_redis()
    count = 0
    if r is not None:
        try:
            keys = r.keys("aegis:scan:*") + r.keys("aegis:job:*")
            if keys:
                r.delete(*keys)
            count = len(keys)
        except Exception:
            pass
    mem_count = len(_memory_jobs)
    _memory_jobs.clear()
    return {"purged": count + mem_count, "redis_purged": count, "memory_purged": mem_count}
