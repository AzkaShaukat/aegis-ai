"""backend/app/services/session.py — Redis session for orchestrator state."""

import json
import time
from typing import Optional
import redis.asyncio as aioredis
from app.core.config import get_settings

settings = get_settings()
_redis: Optional[aioredis.Redis] = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis

def _key(session_id: str) -> str:
    return f"aegis:web:session:{session_id}"

async def get_session(session_id: str) -> dict:
    r = await get_redis()
    raw = await r.get(_key(session_id))
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}

async def save_session(session_id: str, data: dict) -> None:
    r = await get_redis()
    data["last_active"] = time.time()
    await r.set(_key(session_id), json.dumps(data, default=str), ex=settings.session_ttl_seconds)

async def update_session(session_id: str, **kwargs) -> dict:
    session = await get_session(session_id)
    if not session:
        session = {"state": "IDLE", "last_scan": None, "last_module": None, "scan_log": []}
    session.update(kwargs)
    await save_session(session_id, session)
    return session

async def get_or_create_session(session_id: str) -> dict:
    session = await get_session(session_id)
    if not session:
        session = {"state": "IDLE", "last_scan": None, "last_module": None, "scan_log": []}
        await save_session(session_id, session)
    return session

async def store_last_scan(session_id: str, module: str, result: dict, risk: str, flags: list,
                          original_input: str = "", item_scanned: str = "") -> None:
    session = await get_or_create_session(session_id)
    scan_data = {
        "module": module,
        "result": result,
        "risk_level": risk,
        "flags": flags,
        "timestamp": time.time(),
        "original_input": original_input,
        "item_scanned": item_scanned,
    }
    session["last_scan"] = scan_data
    session["last_module"] = module
    scan_log = session.get("scan_log", [])
    scan_log.append({
        "module": module,
        "item": item_scanned or original_input,
        "risk": risk,
        "timestamp": time.time(),
    })
    if len(scan_log) > 50:
        scan_log = scan_log[-50:]
    session["scan_log"] = scan_log
    await save_session(session_id, session)

async def clear_session(session_id: str) -> None:
    r = await get_redis()
    await r.delete(_key(session_id))