"""app/session.py — Redis-backed session management.

Enhanced session stores:
  - last_scan: full result + original user input + URL/item scanned
  - conversation_history: clean one-liner per interaction (for /history)
  - state machine for multi-turn flows
"""
from __future__ import annotations

import json
import time
from enum import Enum
from typing import Any, Optional
import redis.asyncio as aioredis

from app.config import get_settings

settings = get_settings()


class ConvState(str, Enum):
    IDLE                     = "IDLE"
    AWAITING_DISAMBIGUATION  = "AWAITING_DISAMBIGUATION"
    AWAITING_CREDENTIAL      = "AWAITING_CREDENTIAL"
    AWAITING_PROFILE_DATA    = "AWAITING_PROFILE_DATA"
    AWAITING_PROFILE_CONFIRM = "AWAITING_PROFILE_CONFIRM"
    AWAITING_FOLLOWUP        = "AWAITING_FOLLOWUP"
    AWAITING_LINK_OFFER      = "AWAITING_LINK_OFFER"
    AWAITING_DEEPFAKE_CONFIRM = "AWAITING_DEEPFAKE_CONFIRM"   # new
    
_redis: Optional[aioredis.Redis] = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


def _session_key(phone: str) -> str:
    return f"aegis:session:{phone}"


async def get_session(phone: str) -> dict:
    r = await get_redis()
    raw = await r.get(_session_key(phone))
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


async def save_session(phone: str, data: dict) -> None:
    r = await get_redis()
    data["last_active"] = time.time()
    await r.set(_session_key(phone), json.dumps(data, default=str), ex=settings.session_ttl_seconds)


async def delete_session(phone: str) -> None:
    r = await get_redis()
    await r.delete(_session_key(phone))


async def update_session(phone: str, **kwargs) -> dict:
    session = await get_session(phone)
    if not session:
        session = _new_session(phone)
    session.update(kwargs)
    await save_session(phone, session)
    return session


def _new_session(phone: str) -> dict:
    return {
        "session_id": f"aegis:session:{phone}",
        "state": ConvState.IDLE,
        "last_scan": None,
        "last_module": None,
        "conversation_history": [],
        "scan_log": [],          # clean one-liner log for /history
        "partial_profile": {},
        "pending_entities": [],
        "disambiguation_options": {},
        "rate_limit_counts": {},
        "created_at": time.time(),
        "last_active": time.time(),
    }


async def get_or_create_session(phone: str) -> dict:
    session = await get_session(phone)
    if not session:
        session = _new_session(phone)
        await save_session(phone, session)
    return session


async def append_history(phone: str, role: str, content: str, module: str = "") -> None:
    """Add message to raw conversation history (last 20 turns)."""
    session = await get_or_create_session(phone)
    history = session.get("conversation_history", [])
    history.append({
        "role": role,
        "content": content[:500],
        "timestamp": time.time(),
        "module": module,
    })
    if len(history) > 20:
        history = history[-20:]
    session["conversation_history"] = history
    await save_session(phone, session)


async def store_last_scan(
    phone: str,
    module: str,
    result: Any,
    risk_level: str,
    flags: list,
    original_input: str = "",     # The raw text user sent
    item_scanned: str = "",        # URL / email / username / etc.
) -> None:
    """Store last scan with original input so rescan and follow-ups work."""
    session = await get_or_create_session(phone)

    scan_data = {
        "module": module,
        "result": result,
        "risk_level": risk_level,
        "flags": flags,
        "timestamp": time.time(),
        "original_input": original_input,
        "item_scanned": item_scanned,
    }

    # Add to clean scan log for /history
    scan_log = session.get("scan_log", [])
    verdict_emoji = {"safe": "✅", "low": "🟡", "medium": "⚠️", "high": "🚨", "critical": "🆘"}.get(
        (risk_level or "").lower().split()[0], "🔍"
    )
    item_display = item_scanned or original_input
    log_entry = {
        "module": module,
        "item": item_display[:60],
        "risk": risk_level,
        "verdict_emoji": verdict_emoji,
        "timestamp": time.time(),
    }
    scan_log.append(log_entry)
    if len(scan_log) > 50:  # keep last 50 scans
        scan_log = scan_log[-50:]

    session["last_scan"] = scan_data
    session["last_module"] = module
    session["scan_log"] = scan_log
    await save_session(phone, session)


async def check_rate_limit(phone: str, action: str, limit: int = 5, window_seconds: int = 60) -> bool:
    r = await get_redis()
    key = f"aegis:rl:{phone}:{action}"
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, window_seconds)
    return count <= limit
