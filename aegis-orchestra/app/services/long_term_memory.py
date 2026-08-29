"""app/services/long_term_memory.py — 30-day cross-session memory.

Stores anonymized scan history across sessions.
Privacy: only SHA-256 hashes stored, never raw credentials.
TTL: 30 days per user entry.

Storage: Redis with 30-day TTL keys per phone number.
"""
from __future__ import annotations
import hashlib
import json
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_MEMORY_TTL = 30 * 24 * 3600  # 30 days


def _hash(value: str) -> str:
    return hashlib.sha256(value.lower().encode()).hexdigest()[:16]


async def store_long_term(phone: str, entry_type: str, value: str, verdict: str, risk: str) -> None:
    """Store a scan permanently (30 days) in user's long-term memory."""
    try:
        from app.session import get_redis
        r = await get_redis()
        key = f"aegis:ltm:{phone}"
        raw = await r.get(key)
        memory = json.loads(raw) if raw else {"scans": [], "stats": {}}

        memory["scans"].append({
            "hash":      _hash(value),
            "type":      entry_type,
            "verdict":   verdict,
            "risk":      risk,
            "timestamp": time.time(),
        })
        # Keep last 200 scans
        memory["scans"] = memory["scans"][-200:]

        # Update stats
        stats = memory.setdefault("stats", {})
        stats["total"] = stats.get("total", 0) + 1
        stats[f"{entry_type}_count"] = stats.get(f"{entry_type}_count", 0) + 1
        if "high" in risk.lower() or "critical" in risk.lower():
            stats["threats_found"] = stats.get("threats_found", 0) + 1

        await r.set(key, json.dumps(memory), ex=_MEMORY_TTL)
    except Exception as e:
        logger.warning("Long-term memory store error: %s", e)


async def get_long_term_summary(phone: str, entry_type: str = "") -> dict:
    """Get user's scan history summary (30 days)."""
    try:
        from app.session import get_redis
        r = await get_redis()
        key = f"aegis:ltm:{phone}"
        raw = await r.get(key)
        if not raw:
            return {"scans": [], "stats": {}, "total": 0}
        memory = json.loads(raw)
        if entry_type:
            filtered = [s for s in memory["scans"] if s["type"] == entry_type]
            return {"scans": filtered, "stats": memory.get("stats", {}), "total": len(filtered)}
        return memory
    except Exception as e:
        logger.warning("Long-term memory read error: %s", e)
        return {"scans": [], "stats": {}, "total": 0}


async def check_previously_seen(phone: str, value: str) -> Optional[dict]:
    """Check if this value was analysed before (by hash comparison)."""
    try:
        from app.session import get_redis
        r = await get_redis()
        key = f"aegis:ltm:{phone}"
        raw = await r.get(key)
        if not raw:
            return None
        memory = json.loads(raw)
        h = _hash(value)
        for scan in reversed(memory.get("scans", [])):
            if scan.get("hash") == h:
                return scan
    except Exception as e:
        logger.warning("Long-term memory check error: %s", e)
    return None


def format_30day_history(memory: dict) -> str:
    """Format 30-day history for /history command."""
    scans = memory.get("scans", [])
    stats = memory.get("stats", {})
    if not scans:
        return "📋 *Your 30-Day History*\n\nNo scans recorded yet."

    lines = ["📋 *Your 30-Day Security Summary*\n"]
    total = stats.get("total", len(scans))
    threats = stats.get("threats_found", 0)
    lines.append(f"📊 Total scans: *{total}* | 🚨 Threats found: *{threats}*\n")

    # Group by type
    by_type: dict = {}
    for s in scans[-20:]:
        t = s.get("type", "unknown")
        by_type.setdefault(t, []).append(s)

    type_icons = {"link": "🔗", "qr": "📷", "credential": "🔑", "profile": "👤"}
    for t, items in by_type.items():
        icon = type_icons.get(t, "🔍")
        high_count = sum(1 for i in items if "high" in (i.get("risk","")).lower())
        lines.append(f"{icon} *{t.title()}*: {len(items)} scanned, {high_count} high risk")

    lines.append(f"\n_Showing last {min(20, len(scans))} of {total} scans (30-day window)_")
    return "\n".join(lines)
