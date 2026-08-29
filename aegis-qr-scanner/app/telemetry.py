import redis.asyncio as redis
import os
from app.logger import log

# Connect to the QR-specific Redis (Port 6380)
REDIS_URL = os.getenv("REDIS_URL", "redis://host.docker.internal:6380")

async def track_scan_event(scan_type: str, risk_level: str = "Info"):
    """
    Increments counters in Redis for live dashboards.
    """
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        
        # 1. Total Scans (Global Counter)
        await r.incr("stats:total_scans")
        
        # 2. Scans by Type (e.g., stats:type:wifi, stats:type:url)
        await r.incr(f"stats:type:{scan_type}")
        
        # 3. Threats Blocked (If risk is High/Critical)
        if risk_level in ["High", "Critical"]:
            await r.incr("stats:threats_blocked")
            log.warning(f"🚨 Threat Blocked! Type: {scan_type}")
            
    except Exception as e:
        # Telemetry should never crash the app, so we just log the error
        log.warning(f"Telemetry failed: {e}")

async def get_live_stats():
    """
    Fetches all counters for the dashboard.
    """
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        keys = await r.keys("stats:*")
        
        dashboard = {}
        for key in keys:
            value = await r.get(key)
            clean_name = key.replace("stats:", "")
            dashboard[clean_name] = int(value)
            
        return dashboard
    except Exception:
        return {"error": "Dashboard Unavailable"}