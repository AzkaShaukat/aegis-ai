"""
metrics.py
Aegis Link Analyzer

In-memory scan metrics collector.
Tracks scan counts, risk distributions, timing, and cache performance.

Metrics are stored in Redis (shared across uvicorn workers) with a
simple in-memory fallback if Redis is unavailable.

Exposed at GET /metrics in both JSON and Prometheus text format.
"""

import asyncio
import json
import time
from datetime import datetime, date
from typing import Dict, Optional
import redis.asyncio as redis

REDIS_URL = "redis://redis:6379"
METRICS_KEY = "aegis:metrics"
METRICS_TTL = 60 * 60 * 24 * 30  # 30 days

# In-memory fallback (used if Redis is unavailable)
_local_metrics: Dict = {}


# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT STRUCTURE
# ─────────────────────────────────────────────────────────────────────────────

def _default_metrics() -> Dict:
    return {
        "total_scans": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "risk_distribution": {
            "High Risk": 0,
            "Medium Risk": 0,
            "Low Risk": 0,
            "Safe": 0,
        },
        "scan_times_ms": [],          # Last 100 scan durations
        "avg_scan_time_ms": 0.0,
        "phase2_hits": {
            "urlhaus": 0,
            "openphish": 0,
            "gsb": 0,
        },
        "ml_predictions": {
            "total": 0,
            "high_risk": 0,
            "safe": 0,
        },
        "daily_counts": {},           # {"2026-02-27": 42}
        "errors": 0,
        "service_start": datetime.utcnow().isoformat(),
        "last_updated": datetime.utcnow().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# REDIS HELPERS
# ─────────────────────────────────────────────────────────────────────────────

async def _load_metrics() -> Dict:
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        data = await r.get(METRICS_KEY)
        if data:
            return json.loads(data)
    except Exception:
        pass
    return _local_metrics if _local_metrics else _default_metrics()


async def _save_metrics(m: Dict):
    m["last_updated"] = datetime.utcnow().isoformat()
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        await r.set(METRICS_KEY, json.dumps(m), ex=METRICS_TTL)
    except Exception:
        global _local_metrics
        _local_metrics = m


# ─────────────────────────────────────────────────────────────────────────────
# RECORD FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

async def record_scan(
    risk_level: str,
    scan_time_ms: float,
    cache_hit: bool,
    urlhaus_hit: bool = False,
    openphish_hit: bool = False,
    gsb_hit: bool = False,
    ml_risk_level: Optional[str] = None,
    error: bool = False,
):
    """
    Records metrics for a completed scan.
    Call this at the end of every scan_url() execution.
    """
    m = await _load_metrics()

    m["total_scans"] = m.get("total_scans", 0) + 1

    if cache_hit:
        m["cache_hits"] = m.get("cache_hits", 0) + 1
    else:
        m["cache_misses"] = m.get("cache_misses", 0) + 1

    if error:
        m["errors"] = m.get("errors", 0) + 1

    # Risk distribution
    dist = m.setdefault("risk_distribution", {"High Risk": 0, "Medium Risk": 0, "Low Risk": 0, "Safe": 0})
    if risk_level in dist:
        dist[risk_level] += 1

    # Scan timing — keep last 100 only
    times = m.setdefault("scan_times_ms", [])
    times.append(round(scan_time_ms, 1))
    if len(times) > 100:
        times.pop(0)
    m["avg_scan_time_ms"] = round(sum(times) / len(times), 1) if times else 0.0

    # Phase 2 hit counters
    hits = m.setdefault("phase2_hits", {"urlhaus": 0, "openphish": 0, "gsb": 0})
    if urlhaus_hit:
        hits["urlhaus"] = hits.get("urlhaus", 0) + 1
    if openphish_hit:
        hits["openphish"] = hits.get("openphish", 0) + 1
    if gsb_hit:
        hits["gsb"] = hits.get("gsb", 0) + 1

    # ML predictions
    if ml_risk_level:
        ml = m.setdefault("ml_predictions", {"total": 0, "high_risk": 0, "safe": 0})
        ml["total"] = ml.get("total", 0) + 1
        if ml_risk_level in ("High Risk", "Medium Risk"):
            ml["high_risk"] = ml.get("high_risk", 0) + 1
        else:
            ml["safe"] = ml.get("safe", 0) + 1

    # Daily counts
    today = date.today().isoformat()
    daily = m.setdefault("daily_counts", {})
    daily[today] = daily.get(today, 0) + 1

    # Keep only last 30 days
    if len(daily) > 30:
        oldest = sorted(daily.keys())[0]
        del daily[oldest]

    await _save_metrics(m)


async def get_metrics() -> Dict:
    """Returns the current metrics snapshot with computed summary stats."""
    m = await _load_metrics()

    total = m.get("total_scans", 0)
    hits = m.get("cache_hits", 0)

    # Compute cache hit rate
    cache_hit_rate = round((hits / total * 100), 1) if total > 0 else 0.0

    # Compute risk percentage distribution
    dist = m.get("risk_distribution", {})
    dist_pct = {}
    for level, count in dist.items():
        dist_pct[level] = {
            "count": count,
            "percentage": round(count / total * 100, 1) if total > 0 else 0.0,
        }

    # Last 7 days trend
    daily = m.get("daily_counts", {})
    last_7 = {k: daily[k] for k in sorted(daily.keys())[-7:]}

    return {
        "summary": {
            "total_scans": total,
            "cache_hit_rate_pct": cache_hit_rate,
            "cache_hits": hits,
            "cache_misses": m.get("cache_misses", 0),
            "avg_scan_time_ms": m.get("avg_scan_time_ms", 0.0),
            "errors": m.get("errors", 0),
        },
        "risk_distribution": dist_pct,
        "threat_feed_hits": m.get("phase2_hits", {}),
        "ml_predictions": m.get("ml_predictions", {}),
        "daily_scans_last_7_days": last_7,
        "service_start": m.get("service_start"),
        "last_updated": m.get("last_updated"),
    }


async def get_prometheus_metrics() -> str:
    """
    Returns metrics in Prometheus text exposition format.
    Compatible with Prometheus scraping and Grafana dashboards.
    """
    m = await _load_metrics()
    total = m.get("total_scans", 0)
    dist = m.get("risk_distribution", {})
    phase2 = m.get("phase2_hits", {})

    lines = [
        "# HELP aegis_total_scans Total number of URLs scanned",
        "# TYPE aegis_total_scans counter",
        f'aegis_total_scans {total}',
        "",
        "# HELP aegis_cache_hits Total cache hits",
        "# TYPE aegis_cache_hits counter",
        f'aegis_cache_hits {m.get("cache_hits", 0)}',
        "",
        "# HELP aegis_avg_scan_duration_ms Average scan duration in milliseconds",
        "# TYPE aegis_avg_scan_duration_ms gauge",
        f'aegis_avg_scan_duration_ms {m.get("avg_scan_time_ms", 0.0)}',
        "",
        "# HELP aegis_risk_level_total Scans by risk level",
        "# TYPE aegis_risk_level_total counter",
    ]

    for level, count in dist.items():
        label = level.lower().replace(" ", "_")
        lines.append(f'aegis_risk_level_total{{level="{label}"}} {count}')

    lines += [
        "",
        "# HELP aegis_threat_feed_hits Hits in external threat feeds",
        "# TYPE aegis_threat_feed_hits counter",
        f'aegis_threat_feed_hits{{feed="urlhaus"}} {phase2.get("urlhaus", 0)}',
        f'aegis_threat_feed_hits{{feed="openphish"}} {phase2.get("openphish", 0)}',
        f'aegis_threat_feed_hits{{feed="gsb"}} {phase2.get("gsb", 0)}',
        "",
    ]

    return "\n".join(lines)
