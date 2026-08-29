"""
services.py
Aegis Link Analyzer

Core scan orchestration. Runs all detection layers concurrently
and assembles the final risk-scored result.
"""

import httpx
import asyncio
import os
import json
import time
import redis.asyncio as redis
from dotenv import load_dotenv
from datetime import datetime

from app.utils import classify_risk, render_message
from app.memory import store_scan_result
from app.logger import log
from app.heuristics import run_heuristics
from app.whois_check import run_whois_check
from app.dns_check import run_dns_check
from app.ssl_check import run_ssl_check
from app.redirect_tracer import trace_redirects
from app.urlhaus_check import run_urlhaus_check
from app.openphish_check import run_openphish_check
from app.gsb_check import run_gsb_check
from app.ml_classifier import run_ml_prediction
from app.metrics import record_scan

load_dotenv()

VT_API_KEY     = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
REDIS_URL       = "redis://redis:6379"


async def scan_url(target_url: str) -> dict:
    """
    Performs a complete multi-layer threat analysis on a URL.

    Execution pipeline:
      1. Redis cache check — returns instantly on hit
      2. URL heuristics (synchronous, CPU-bound)
      3. WHOIS, DNS, SSL, redirect, URLhaus, OpenPhish, GSB — all concurrent
      4. VirusTotal + URLScan submission & polling — concurrent
      5. ML classifier prediction
      6. Unified risk classification with weighted scoring
      7. Cache storage + memory indexing
      8. Metrics recording

    Returns:
        Complete scan result dictionary matching ScanResult schema.
    """
    scan_start = time.time()
    cache_hit = False

    # ── Cache check ───────────────────────────────────────────────────────────
    r = None
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        cached = await r.get(target_url)
        if cached:
            cache_hit = True
            log.success(f"Cache hit: {target_url}")
            result = json.loads(cached)
            await record_scan(
                risk_level=result.get("risk_level", "Safe"),
                scan_time_ms=(time.time() - scan_start) * 1000,
                cache_hit=True,
            )
            return result
    except Exception as e:
        log.warning(f"Redis unavailable: {e}")

    log.info(f"Starting scan: {target_url}")

    # ── Heuristics (sync) ─────────────────────────────────────────────────────
    heuristics_result = run_heuristics(target_url)

    # ── All async checks concurrently ─────────────────────────────────────────
    (
        whois_result, dns_result, ssl_result, redirect_result,
        urlhaus_result, openphish_result, gsb_result,
    ) = await asyncio.gather(
        run_whois_check(target_url),
        run_dns_check(target_url),
        run_ssl_check(target_url),
        trace_redirects(target_url),
        run_urlhaus_check(target_url),
        run_openphish_check(target_url),
        run_gsb_check(target_url),
        return_exceptions=True,
    )

    def _safe(r, default):
        return r if not isinstance(r, Exception) else default

    whois_result     = _safe(whois_result,     {"flags": [], "whois_score": 0})
    dns_result       = _safe(dns_result,        {"flags": [], "dns_score": 0})
    ssl_result       = _safe(ssl_result,        {"flags": [], "ssl_score": 0})
    redirect_result  = _safe(redirect_result,   {"flags": [], "redirect_score": 0, "hops": [], "hop_count": 0})
    urlhaus_result   = _safe(urlhaus_result,    {"flags": [], "urlhaus_score": 0, "found": False})
    openphish_result = _safe(openphish_result,  {"flags": [], "phishtank_score": 0, "found": False})
    gsb_result       = _safe(gsb_result,        {"flags": [], "gsb_score": 0, "found": False})

    # ── External APIs (VT + URLScan) ──────────────────────────────────────────
    vt_stats = {}
    us_data  = {}
    vt_id    = "unavailable"
    vt_link  = None

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            vt_h = {"x-apikey": VT_API_KEY}
            us_h = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}

            vt_sub, us_sub = await asyncio.gather(
                client.post("https://www.virustotal.com/api/v3/urls",
                            headers=vt_h, data={"url": target_url}),
                client.post("https://urlscan.io/api/v1/scan/",
                            headers=us_h, json={
                                "url": target_url,
                                "visibility": "public",
                                "country": "us",           # Force English-locale screenshots
                            }),
                return_exceptions=True,
            )

            if not isinstance(vt_sub, Exception) and vt_sub.status_code == 200:
                vt_id = vt_sub.json()["data"]["id"]

            us_uuid = None
            if not isinstance(us_sub, Exception) and us_sub.status_code == 200:
                us_uuid = us_sub.json()["uuid"]

            async def _poll_vt():
                if vt_id == "unavailable":
                    return {}
                for _ in range(12):
                    await asyncio.sleep(5)
                    try:
                        r = await client.get(
                            f"https://www.virustotal.com/api/v3/analyses/{vt_id}",
                            headers=vt_h
                        )
                        d = r.json()
                        if d["data"]["attributes"]["status"] == "completed":
                            return d["data"]["attributes"]["stats"]
                    except Exception:
                        pass
                return {}

            async def _poll_urlscan():
                if not us_uuid:
                    return {}
                for _ in range(15):
                    await asyncio.sleep(5)
                    try:
                        r = await client.get(f"https://urlscan.io/api/v1/result/{us_uuid}/")
                        if r.status_code == 200:
                            return r.json()
                    except Exception:
                        pass
                return {}

            vt_stats, us_data = await asyncio.gather(_poll_vt(), _poll_urlscan())

    except Exception as e:
        log.error(f"External API error: {e}")

    # ── Risk classification ───────────────────────────────────────────────────
    # ── ML prediction (runs before classify_risk so its output feeds the score) ──
    # Build a lightweight feature dict from already-computed results so the ML
    # classifier can run without needing the full assembled payload.
    _pre_ml_payload = {
        "url":        target_url,
        "heuristics": heuristics_result,
        "whois":      whois_result,
        "dns":        dns_result,
        "ssl":        ssl_result,
        "redirects":  redirect_result,
        "urlhaus":    urlhaus_result,
        "phishtank":  openphish_result,
        "gsb":        gsb_result,
    }
    _ml_early = await run_ml_prediction(_pre_ml_payload)
    _ml_prob  = float(_ml_early.get("phishing_probability", 0.0)) if _ml_early.get("available") else 0.0

    risk_level, confidence, breakdown = classify_risk(
        vt_stats=vt_stats,
        heuristic_score=float(heuristics_result.get("heuristic_score", 0)),
        whois_score=float(whois_result.get("whois_score", 0)),
        dns_score=float(dns_result.get("dns_score", 0)),
        ssl_score=float(ssl_result.get("ssl_score", 0)),
        redirect_score=float(redirect_result.get("redirect_score", 0)),
        urlhaus_score=float(urlhaus_result.get("urlhaus_score", 0)),
        phishtank_score=float(openphish_result.get("phishtank_score", 0)),
        gsb_score=float(gsb_result.get("gsb_score", 0)),
        ml_phishing_probability=_ml_prob,   # NEW — ML now informs the score
    )
    message = render_message(target_url, risk_level, confidence)

    try:
        vt_hash = vt_id.split("-")[1]
        vt_link = f"https://www.virustotal.com/gui/url/{vt_hash}/detection"
    except Exception:
        vt_link = None

    # ── Aggregate all flags ───────────────────────────────────────────────────
    all_flags = (
        heuristics_result.get("flags", []) +
        whois_result.get("flags", []) +
        dns_result.get("flags", []) +
        ssl_result.get("flags", []) +
        redirect_result.get("flags", []) +
        urlhaus_result.get("flags", []) +
        openphish_result.get("flags", []) +
        gsb_result.get("flags", [])
    )

    # ── Build result payload ──────────────────────────────────────────────────
    result_payload = {
        "url": target_url,
        "risk_level": risk_level,
        "confidence_score": confidence,
        "message": message,
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "scan_id": vt_id,
        "detection_counts": vt_stats,
        "scanners_count": sum(vt_stats.values()) if vt_stats else 0,
        "virustotal_report": vt_link,
        "report_url": us_data.get("task", {}).get("reportURL") if us_data else None,
        "screenshot_url": us_data.get("task", {}).get("screenshotURL") if us_data else None,
        "score_breakdown": breakdown,
        "heuristics": {
            "flags": heuristics_result.get("flags", []),
            "flag_count": heuristics_result.get("flag_count", 0),
            "heuristic_score": heuristics_result.get("heuristic_score", 0),
            "entropy": heuristics_result.get("entropy", 0.0),
            "checks_count": heuristics_result.get("checks_count", 0),
            "is_suspicious": heuristics_result.get("is_suspicious", False),
        },
        "whois": {
            "domain": whois_result.get("domain"),
            "domain_age_days": whois_result.get("domain_age_days"),
            "registrar": whois_result.get("registrar"),
            "creation_date": whois_result.get("creation_date"),
            "expiration_date": whois_result.get("expiration_date"),
            "country": whois_result.get("country"),
            "flags": whois_result.get("flags", []),
            "whois_score": whois_result.get("whois_score", 0),
            "is_suspicious": whois_result.get("is_suspicious", False),
        },
        "dns": {
            "hostname": dns_result.get("hostname"),
            "flags": dns_result.get("flags", []),
            "dns_score": dns_result.get("dns_score", 0),
            "details": dns_result.get("details", {}),
            "is_suspicious": dns_result.get("is_suspicious", False),
        },
        "ssl": {
            "hostname": ssl_result.get("hostname"),
            "flags": ssl_result.get("flags", []),
            "ssl_score": ssl_result.get("ssl_score", 0),
            "details": ssl_result.get("details", {}),
            "is_suspicious": ssl_result.get("is_suspicious", False),
        },
        "redirects": {
            "original_url": redirect_result.get("original_url"),
            "final_url": redirect_result.get("final_url"),
            "hop_count": redirect_result.get("hop_count", 0),
            "hops": redirect_result.get("hops", []),
            "shorteners_found": redirect_result.get("shorteners_found", []),
            "destination_changed": redirect_result.get("destination_changed", False),
            "is_www_normalization": redirect_result.get("is_www_normalization", False),
            "final_domain": redirect_result.get("final_domain"),
            "flags": redirect_result.get("flags", []),
            "redirect_score": redirect_result.get("redirect_score", 0),
            "is_suspicious": redirect_result.get("is_suspicious", False),
        },
        "urlhaus": {
            "found": urlhaus_result.get("found", False),
            "status": urlhaus_result.get("status"),
            "threat": urlhaus_result.get("threat"),
            "tags": urlhaus_result.get("tags", []),
            "date_added": urlhaus_result.get("date_added"),
            "reporter": urlhaus_result.get("reporter"),
            "urlhaus_url": urlhaus_result.get("urlhaus_url"),
            "flags": urlhaus_result.get("flags", []),
            "urlhaus_score": urlhaus_result.get("urlhaus_score", 0),
            "is_suspicious": urlhaus_result.get("is_suspicious", False),
        },
        "phishtank": {
            "found": openphish_result.get("found", False),
            "match_type": openphish_result.get("match_type"),
            "matched_entry": openphish_result.get("matched_entry"),
            "feed_size": openphish_result.get("feed_size", 0),
            "source": openphish_result.get("source", "openphish"),
            "flags": openphish_result.get("flags", []),
            "phishtank_score": openphish_result.get("phishtank_score", 0),
            "is_suspicious": openphish_result.get("is_suspicious", False),
        },
        "gsb": {
            "found": gsb_result.get("found", False),
            "threats": gsb_result.get("threats", []),
            "flags": gsb_result.get("flags", []),
            "gsb_score": gsb_result.get("gsb_score", 0),
            "is_suspicious": gsb_result.get("is_suspicious", False),
            "api_available": gsb_result.get("api_available", False),
        },
        "all_flags": all_flags,
        "total_flags": len(all_flags),
    }

    # ── ML Prediction (final enrichment) ─────────────────────────────────────
    # Re-run with the fully assembled payload for richer feature extraction.
    # The early run (_ml_early) already fed its probability into classify_risk().
    # This second run produces the detailed top_features breakdown for the UI.
    ml_result = await run_ml_prediction(result_payload)
    result_payload["ml_prediction"] = ml_result

    log.success(
        f"Scan complete: {target_url} | {risk_level} ({confidence}%) | "
        f"Flags: {len(all_flags)} | "
        f"ML: {ml_result.get('ml_risk_level', 'N/A')} "
        f"({ml_result.get('phishing_probability', 'N/A')}%)"
    )

    # ── Cache ─────────────────────────────────────────────────────────────────
    try:
        if r:
            await r.set(target_url, json.dumps(result_payload), ex=3600)
    except Exception as e:
        log.warning(f"Cache save failed: {e}")

    # ── Memory index ──────────────────────────────────────────────────────────
    try:
        await store_scan_result(result_payload)
    except Exception as e:
        log.warning(f"Memory index failed: {e}")

    # ── Metrics ───────────────────────────────────────────────────────────────
    try:
        await record_scan(
            risk_level=risk_level,
            scan_time_ms=(time.time() - scan_start) * 1000,
            cache_hit=False,
            urlhaus_hit=urlhaus_result.get("found", False),
            openphish_hit=openphish_result.get("found", False),
            gsb_hit=gsb_result.get("found", False),
            ml_risk_level=ml_result.get("ml_risk_level"),
        )
    except Exception as e:
        log.warning(f"Metrics recording failed: {e}")

    return result_payload
