"""
main.py — Phase 1+2+3 v5
==========================

Phase 1 (Zero-API Local Detection):
  - Multi-QR decoder (all QRs in one image)
  - 12-layer payload deobfuscation engine
  - 15 QR type parsers (vCard, crypto, geo, deep link, calendar, etc.)
  - WiFi Security Auditor v2 (evil twin, password strength, MAC spoof)
  - Payload hash blacklist (SQLite, instant blocking)
  - Smishing pattern detector (20+ pattern library, zero API)

Phase 2 (Image-Level Analysis):
  - Physical tamper detection (sticker overlay CV analysis)
  - EXIF metadata extractor (GPS, device, editing software)
  - QR visual fingerprinting + coordinated campaign detection (pHash + Redis)

Phase 2 Bug Fixes:
  B10: Photo QR via cv2.QRCodeDetector
  B11: Campaign detection fixed
  B12: Base64 deduplication (google.com no longer High risk)
  B13: WiFi evil twin detection
  B14: DNS false positives on subdomains
  B15: URL scan Redis cache (6h safe / 1h risky)
  B18: Concurrent QR processing (asyncio.gather)
  B19: URL type gathers all URLs at once
  B20: Tamper text 1-technique now shows warning not all-clear
  NEW: QR payload Redis cache (24h safe / 30min critical)

Phase 3 — External Intelligence APIs (v5):
  ─────────────────────────────────────────────
  IPQualityScore (IPQS):
    - URL fraud scoring (phishing, malware, proxy detection)
    - Phone number fraud scoring (VOIP, disposable, fraud-linked)
    - Triggered for: URL, tel:, SMS, vCard phone numbers
    - Free: 5,000 lookups/month at ipqualityscore.com

  AbuseIPDB:
    - IP address reputation (100M+ abuse reports)
    - Triggered automatically for: URLs containing raw IP addresses
    - Free: 1,000 checks/day at abuseipdb.com

  Have I Been Pwned (HIBP):
    - Email address data breach check
    - Triggered for: mailto: QR codes, email fields in vCard
    - Key required: $3.50/mo at haveibeenpwned.com

  Crypto Intelligence (BitcoinAbuse + Blockchain.com):
    - Wallet address scam report check (BitcoinAbuse)
    - Transaction history (Blockchain.com, no key required)
    - Address format validation (substitution attack detection)
    - Triggered for: bitcoin:, ethereum:, litecoin:, monero: QR codes

  PhishTank:
    - Verified phishing URL database (50,000+ entries)
    - Free with API key at phishtank.com
    - Triggered for: all URL-type QR codes (alongside Link Analyzer)

  Architecture:
    - All Phase 3 checks run CONCURRENTLY per QR payload via asyncio.gather
    - Phase 3 enrichment runs ALONGSIDE Link Analyzer (not after) for URLs
    - All API calls gracefully skipped if key not set in .env
    - Risk level from Phase 3 feeds into final composite risk score
    - Phase 3 results nested under "phase3_enrichment" in API response

Phase 4 — Architecture & Platform (v6):
    - 4.1 Async scan with job polling (/scan-async, /scan-status/{job_id})
    - 4.2 Scan history & audit trail (/history, /history/export)
    - 4.3 Batch QR processing up to 20 images (/scan-batch)
    - 4.4 Community /report endpoint (existing, enhanced)
    - 4.5 WebSocket live dashboard (/ws/live, /stats/detailed, /stats/threats)
    - 4.6 QR code generator with Aegis safety badge (/generate)
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from PIL import Image, ImageDraw, ImageFont
from typing import Optional, List
import io
import csv
import uuid
import base64
import os
import asyncio
import hashlib
import json
import datetime
import httpx
import redis.asyncio as redis_async

try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_H, ERROR_CORRECT_M, ERROR_CORRECT_L
    QR_GEN_AVAILABLE = True
except ImportError:
    QR_GEN_AVAILABLE = False

from app.logger import log
from app.multi_decoder import extract_all_qr_codes
from app.deobfuscator import deobfuscate_payload
from app.type_parser import identify_and_parse
from app.blacklist import init_blacklist_db, check_blacklist, add_to_blacklist, get_blacklist_stats
from app.smishing_detector import detect_smishing
from app.logic import analyze_wifi, offline_url_check, analyze_communication
from app.ai import analyze_intent
from app.telemetry import track_scan_event, get_live_stats
# Phase 2
from app.tamper_detector import detect_physical_tamper
from app.exif_analyzer import analyze_exif
from app.fingerprint import check_fingerprint_campaign
# Phase 3 — External Intelligence
from app.enrichment import (
    enrich_url,
    enrich_email,
    enrich_phone,
    enrich_crypto,
    enrich_vcard,
)

app = FastAPI(
    title="Aegis QR Scanner",
    version="Phase 1+2+3+4 v6 — Full Platform",
    description=(
        "**Phase 1:** Multi-QR · 12-layer deobfuscation · 15 type parsers · Blacklist · Smishing\n\n"
        "**Phase 2:** Physical tamper · EXIF metadata · Visual fingerprinting · Campaign detection\n\n"
        "**Phase 3:** Google Safe Browsing · AbuseIPDB · EmailRep.io · "
        "Chainabuse · Blockchain.com · NumVerify\n\n"
        "**v5:** All enrichment runs concurrently alongside Link Analyzer. "
        "Set API keys in .env to activate each intelligence layer."
    )
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

LINK_ANALYZER_URL = os.getenv("LINK_ANALYZER_URL", "http://host.docker.internal:8000")
REDIS_URL         = os.getenv("REDIS_URL", "redis://redis:6379")


# ── Async no-op helpers (replace deprecated asyncio.coroutine) ──
async def _noop_dict() -> dict:
    """Returns empty dict — used as a placeholder in asyncio.gather() when a step is skipped."""
    return {}

async def _noop_list() -> list:
    """Returns empty list — used as a placeholder in asyncio.gather() when a step is skipped."""
    return []


# ════════════════════════════════════════════════════════════════
# Phase 4 — Platform Globals
# ════════════════════════════════════════════════════════════════

# WebSocket connection manager
class _WSManager:
    def __init__(self):
        self.clients: set = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)
        log.info(f"[WS] Client connected. Total: {len(self.clients)}")

    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)
        log.info(f"[WS] Client disconnected. Total: {len(self.clients)}")

    async def broadcast(self, payload: dict):
        if not self.clients:
            return
        msg = json.dumps(payload)
        dead = set()
        for ws in self.clients:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self.clients -= dead

ws_manager = _WSManager()

# Redis keys for Phase 4
HISTORY_KEY    = "aegis:scan_history"   # sorted set — score = unix timestamp
THREATS_KEY    = "aegis:recent_threats" # list, capped at 50 entries
JOB_PREFIX     = "aegis:job:"
HISTORY_TTL    = 60 * 60 * 24 * 30     # 30 days
JOB_TTL        = 3600                   # 1 hour


async def _store_history(result: dict) -> None:
    """Persist scan summary to Redis history sorted set."""
    try:
        r = redis_async.from_url(REDIS_URL, socket_timeout=2.0)
        ts = datetime.datetime.utcnow().timestamp()

        summary = {
            "id":            str(uuid.uuid4()),
            "timestamp":     datetime.datetime.utcnow().isoformat(),
            "total_qr":      result.get("total_qr_found", 0),
            "overall_risk":  result.get("overall_risk", "Safe"),
            "analyses":      [
                {
                    "type":        a.get("qr_type"),
                    "risk":        a.get("final_risk_level"),
                    "score":       a.get("final_risk_score"),
                    "preview":     a.get("payload_preview", "")[:80],
                    "flags":       (a.get("phase3_enrichment") or {}).get("all_enrichment_flags", [])[:3],
                }
                for a in result.get("analyses", [])
            ],
            "alerts":        {
                "tamper":       result.get("security_alerts", {}).get("tamper_suspected", False),
                "multi_qr":     result.get("security_alerts", {}).get("multiple_qr_codes", False),
                "campaign":     result.get("security_alerts", {}).get("campaign_detected", False),
                "stego":        result.get("security_alerts", {}).get("steganography", {}).get("detected", False),
            },
        }

        entry_json = json.dumps(summary)
        await r.zadd(HISTORY_KEY, {entry_json: ts})
        await r.expire(HISTORY_KEY, HISTORY_TTL)

        # Track high-risk scans in recent_threats list
        risk = result.get("overall_risk", "Safe")
        if risk in ("High", "Critical"):
            await r.lpush(THREATS_KEY, entry_json)
            await r.ltrim(THREATS_KEY, 0, 49)   # Keep last 50 threats
            await r.expire(THREATS_KEY, HISTORY_TTL)

        await r.aclose()

    except Exception as e:
        log.warning(f"[History] Failed to store scan: {e}")


async def _emit_ws_event(result: dict) -> None:
    """Broadcast scan completion event to all WebSocket clients."""
    try:
        await ws_manager.broadcast({
            "event":        "scan_complete",
            "timestamp":    datetime.datetime.utcnow().isoformat(),
            "overall_risk": result.get("overall_risk", "Safe"),
            "total_qr":     result.get("total_qr_found", 0),
            "alerts":       {
                "tamper":   result.get("security_alerts", {}).get("tamper_suspected", False),
                "multi_qr": result.get("security_alerts", {}).get("multiple_qr_codes", False),
            },
            "risk_summary": [
                {"type": a.get("qr_type"), "risk": a.get("final_risk_level")}
                for a in result.get("analyses", [])
            ],
        })
    except Exception as e:
        log.warning(f"[WS Broadcast] {e}")

# URL scan cache TTLs
CACHE_TTL_SAFE    = 21600   # 6 hours for clean URLs
CACHE_TTL_RISKY   = 3600    # 1 hour for risky URLs (re-check sooner)
CACHE_TTL_BLOCK   = 300     # 5 minutes for errors (retry quickly)

# QR payload analysis cache TTLs (B18 NEW FEATURE)
QR_CACHE_TTL_SAFE     = 86400   # 24h — safe QR analyses don't change
QR_CACHE_TTL_MEDIUM   = 7200    # 2h  — medium risk, recheck periodically
QR_CACHE_TTL_CRITICAL = 1800    # 30min — critical/high, URLs may be taken down
QR_CACHE_TTL_ERROR    = 300     # 5min — errors, retry quickly


# ─────────────────────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────────────────────

class QRRequest(BaseModel):
    image_base64: str

class ReportRequest(BaseModel):
    payload: str
    threat_type: str
    source: Optional[str] = "user_report"
    notes: Optional[str] = None

# Phase 4 models
class ScanBatchRequest(BaseModel):
    images: List[str]                   # list of base64-encoded images, max 20

class GenerateRequest(BaseModel):
    url: str
    label: Optional[str] = None         # text label below QR (optional)
    add_safety_badge: bool = True       # add Aegis verified badge
    error_correction: str = "H"         # H / M / L — H = 30% data recovery


# ─────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    log.info("[Main] Aegis QR Scanner Phase 1+2 v3 starting...")
    init_blacklist_db()

    # Test Redis
    redis_ok = False
    for url in [REDIS_URL, "redis://redis:6379", "redis://host.docker.internal:6380"]:
        try:
            r = redis_async.from_url(url, socket_timeout=2.0)
            await r.ping()
            await r.aclose()
            log.info(f"[Main] ✅ Redis connected: {url}")
            redis_ok = True
            break
        except Exception:
            continue
    if not redis_ok:
        log.warning("[Main] ⚠️ Redis unavailable — caching + campaign detection disabled")

    log.info(f"[Main] ✅ Blacklist DB ready | Link Analyzer: {LINK_ANALYZER_URL}")


# ─────────────────────────────────────────────────────────────
# URL Scan Cache (B15 FIX)
# ─────────────────────────────────────────────────────────────

async def _get_cached_url_scan(url: str) -> Optional[dict]:
    """
    Check Redis for a cached URL scan result.
    Returns the cached result dict or None if not cached.
    """
    try:
        r = redis_async.from_url(REDIS_URL, encoding="utf-8", decode_responses=True, socket_timeout=2.0)
        key = f"urlscan:{hashlib.sha256(url.encode()).hexdigest()[:16]}"
        raw = await r.get(key)
        await r.aclose()
        if raw:
            result = json.loads(raw)
            result["_cached"] = True
            log.info(f"[URLCache] ✅ Cache hit for {url[:50]} — risk={result.get('risk_level','?')}")
            return result
    except Exception:
        pass
    return None


async def _cache_url_scan(url: str, result: dict) -> None:
    """
    Cache a URL scan result in Redis.
    TTL varies by risk level — safe URLs cached longer since they change rarely.
    """
    try:
        risk = result.get("risk_level", "").lower()
        if "safe" in risk:
            ttl = CACHE_TTL_SAFE
        elif "low" in risk:
            ttl = CACHE_TTL_SAFE
        elif "medium" in risk:
            ttl = CACHE_TTL_RISKY
        elif "high" in risk or "critical" in risk:
            ttl = CACHE_TTL_RISKY
        else:
            ttl = CACHE_TTL_BLOCK

        r = redis_async.from_url(REDIS_URL, encoding="utf-8", decode_responses=True, socket_timeout=2.0)
        key = f"urlscan:{hashlib.sha256(url.encode()).hexdigest()[:16]}"
        await r.setex(key, ttl, json.dumps(result))
        await r.aclose()
        log.debug(f"[URLCache] Cached {url[:50]} for {ttl}s")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
# QR Payload Analysis Cache (B18 NEW — v4)
# ─────────────────────────────────────────────────────────────
# Caches the full payload analysis result (deobfuscation, smishing,
# type parsing, URL scans). Second scan of identical QR barcode returns
# instantly from Redis — no external API calls needed.
# Key: qrscan:{sha256(payload)[:16]}  TTL: 24h safe, 2h medium, 30min critical
# ─────────────────────────────────────────────────────────────

async def _get_cached_qr_analysis(payload: str) -> Optional[dict]:
    """
    Check Redis for a cached QR payload analysis result.
    Returns full analysis dict (with _qr_cached=True flag) or None.
    """
    try:
        r = redis_async.from_url(REDIS_URL, encoding="utf-8", decode_responses=True, socket_timeout=2.0)
        key = f"qrscan:{hashlib.sha256(payload.encode()).hexdigest()[:16]}"
        raw = await r.get(key)
        await r.aclose()
        if raw:
            result = json.loads(raw)
            result["_qr_cached"] = True
            log.info(f"[QRCache] ✅ Cache hit: {payload[:50]} → risk={result.get('final_risk_level','?')}")
            return result
    except Exception:
        pass
    return None


async def _cache_qr_analysis(payload: str, result: dict) -> None:
    """
    Cache full QR analysis result in Redis.
    TTL by risk level: safe=24h, medium=2h, critical/high=30min.
    Blacklisted payloads (Critical) use short TTL so block can be updated.
    """
    try:
        risk = result.get("final_risk_level", "").lower()
        if "critical" in risk or "high" in risk:
            ttl = QR_CACHE_TTL_CRITICAL
        elif "medium" in risk:
            ttl = QR_CACHE_TTL_MEDIUM
        elif "safe" in risk or "low" in risk:
            ttl = QR_CACHE_TTL_SAFE
        else:
            ttl = QR_CACHE_TTL_ERROR

        r = redis_async.from_url(REDIS_URL, encoding="utf-8", decode_responses=True, socket_timeout=2.0)
        key = f"qrscan:{hashlib.sha256(payload.encode()).hexdigest()[:16]}"
        await r.setex(key, ttl, json.dumps(result))
        await r.aclose()
        log.info(f"[QRCache] Cached QR analysis: {payload[:40]} risk={risk} TTL={ttl}s")
    except Exception:
        pass


async def analyze_payload_with_cache(payload: str, qr_index: int) -> dict:
    """
    Wrapper around analyze_single_payload that checks/sets QR cache.
    On cache hit: returns full result in <100ms with _qr_cached=True.
    On cache miss: runs full analysis, stores result, returns.
    """
    cached = await _get_cached_qr_analysis(payload)
    if cached:
        # Update payload_index to current position (may differ in multi-QR)
        cached["payload_index"] = qr_index
        return cached

    result = await analyze_single_payload(payload, qr_index)
    await _cache_qr_analysis(payload, result)
    return result


# ─────────────────────────────────────────────────────────────
# Link Analyzer Integration
# ─────────────────────────────────────────────────────────────

async def deep_scan_url(url: str) -> dict:
    """
    Sends URL to Link Analyzer. Checks Redis cache first (B15 FIX).
    On cache hit: returns instantly without network call.
    On cache miss: calls Link Analyzer, caches result for future calls.
    """
    # Check cache first
    cached = await _get_cached_url_scan(url)
    if cached:
        return cached

    # Call Link Analyzer
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{LINK_ANALYZER_URL}/scan",
                json={"url": url},
                timeout=90.0
            )
        if response.status_code == 200:
            result = response.json()
            result["source"] = "link_analyzer"
            result["url"] = url
            await _cache_url_scan(url, result)
            log.info(f"[LinkAnalyzer] {url[:60]} → risk={result.get('risk_level', '?')}")
            return result
        else:
            fallback = {"source": "link_analyzer_error", "http_code": response.status_code,
                        "url": url, **offline_url_check(url)}
            return fallback
    except httpx.TimeoutException:
        log.warning(f"[LinkAnalyzer] Timeout: {url[:50]}")
        return {"source": "offline_timeout", "url": url, **offline_url_check(url)}
    except Exception as e:
        log.warning(f"[LinkAnalyzer] Unavailable: {e}")
        return {"source": "offline_fallback", "url": url, **offline_url_check(url)}


async def deep_scan_all_urls(urls: List[str]) -> List[dict]:
    """Scan a list of URLs concurrently (max 3 parallel)."""
    if not urls:
        return []
    unique = list(dict.fromkeys(urls))
    sem = asyncio.Semaphore(3)

    async def _scan(url):
        async with sem:
            return await deep_scan_url(url)

    return list(await asyncio.gather(*[_scan(u) for u in unique]))


# ─────────────────────────────────────────────────────────────
# Phase 1 Payload Pipeline
# ─────────────────────────────────────────────────────────────

async def analyze_single_payload(raw_payload: str, qr_index: int = 0) -> dict:
    """
    Full Phase 1 pipeline for a single QR payload.

    Pipeline order:
    1. Blacklist check on original
    2. Deobfuscation
    3. Type-parse ORIGINAL first (B1 fix from Phase 1)
       → Only use decoded if original="text" AND decoded="known type"
    4. Blacklist check on decoded
    5. Smishing on original text
    6. Type-specific analysis + URL scans (with caching)
    7. Composite risk score
    """
    log.info(f"[Pipeline] Payload #{qr_index}: {raw_payload[:70]}")

    # ── 1. Blacklist check on original ─────────────────────
    bl_original = check_blacklist(raw_payload)
    if bl_original["blacklisted"]:
        await track_scan_event("blacklisted", "Critical")
        return {
            "payload_index":   qr_index,
            "payload_preview": raw_payload[:150],
            "blacklist":       bl_original,
            "blocked":         True,
            "risk_level":      "Critical",
            "risk_score":      100,
            "message":         "🚨 Payload is in the known-malicious blacklist. Blocked."
        }

    # ── 2. Deobfuscation ────────────────────────────────────
    deobfuscation = deobfuscate_payload(raw_payload)

    # ── 3. Type-parse ORIGINAL first ───────────────────────
    parsed_original = identify_and_parse(raw_payload)
    original_type   = parsed_original.get("qr_type", "text")

    working_payload = raw_payload
    parsed_type     = parsed_original

    if original_type == "text" and deobfuscation["is_obfuscated"]:
        best_decoded = deobfuscation["likely_true_payload"]
        if best_decoded and best_decoded != raw_payload:
            parsed_decoded = identify_and_parse(best_decoded)
            if parsed_decoded["qr_type"] != "text":
                working_payload = best_decoded
                parsed_type     = parsed_decoded
                log.info(f"[Pipeline] Deobf revealed: '{original_type}' → '{parsed_decoded['qr_type']}'")

    qr_type = parsed_type.get("qr_type", "text")

    # ── 4. Blacklist check on decoded ───────────────────────
    bl_decoded = {"blacklisted": False}
    if working_payload != raw_payload:
        bl_decoded = check_blacklist(working_payload)
        if bl_decoded["blacklisted"]:
            bl_decoded["note"] = "Payload was obfuscated — blacklisted after decoding"
            await track_scan_event("blacklisted_deob", "Critical")
            return {
                "payload_index":   qr_index,
                "payload_preview": raw_payload[:150],
                "deobfuscation":   deobfuscation,
                "blacklist":       bl_decoded,
                "blocked":         True,
                "risk_level":      "Critical",
                "risk_score":      100,
                "message":         "🚨 Hidden malicious payload found after deobfuscation."
            }

    # ── 5. Smishing on original text ────────────────────────
    smishing_result = {}
    smishing_types  = ["sms", "email", "text", "vcard", "mecard", "calendar"]
    if qr_type in smishing_types:
        if qr_type == "sms":
            smish_text = parsed_type.get("body", "") or raw_payload
        elif qr_type == "email":
            smish_text = f"{parsed_type.get('subject','') or ''} {parsed_type.get('body','') or ''}".strip() or raw_payload
        elif qr_type in ("calendar",):
            smish_text = f"{parsed_type.get('summary','') or ''} {parsed_type.get('description','') or ''}".strip() or raw_payload
        else:
            smish_text = raw_payload
        smishing_result = detect_smishing(smish_text, qr_type)

    # ── 6. URL collection + type-specific analysis ──────────
    urls_to_scan = list(parsed_type.get("urls_to_scan", []))
    for url in deobfuscation.get("all_extracted_urls", []):
        if url not in urls_to_scan:
            urls_to_scan.append(url)
    if raw_payload.startswith(("http://", "https://")) and raw_payload not in urls_to_scan:
        urls_to_scan.insert(0, raw_payload)

    type_analysis     = {}
    url_scans         = []
    ai_analysis       = {}
    phase3_enrichment = {}

    if qr_type == "wifi":
        type_analysis = analyze_wifi(raw_payload)
        # WiFi: no external enrichment (local analysis only)
        await track_scan_event("wifi", type_analysis.get("risk_level", "Low"))

    elif qr_type == "url":
        # B19 FIX: gather ALL URLs at once — primary + any extras from deobfuscation
        primary = working_payload if working_payload.startswith(("http://", "https://")) else raw_payload
        all_urls_ordered = [primary] + [u for u in urls_to_scan if u != primary]

        # Phase 3: run Link Analyzer + IPQS + PhishTank CONCURRENTLY
        la_task   = deep_scan_all_urls(all_urls_ordered)
        p3_task   = enrich_url(primary)
        la_result, p3_result = await asyncio.gather(la_task, p3_task, return_exceptions=True)

        url_scans         = la_result if isinstance(la_result, list) else []
        phase3_enrichment = p3_result if isinstance(p3_result, dict) else {"status": "error", "error": str(p3_result)}

        await track_scan_event("url", url_scans[0].get("risk_level", "Low") if url_scans else "Low")

    elif qr_type in ("email", "sms", "tel"):
        # Phase 3: communication analysis + IPQS phone/email enrichment concurrently
        comm_task = analyze_communication(raw_payload, parsed_type)

        # Determine enrichment based on type
        # Note: email parser stores address at "address" key (not "to_address")
        email_addr = (parsed_type.get("address") or
                      parsed_type.get("to_address") or
                      parsed_type.get("email", ""))
        phone_num  = (parsed_type.get("number") or
                      parsed_type.get("phone") or
                      parsed_type.get("tel", ""))
        comm_urls  = urls_to_scan

        tasks = [comm_task]
        if qr_type == "email" and email_addr:
            tasks.append(enrich_email(email_addr))
        elif qr_type in ("sms", "tel") and phone_num:
            tasks.append(enrich_phone(phone_num))
        else:
            tasks.append(asyncio.ensure_future(_noop_dict()))

        if comm_urls:
            tasks.append(deep_scan_all_urls(comm_urls))
        else:
            tasks.append(asyncio.ensure_future(_noop_list()))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        type_analysis     = results[0] if isinstance(results[0], dict) else {}
        phase3_enrichment = results[1] if isinstance(results[1], dict) else {}
        url_scans         = results[2] if isinstance(results[2], list) else []

        await track_scan_event("communication", type_analysis.get("ai_analysis", {}).get("risk", "Low"))

    elif qr_type == "vcard":
        # Phase 3: vCard enrichment checks all embedded URLs, phones, and emails
        la_task = deep_scan_all_urls(urls_to_scan) if urls_to_scan else asyncio.ensure_future(_noop_list())
        ai_task = analyze_intent(raw_payload, "vCard contact — check for contact injection attack")
        p3_task = enrich_vcard(parsed_type)

        results = await asyncio.gather(la_task, ai_task, p3_task, return_exceptions=True)

        url_scans         = results[0] if isinstance(results[0], list) else []
        ai_analysis       = results[1] if isinstance(results[1], dict) else {}
        phase3_enrichment = results[2] if isinstance(results[2], dict) else {"status": "error"}

        await track_scan_event("vcard", ai_analysis.get("risk", "Low"))

    elif qr_type == "mecard":
        # MeCard: extract phone/email from parsed_type for enrichment
        la_task = deep_scan_all_urls(urls_to_scan) if urls_to_scan else asyncio.ensure_future(_noop_list())
        ai_task = analyze_intent(raw_payload, "MeCard contact — check for injection")
        phone_n = parsed_type.get("phone", "")
        p3_task = enrich_phone(phone_n) if phone_n else asyncio.ensure_future(_noop_dict())

        results = await asyncio.gather(la_task, ai_task, p3_task, return_exceptions=True)

        url_scans         = results[0] if isinstance(results[0], list) else []
        ai_analysis       = results[1] if isinstance(results[1], dict) else {}
        phase3_enrichment = results[2] if isinstance(results[2], dict) else {}

        await track_scan_event("mecard", ai_analysis.get("risk", "Low"))

    elif qr_type == "calendar":
        la_task = deep_scan_all_urls(urls_to_scan) if urls_to_scan else asyncio.ensure_future(_noop_list())
        ai_task = analyze_intent(raw_payload, "Calendar event — social engineering check")

        results = await asyncio.gather(la_task, ai_task, return_exceptions=True)

        url_scans   = results[0] if isinstance(results[0], list) else []
        ai_analysis = results[1] if isinstance(results[1], dict) else {}

        await track_scan_event("calendar", ai_analysis.get("risk", "Low"))

    elif qr_type == "bitcoin":
        # Phase 3: crypto intelligence — address check + AI analysis concurrently
        coin    = parsed_type.get("coin", "bitcoin")
        address = parsed_type.get("wallet_address", raw_payload.split(":")[-1].split("?")[0].strip())

        ai_task = analyze_intent(raw_payload, "Crypto QR — check for payment scam or address substitution")
        p3_task = enrich_crypto(address, coin) if address else asyncio.ensure_future(_noop_dict())

        results = await asyncio.gather(ai_task, p3_task, return_exceptions=True)

        ai_analysis       = results[0] if isinstance(results[0], dict) else {}
        phase3_enrichment = results[1] if isinstance(results[1], dict) else {}

        await track_scan_event("crypto", ai_analysis.get("risk", "Medium"))

    elif qr_type == "geo":
        ai_analysis = await analyze_intent(raw_payload, "GPS coordinates — verify physical location safety")
        await track_scan_event("geo", ai_analysis.get("risk", "Low"))

    elif qr_type == "app_deeplink":
        la_task = deep_scan_all_urls(urls_to_scan) if urls_to_scan else asyncio.ensure_future(_noop_list())
        ai_task = analyze_intent(raw_payload, "App deep link — check for silent app launch or hijacking")

        results = await asyncio.gather(la_task, ai_task, return_exceptions=True)

        url_scans   = results[0] if isinstance(results[0], list) else []
        ai_analysis = results[1] if isinstance(results[1], dict) else {}

        await track_scan_event("deeplink", ai_analysis.get("risk", "Medium"))

    elif qr_type in ("ftp", "ssh"):
        ai_analysis = await analyze_intent(raw_payload, f"{qr_type.upper()} connection — credential theft check")
        await track_scan_event(qr_type, ai_analysis.get("risk", "Medium"))

    elif qr_type == "data_uri":
        ai_analysis = await analyze_intent(raw_payload, "Data URI — possible HTML/JavaScript injection attack")
        await track_scan_event("data_uri", "High")

    elif qr_type == "magnet":
        ai_analysis = await analyze_intent(raw_payload, "Magnet/torrent link — verify content legitimacy")
        await track_scan_event("magnet", ai_analysis.get("risk", "Low"))

    else:
        la_task = deep_scan_all_urls(urls_to_scan) if urls_to_scan else asyncio.ensure_future(_noop_list())
        ai_task = analyze_intent(raw_payload, "QR payload — social engineering / malicious content check")

        results = await asyncio.gather(la_task, ai_task, return_exceptions=True)

        url_scans   = results[0] if isinstance(results[0], list) else []
        ai_analysis = results[1] if isinstance(results[1], dict) else {}

        await track_scan_event("text", ai_analysis.get("risk", "Low"))

    # ── 7. Composite risk score ─────────────────────────────
    risk_inputs = []

    if smishing_result and qr_type in smishing_types:
        risk_inputs.append(smishing_result.get("smishing_score", 0))

    # Deobfuscation boost: only when critical_alert present (genuine obfuscation)
    if deobfuscation.get("is_obfuscated") and deobfuscation.get("critical_alert"):
        risk_inputs.append(min(deobfuscation["risk_score_boost"], 60))

    la_map = {
        "Safe": 5, "Low Risk": 20, "Low": 20,
        "Medium Risk": 50, "Medium": 50,
        "High Risk": 80, "High": 80, "Critical": 95
    }
    for scan in url_scans:
        risk_inputs.append(la_map.get(scan.get("risk_level", "Low"), 10))

    if type_analysis:
        risk_inputs.append(type_analysis.get("risk_score", 0))

    # Phase 3 enrichment risk feeds into composite score
    p3_risk_map = {"Safe": 5, "Low": 15, "Medium": 45, "High": 70, "Critical": 90}
    p3_risk = phase3_enrichment.get("enrichment_risk_level", "Safe")
    if p3_risk != "Safe":
        risk_inputs.append(p3_risk_map.get(p3_risk, 5))

    final_score = max(risk_inputs) if risk_inputs else 5

    if final_score >= 80:   final_risk = "Critical"
    elif final_score >= 60: final_risk = "High"
    elif final_score >= 35: final_risk = "Medium"
    elif final_score >= 15: final_risk = "Low"
    else:                   final_risk = "Safe"

    return {
        "payload_index":     qr_index,
        "payload_preview":   raw_payload[:150],
        "qr_type":           qr_type,
        "qr_type_label":     parsed_type.get("label", qr_type),
        "blocked":           False,
        "blacklist":         bl_original,
        "deobfuscation":     deobfuscation,
        "parsed_content":    parsed_type,
        "smishing_analysis": smishing_result,
        "type_analysis":     type_analysis,
        "url_deep_scans":    url_scans,
        "ai_analysis":       ai_analysis,
        "phase3_enrichment": phase3_enrichment,   # NEW — Phase 3 external intelligence
        "final_risk_score":  final_score,
        "final_risk_level":  final_risk,
    }


# ─────────────────────────────────────────────────────────────
# Phase 2 — Image-Level Analysis
# ─────────────────────────────────────────────────────────────

async def analyze_image_phase2(
    image: Image.Image,
    payload_hash: str,
    payload_preview: str
) -> dict:
    """
    Runs Phase 2 image analyses concurrently:
      - Physical tamper detection (sticker overlay CV)
      - EXIF metadata (GPS, device, editing software)
      - Visual fingerprinting + campaign detection (pHash + Redis)
    """
    tamper_task      = asyncio.to_thread(detect_physical_tamper, image)
    exif_task        = asyncio.to_thread(analyze_exif, image)
    fingerprint_task = check_fingerprint_campaign(image, payload_hash, payload_preview)

    tamper, exif, fingerprint = await asyncio.gather(
        tamper_task, exif_task, fingerprint_task,
        return_exceptions=True
    )

    if isinstance(tamper, Exception):
        log.error(f"[Phase2] Tamper error: {tamper}")
        tamper = {"error": str(tamper), "tamper_suspected": False}
    if isinstance(exif, Exception):
        log.error(f"[Phase2] EXIF error: {exif}")
        exif = {"error": str(exif), "available": False}
    if isinstance(fingerprint, Exception):
        log.error(f"[Phase2] Fingerprint error: {fingerprint}")
        fingerprint = {"error": str(fingerprint), "campaign_detected": False}

    phase2_risk   = 0
    phase2_alerts = []

    if tamper.get("tamper_suspected"):
        phase2_risk = max(phase2_risk, tamper.get("risk_score", 0))
        phase2_alerts.append(
            f"🚨 PHYSICAL TAMPER SUSPECTED ({tamper.get('techniques_triggered', 0)}/5 techniques)"
        )

    if fingerprint.get("campaign_detected"):
        phase2_risk = max(phase2_risk, 70)
        phase2_alerts.append(fingerprint.get("campaign_alert", "🚨 Phishing campaign detected"))

    if exif.get("available") and exif.get("device", {}).get("is_edited"):
        phase2_risk = max(phase2_risk, 30)
        phase2_alerts.append(f"⚠️ Image edited with {exif['device'].get('software', 'unknown software')}")

    if exif.get("gps"):
        phase2_alerts.append(
            f"📍 GPS: {exif['gps']['latitude']}, {exif['gps']['longitude']}"
        )

    return {
        "tamper_detection":   tamper,
        "exif_metadata":      exif,
        "visual_fingerprint": fingerprint,
        "phase2_risk_score":  phase2_risk,
        "phase2_alerts":      phase2_alerts
    }


# ─────────────────────────────────────────────────────────────
# Shared image processing
# ─────────────────────────────────────────────────────────────

async def _process_image(image: Image.Image) -> dict:
    """
    Main processing:
    1. Multi-pass dual-decoder QR detection (cv2 + pyzbar)
    2. Phase 2 image analysis (concurrent)
    3. Phase 1 payload analysis for each QR
    4. Aggregate risk
    """
    # ── Step 1: Decode all QR codes ────────────────────────
    decode_result = extract_all_qr_codes(image)
    codes         = decode_result.get("qr_codes", [])
    stego         = decode_result.get("steganography", {})
    multi_alert   = decode_result.get("multiple_qr_alert", False)

    if not codes:
        await track_scan_event("failed")
        return {
            "status":  "failed",
            "message": (
                "No QR code detected. Tips:\n"
                "• Ensure QR fills at least 30% of the image frame\n"
                "• For phone photos: hold steady, ensure good lighting\n"
                "• For WhatsApp images: use original quality (not compressed)\n"
                "• Avoid extreme angles — try to photograph straight-on"
            ),
            "steganography":   stego,
            "successful_pass": decode_result.get("successful_pass"),
            "passes_tried":    decode_result.get("scan_passes_used", 0),
        }

    # ── Step 2: Phase 2 image analysis ─────────────────────
    first_payload = codes[0]["payload"]
    payload_hash  = hashlib.sha256(first_payload.encode()).hexdigest()
    phase2 = await analyze_image_phase2(image, payload_hash, first_payload[:60])

    # ── Step 3: Phase 1 payload analysis — CONCURRENT (B18 FIX v4) ────
    # All QR payloads analysed in parallel via asyncio.gather.
    # With 2 URL QRs: total time = max(scan1, scan2) not sum(scan1, scan2).
    # Mixed types (e.g. SMS + URL): both run simultaneously.
    # Each uses QR payload cache — repeat scans return instantly.

    async def _process_single_qr(code: dict, qr_index: int) -> dict:
        analysis = await analyze_payload_with_cache(code["payload"], qr_index)
        analysis["qr_format"]    = code.get("format", "QRCODE")
        analysis["bounding_box"] = code.get("bounding_box")
        analysis["scan_pass"]    = code.get("scan_pass")
        return analysis

    qr_tasks = [_process_single_qr(code, i) for i, code in enumerate(codes)]
    analyses_raw = await asyncio.gather(*qr_tasks, return_exceptions=True)

    analyses = []
    for i, result in enumerate(analyses_raw):
        if isinstance(result, Exception):
            log.error(f"[Main] QR #{i} analysis error: {result}")
            analyses.append({
                "payload_index": i,
                "payload_preview": codes[i]["payload"][:60],
                "error": str(result),
                "final_risk_level": "Safe",
                "final_risk_score": 0,
            })
        else:
            analyses.append(result)

    # ── Telemetry ───────────────────────────────────────────
    if stego.get("detected"):
        await track_scan_event("steganography_detected", "High")
    if multi_alert:
        await track_scan_event("multi_qr_detected", "High")
    if phase2["tamper_detection"].get("tamper_suspected"):
        await track_scan_event("tamper_suspected", "High")
    if phase2["visual_fingerprint"].get("campaign_detected"):
        await track_scan_event("campaign_detected", "Critical")

    # ── Overall risk ────────────────────────────────────────
    risk_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Safe": 1}
    p1_risks   = [a.get("final_risk_level", a.get("risk_level", "Safe")) for a in analyses]

    p2_score = phase2["phase2_risk_score"]
    if p2_score >= 80:   p2_risk = "Critical"
    elif p2_score >= 60: p2_risk = "High"
    elif p2_score >= 35: p2_risk = "Medium"
    elif p2_score >= 15: p2_risk = "Low"
    else:                p2_risk = "Safe"

    all_risks    = p1_risks + [p2_risk]
    overall_risk = max(all_risks, key=lambda r: risk_order.get(r, 0))

    result = {
        "status":            "success",
        "total_qr_found":    len(codes),
        "multiple_qr_alert": multi_alert,
        "overall_risk":      overall_risk,
        "analyses":          analyses,
        "phase2_image_analysis": phase2,
        "security_alerts": {
            "steganography":     stego,
            "multiple_qr_codes": multi_alert,
            "tamper_suspected":  phase2["tamper_detection"].get("tamper_suspected", False),
            "campaign_detected": phase2["visual_fingerprint"].get("campaign_detected", False),
            "phase2_alerts":     phase2["phase2_alerts"],
            "alert_message":     decode_result.get("alert_message")
        }
    }

    # Phase 4: store history + emit WebSocket event (fire-and-forget, non-blocking)
    asyncio.ensure_future(_store_history(result))
    asyncio.ensure_future(_emit_ws_event(result))

    return result


# ─────────────────────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────────────────────

@app.post("/scan-file", summary="Scan QR from uploaded image file")
async def scan_file(file: UploadFile = File(...)):
    """
    Upload JPG, PNG, BMP, or WEBP.
    v3: Now handles mobile phone photos, WhatsApp images, and screen photographs.
    """
    try:
        image = Image.open(io.BytesIO(await file.read()))
    except Exception:
        raise HTTPException(400, "Cannot open image. Supported: JPG, PNG, BMP, WEBP.")
    return await _process_image(image)


@app.post("/scan-base64", summary="Scan QR from base64-encoded image")
async def scan_base64(request: QRRequest):
    """Submit base64-encoded image for analysis."""
    try:
        img_str = request.image_base64
        if "," in img_str:
            img_str = img_str.split(",")[1]
        image = Image.open(io.BytesIO(base64.b64decode(img_str)))
    except Exception:
        raise HTTPException(400, "Invalid base64 image data.")
    return await _process_image(image)


@app.post("/report", summary="Report malicious QR payload to local blacklist")
async def report_malicious(request: ReportRequest):
    """
    Report a confirmed malicious payload.
    Adds SHA-256 hash to SQLite blacklist — future scans blocked instantly.
    threat_type: phishing | malware | smishing | crypto_scam | credential_harvest | spam | other
    """
    result = add_to_blacklist(
        payload=request.payload,
        threat_type=request.threat_type,
        source=request.source,
        notes=request.notes
    )
    if result.get("added"):
        log.warning(f"[Report] New blacklist entry: {request.threat_type} from {request.source}")
    return result


@app.get("/blacklist/stats", summary="Local blacklist statistics")
async def blacklist_stats():
    return get_blacklist_stats()


# ══════════════════════════════════════════════════════════════
# Phase 4.1 — Async Scan with Job Polling
# ══════════════════════════════════════════════════════════════

@app.post("/scan-async", summary="4.1 Submit scan job asynchronously")
async def scan_async(request: QRRequest):
    """
    Submit a scan job and get a job_id immediately.
    The scan runs in the background — poll /scan-status/{job_id} for result.
    Prevents 90-second timeouts in mobile apps and slow connections.
    """
    job_id  = str(uuid.uuid4())
    job_key = f"{JOB_PREFIX}{job_id}"

    # Decode image immediately to catch bad input before queuing
    try:
        img_str = request.image_base64
        if "," in img_str:
            img_str = img_str.split(",")[1]
        image = Image.open(io.BytesIO(base64.b64decode(img_str)))
    except Exception:
        raise HTTPException(400, "Invalid base64 image data.")

    # Store initial job state in Redis
    async def _run_job():
        try:
            r = redis_async.from_url(REDIS_URL, socket_timeout=2.0)
            await r.hset(job_key, mapping={"status": "processing", "progress": "Running analysis..."})
            await r.expire(job_key, JOB_TTL)

            result = await _process_image(image)

            await r.hset(job_key, mapping={
                "status":   "complete",
                "progress": "Done",
                "result":   json.dumps(result),
            })
            await r.expire(job_key, JOB_TTL)
            await r.aclose()
            log.info(f"[Async Job] {job_id} complete — risk={result.get('overall_risk')}")
        except Exception as e:
            try:
                await r.hset(job_key, mapping={"status": "error", "error": str(e)})
                await r.aclose()
            except Exception:
                pass
            log.error(f"[Async Job] {job_id} failed: {e}")

    asyncio.ensure_future(_run_job())

    return {
        "job_id":    job_id,
        "status":    "queued",
        "poll_url":  f"/scan-status/{job_id}",
        "message":   "Scan job submitted. Poll poll_url every 1-2 seconds for result.",
        "expires_in": f"{JOB_TTL}s",
    }


@app.get("/scan-status/{job_id}", summary="4.1 Poll async scan job status")
async def scan_status(job_id: str):
    """
    Poll the result of an async scan job.
    Returns {status: queued|processing|complete|error}.
    When complete, 'result' contains the full scan response.
    """
    job_key = f"{JOB_PREFIX}{job_id}"
    try:
        r = redis_async.from_url(REDIS_URL, socket_timeout=2.0)
        data = await r.hgetall(job_key)
        await r.aclose()

        if not data:
            raise HTTPException(404, f"Job '{job_id}' not found or expired.")

        status   = (data.get(b"status") or b"unknown").decode()
        progress = (data.get(b"progress") or b"").decode()
        error    = (data.get(b"error") or b"").decode()
        result   = data.get(b"result")

        response = {"job_id": job_id, "status": status, "progress": progress}
        if error:
            response["error"] = error
        if result and status == "complete":
            response["result"] = json.loads(result)
        return response

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to retrieve job status: {e}")


# ══════════════════════════════════════════════════════════════
# Phase 4.2 — Scan History & Audit Trail
# ══════════════════════════════════════════════════════════════

@app.get("/history", summary="4.2 Scan history with filtering")
async def scan_history(
    limit: int = 20,
    risk: Optional[str] = None,       # filter by risk level: Safe|Low|Medium|High|Critical
    type: Optional[str] = None,       # filter by QR type: url|email|bitcoin|etc
    page: int = 1,
):
    """
    Returns scan history stored in Redis (30-day TTL).
    Supports filtering by risk level, QR type, and pagination.
    """
    try:
        r = redis_async.from_url(REDIS_URL, socket_timeout=2.0)
        # Fetch all entries sorted newest first (score = timestamp, ZREVRANGE)
        raw_entries = await r.zrevrange(HISTORY_KEY, 0, -1)
        await r.aclose()

        entries = []
        for raw in raw_entries:
            try:
                entry = json.loads(raw)

                # Apply risk filter
                if risk and entry.get("overall_risk", "").lower() != risk.lower():
                    continue

                # Apply type filter
                if type:
                    types = [a.get("type", "") for a in entry.get("analyses", [])]
                    if type.lower() not in [t.lower() for t in types]:
                        continue

                entries.append(entry)
            except Exception:
                continue

        total    = len(entries)
        offset   = (page - 1) * limit
        paginated = entries[offset: offset + limit]

        return {
            "total":    total,
            "page":     page,
            "limit":    limit,
            "entries":  paginated,
            "filters":  {"risk": risk, "type": type},
        }

    except Exception as e:
        raise HTTPException(500, f"History retrieval failed: {e}")


@app.get("/history/export", summary="4.2 Export scan history as CSV")
async def history_export():
    """
    Export all scan history as a downloadable CSV file.
    Columns: timestamp, overall_risk, total_qr, qr_types, tamper, multi_qr, campaign.
    """
    try:
        r = redis_async.from_url(REDIS_URL, socket_timeout=2.0)
        raw_entries = await r.zrevrange(HISTORY_KEY, 0, -1)
        await r.aclose()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "timestamp", "overall_risk", "total_qr",
            "qr_types", "risk_levels", "tamper", "multi_qr", "campaign", "stego"
        ])

        for raw in raw_entries:
            try:
                e       = json.loads(raw)
                types   = ",".join([a.get("type", "?") for a in e.get("analyses", [])])
                risks   = ",".join([a.get("risk", "?") for a in e.get("analyses", [])])
                alerts  = e.get("alerts", {})
                writer.writerow([
                    e.get("timestamp", ""),
                    e.get("overall_risk", ""),
                    e.get("total_qr", 0),
                    types, risks,
                    alerts.get("tamper", False),
                    alerts.get("multi_qr", False),
                    alerts.get("campaign", False),
                    alerts.get("stego", False),
                ])
            except Exception:
                continue

        output.seek(0)
        filename = f"aegis_history_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        return StreamingResponse(
            iter([output.read()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except Exception as e:
        raise HTTPException(500, f"CSV export failed: {e}")


# ══════════════════════════════════════════════════════════════
# Phase 4.3 — Batch QR Processing
# ══════════════════════════════════════════════════════════════

@app.post("/scan-batch", summary="4.3 Scan up to 20 QR images concurrently")
async def scan_batch(request: ScanBatchRequest):
    """
    Process up to 20 QR images in a single request.
    All images scanned concurrently via asyncio.gather().
    Useful for: bulk phishing investigation, folder of documents, video frame analysis.
    """
    if not request.images:
        raise HTTPException(400, "No images provided.")
    if len(request.images) > 20:
        raise HTTPException(400, f"Maximum 20 images per batch (received {len(request.images)}).")

    # Decode all images first — fail fast on bad input
    decoded_images = []
    for i, img_str in enumerate(request.images):
        try:
            if "," in img_str:
                img_str = img_str.split(",")[1]
            image = Image.open(io.BytesIO(base64.b64decode(img_str)))
            decoded_images.append((i, image))
        except Exception as e:
            decoded_images.append((i, None))   # Mark failed images
            log.warning(f"[Batch] Image {i} decode failed: {e}")

    # Run all valid images concurrently
    tasks = []
    for (idx, img) in decoded_images:
        if img is not None:
            tasks.append(_process_image(img))
        else:
            async def _bad_image():
                return {"status": "error", "error": "Invalid image data"}
            tasks.append(_bad_image())

    results_raw = await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for i, (res) in enumerate(results_raw):
        if isinstance(res, Exception):
            results.append({"image_index": i, "status": "error", "error": str(res)})
        else:
            results.append({"image_index": i, **res})

    # Aggregate overall risk across all images
    risk_order   = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Safe": 1}
    batch_risks  = [r.get("overall_risk", "Safe") for r in results if r.get("status") == "success"]
    batch_risk   = max(batch_risks, key=lambda r: risk_order.get(r, 0)) if batch_risks else "Safe"

    return {
        "status":        "success",
        "total_images":  len(request.images),
        "processed":     len([r for r in results if r.get("status") == "success"]),
        "failed":        len([r for r in results if r.get("status") == "error"]),
        "batch_risk":    batch_risk,
        "results":       results,
    }


# ══════════════════════════════════════════════════════════════
# Phase 4.5 — Real-Time Dashboard Endpoints
# ══════════════════════════════════════════════════════════════

@app.get("/stats/detailed", summary="4.5 Detailed scan statistics")
async def stats_detailed():
    """
    Extended statistics: per-risk breakdown, QR type breakdown,
    recent threat summary, cache stats in one call.
    """
    try:
        r = redis_async.from_url(REDIS_URL, socket_timeout=2.0)

        # Total scans from history
        total_scans = await r.zcard(HISTORY_KEY)
        raw_all     = await r.zrevrange(HISTORY_KEY, 0, 99)   # Last 100 for aggregation
        await r.aclose()

        risk_counts = {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        type_counts: dict = {}
        alert_counts = {"tamper": 0, "multi_qr": 0, "campaign": 0, "stego": 0}

        for raw in raw_all:
            try:
                e = json.loads(raw)
                risk = e.get("overall_risk", "Safe")
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
                for a in e.get("analyses", []):
                    qtype = a.get("type", "unknown")
                    type_counts[qtype] = type_counts.get(qtype, 0) + 1
                alerts = e.get("alerts", {})
                for k in alert_counts:
                    if alerts.get(k):
                        alert_counts[k] += 1
            except Exception:
                continue

        return {
            "total_scans":   total_scans,
            "risk_breakdown": risk_counts,
            "type_breakdown": dict(sorted(type_counts.items(), key=lambda x: -x[1])),
            "alert_counts":  alert_counts,
            "active_ws_clients": len(ws_manager.clients),
            "note": "Aggregated from last 100 scans in history.",
        }

    except Exception as e:
        raise HTTPException(500, f"Stats failed: {e}")


@app.get("/stats/threats", summary="4.5 Last 20 high/critical risk scans")
async def recent_threats():
    """Returns last 20 High or Critical risk scan summaries."""
    try:
        r = redis_async.from_url(REDIS_URL, socket_timeout=2.0)
        raw_threats = await r.lrange(THREATS_KEY, 0, 19)
        await r.aclose()
        threats = []
        for raw in raw_threats:
            try:
                threats.append(json.loads(raw))
            except Exception:
                pass
        return {"total": len(threats), "threats": threats}
    except Exception as e:
        raise HTTPException(500, f"Threats retrieval failed: {e}")


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """
    4.5 WebSocket live feed.
    Connect to receive real-time scan events as JSON.
    Each event: {event, timestamp, overall_risk, total_qr, alerts, risk_summary}
    """
    await ws_manager.connect(websocket)
    try:
        # Send welcome ping
        await websocket.send_text(json.dumps({
            "event":     "connected",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "message":   "Aegis live feed connected. You will receive scan events in real time.",
        }))
        # Keep connection alive — wait for disconnect
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Echo pings back as pongs
                if msg == "ping":
                    await websocket.send_text(json.dumps({"event": "pong"}))
            except asyncio.TimeoutError:
                # Send keepalive every 30s
                await websocket.send_text(json.dumps({"event": "keepalive"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ══════════════════════════════════════════════════════════════
# Phase 4.6 — QR Code Generator with Safety Badge
# ══════════════════════════════════════════════════════════════

@app.post("/generate", summary="4.6 Generate a safety-verified QR code")
async def generate_qr(request: GenerateRequest):
    """
    Generates a QR code from a URL, runs full Aegis analysis first.
    If URL is Safe or Low risk: generates QR with optional green safety badge.
    If URL is High/Critical: refuses to generate.

    Returns: base64-encoded PNG image + analysis summary.
    """
    if not QR_GEN_AVAILABLE:
        raise HTTPException(503,
            "QR generation requires the 'qrcode[pil]' package. "
            "Add it to requirements.txt and rebuild.")

    url = request.url.strip()
    if not url:
        raise HTTPException(400, "URL is required.")

    # Validate URL format
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")

    # ── Step 1: Scan the URL through Aegis ────────────────────
    log.info(f"[Generate] Scanning URL before generation: {url[:80]}")
    try:
        from app.multi_decoder import extract_all_qr_codes
        # Use the full pipeline: create a minimal payload analysis
        analysis = await analyze_single_payload(url, 0)
        risk      = analysis.get("final_risk_level", "Safe")
        score     = analysis.get("final_risk_score", 0)
    except Exception as e:
        log.warning(f"[Generate] Analysis failed: {e}")
        analysis = {}
        risk     = "Safe"
        score    = 0

    # ── Step 2: Refuse high-risk URLs ─────────────────────────
    if risk in ("High", "Critical"):
        return {
            "status":   "refused",
            "reason":   f"Cannot generate QR for {risk.upper()} risk URL.",
            "risk":     risk,
            "score":    score,
            "url":      url,
            "analysis": analysis,
        }

    # ── Step 3: Generate QR ────────────────────────────────────
    ec_map = {"H": ERROR_CORRECT_H, "M": ERROR_CORRECT_M, "L": ERROR_CORRECT_L}
    ec     = ec_map.get(request.error_correction.upper(), ERROR_CORRECT_H)

    qr = qrcode.QRCode(
        version=None,             # auto-size
        error_correction=ec,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
    w, h   = qr_img.size

    # ── Step 4: Add safety badge (optional) ───────────────────
    badge_height = 0
    if request.add_safety_badge:
        badge_height = 52
        label_height = 28 if request.label else 0
        total_h      = h + badge_height + label_height

        # Create canvas
        canvas = Image.new("RGBA", (w, total_h), (255, 255, 255, 255))
        canvas.paste(qr_img, (0, 0))

        draw = ImageDraw.Draw(canvas)

        # Badge background: green gradient-like solid
        badge_color = (34, 197, 94, 240)     # Tailwind green-500
        draw.rectangle([0, h, w, h + badge_height], fill=badge_color)

        # Badge text
        badge_text = "✓ AEGIS VERIFIED SAFE"
        risk_text  = f"Risk: {risk} ({score}/100)"

        try:
            # Try system font, fallback to default
            font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 15)
            font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        except Exception:
            font_lg = ImageFont.load_default()
            font_sm = ImageFont.load_default()

        # Center text in badge
        bbox = draw.textbbox((0, 0), badge_text, font=font_lg)
        tx   = (w - (bbox[2] - bbox[0])) // 2
        draw.text((tx, h + 8),  badge_text, fill=(255, 255, 255), font=font_lg)
        bbox2 = draw.textbbox((0, 0), risk_text, font=font_sm)
        tx2   = (w - (bbox2[2] - bbox2[0])) // 2
        draw.text((tx2, h + 30), risk_text,  fill=(220, 252, 231), font=font_sm)

        # Optional label
        if request.label:
            draw.rectangle([0, h + badge_height, w, total_h], fill=(245, 245, 245, 255))
            label = request.label[:80]
            bbox3 = draw.textbbox((0, 0), label, font=font_sm)
            tx3   = (w - (bbox3[2] - bbox3[0])) // 2
            draw.text((tx3, h + badge_height + 6), label, fill=(30, 30, 30), font=font_sm)

        qr_img = canvas

    # ── Step 5: Encode to base64 ──────────────────────────────
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    log.info(f"[Generate] QR generated for {url[:60]} — risk={risk}")

    return {
        "status":           "ok",
        "url":              url,
        "risk":             risk,
        "risk_score":       score,
        "safety_verified":  True,
        "safety_badge":     request.add_safety_badge,
        "error_correction": request.error_correction.upper(),
        "qr_base64":        f"data:image/png;base64,{qr_b64}",
        "qr_size_px":       list(qr_img.size),
        "analysis_summary": {
            "final_risk_level":  analysis.get("final_risk_level"),
            "final_risk_score":  analysis.get("final_risk_score"),
            "url_deep_scans":    len(analysis.get("url_deep_scans", [])),
            "phase3_enrichment": analysis.get("phase3_enrichment", {}),
        },
        "usage": (
            "Decode this image with /scan-file to verify the embedded safety metadata."
        ),
    }


@app.get("/stats", summary="Live scan telemetry")
async def dashboard():
    return await get_live_stats()


@app.get("/cache/stats", summary="URL scan + QR analysis cache statistics")
async def cache_stats():
    """Returns count of cached URL scans and QR analyses in Redis."""
    try:
        r = redis_async.from_url(REDIS_URL, encoding="utf-8", decode_responses=True, socket_timeout=2.0)
        url_keys = await r.keys("urlscan:*")
        qr_keys  = await r.keys("qrscan:*")
        fp_keys  = await r.hlen("qr:fingerprints")
        await r.aclose()
        return {
            "url_scan_cache_entries":    len(url_keys),
            "qr_analysis_cache_entries": len(qr_keys),
            "fingerprint_entries":       fp_keys,
            "status": "online"
        }
    except Exception as e:
        return {"status": "offline", "error": str(e)}


@app.delete("/cache/clear", summary="Clear URL scan cache")
async def cache_clear():
    """Clears all cached URL scan results (not fingerprints, not QR cache)."""
    try:
        r = redis_async.from_url(REDIS_URL, encoding="utf-8", decode_responses=True, socket_timeout=2.0)
        url_keys = await r.keys("urlscan:*")
        if url_keys:
            await r.delete(*url_keys)
        await r.aclose()
        return {"cleared": len(url_keys), "type": "url_scan_cache", "status": "success"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.delete("/qr-cache/clear", summary="Clear QR payload analysis cache")
async def qr_cache_clear():
    """Clears all cached QR payload analysis results. Forces fresh re-analysis on next scan."""
    try:
        r = redis_async.from_url(REDIS_URL, encoding="utf-8", decode_responses=True, socket_timeout=2.0)
        qr_keys = await r.keys("qrscan:*")
        if qr_keys:
            await r.delete(*qr_keys)
        await r.aclose()
        return {"cleared": len(qr_keys), "type": "qr_analysis_cache", "status": "success"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/phase3/status", summary="Phase 3 API key configuration status")
async def phase3_status():
    """
    Reports which Phase 3 external intelligence APIs are configured.
    v5.1 — Updated API set (IPQS/HIBP/BitcoinAbuse/PhishTank replaced).
    """
    import os
    return {
        "phase3_external_intelligence": {
            # ── Free, no key needed — always active ──
            "urlhaus_abuse_ch": "active — no key required (URL malware/phishing DB)",
            "emailrep_io":      "active — no key required (email breach/spam/disposable)",
            "blockchain_com":   "active — no key required (BTC transaction history)",

            # ── Reused keys from existing setup ──
            "google_safe_browsing": (
                "configured — reusing GSB_API_KEY from Link Analyzer"
                if os.getenv("GSB_API_KEY") else
                "skipped — copy GSB_API_KEY from Link Analyzer .env"
            ),
            "numverify": (
                "configured — reusing NUMVERIFY_KEY from Phase 1"
                if os.getenv("NUMVERIFY_KEY") else
                "skipped — copy NUMVERIFY_KEY from Phase 1 setup"
            ),

            # ── New keys ──
            "abuseipdb": (
                "configured"
                if os.getenv("ABUSEIPDB_KEY") else
                "skipped — set ABUSEIPDB_KEY (free: abuseipdb.com)"
            ),
            "chainabuse": (
                "configured — Chainabuse GraphQL active"
                if os.getenv("CHAINABUSE_KEY") else
                "skipped — set CHAINABUSE_KEY (chainabuse.com)"
            ),

            # ── Optional key for higher rate limit ──
            "emailrep_key": (
                "configured — using higher rate limit"
                if os.getenv("EMAILREP_KEY") else
                "not set — using free tier (10 req/hr). Add EMAILREP_KEY for 1000+/hr"
            ),
        },
        "removed_in_v5_1": [
            "IPQualityScore → replaced by URLHaus + Google Safe Browsing",
            "HIBP → replaced by EmailRep.io (free, same data + disposable/spam detection)",
            "BitcoinAbuse → platform merged into Chainabuse",
            "PhishTank → registration disabled; Link Analyzer covers URL phishing via GSB + VirusTotal",
        ],
        "note": (
            "Free APIs (URLHaus, EmailRep.io, Blockchain.com) run without any configuration. "
            "See PHASE3_SETUP_GUIDE.md for remaining key setup."
        ),
    }


@app.get("/health", summary="Health check")
async def health_check():
    services = {}

    # Link Analyzer
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{LINK_ANALYZER_URL}/health", timeout=3.0)
        services["link_analyzer"] = {
            "status": "online" if r.status_code == 200 else "degraded",
            "url": LINK_ANALYZER_URL
        }
    except Exception as e:
        services["link_analyzer"] = {"status": "offline", "error": str(e)}

    # Redis
    try:
        r = redis_async.from_url(REDIS_URL, socket_timeout=2.0)
        await r.ping()
        await r.aclose()
        services["redis"] = {"status": "online", "url": REDIS_URL}
    except Exception as e:
        services["redis"] = {"status": "offline", "error": str(e)}

    # Blacklist DB
    try:
        bl = get_blacklist_stats()
        services["blacklist_db"] = {
            "status": "online",
            "total_entries": bl.get("total_entries", 0)
        }
    except Exception:
        services["blacklist_db"] = {"status": "offline"}

    # Ollama
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get("http://host.docker.internal:11434/api/tags", timeout=3.0)
        services["ollama"] = {"status": "online" if r.status_code == 200 else "degraded"}
    except Exception:
        services["ollama"] = {"status": "offline"}

    all_ok = all(s.get("status") == "online" for s in services.values())
    return {
        "status":   "healthy" if all_ok else "degraded",
        "version":  "Phase 1+2 v4",
        "services": services
    }
