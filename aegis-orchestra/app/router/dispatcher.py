"""app/router/dispatcher.py — HTTP client for all 4 microservices.

Each call_* function:
  • Makes an async HTTP call to the right microservice
  • Returns raw JSON dict on success
  • Returns {"error": "...", "module_unavailable": True} on failure
  • Handles timeouts gracefully (module down = don't crash bot)
"""
from __future__ import annotations

import base64
import logging
from typing import Any, Optional

import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(100.0, connect=10.0)  # 90s for VT polling


def _client(headers: dict = None) -> httpx.AsyncClient:
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    return httpx.AsyncClient(timeout=_TIMEOUT, headers=h)


def _headers_for(url: str) -> dict:
    """Return auth headers required for a given module URL."""
    h = {}
    if settings.credential_api_key and settings.credential_analyzer_url in url:
        h["X-API-Key"] = settings.credential_api_key
    if settings.profile_api_key and settings.profile_analyzer_url in url:
        h["X-API-Key"] = settings.profile_api_key
    if settings.qr_api_key and settings.qr_scanner_url in url:
        h["X-API-Key"] = settings.qr_api_key
    if settings.link_api_key and settings.link_analyzer_url in url:
        h["X-API-Key"] = settings.link_api_key
    return h


async def _post(url: str, payload: dict) -> dict:
    try:
        async with _client(_headers_for(url)) as c:
            r = await c.post(url, json=payload)
            if r.status_code == 401:
                logger.error(f"Auth failed for {url} — check API key in config")
                return {"error": "Auth failed (401) — wrong API key", "module_unavailable": True}
            if r.status_code == 429:
                return {"error": "Rate limit exceeded", "status_code": 429}
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        logger.error(f"Connection refused: {url}")
        return {"error": f"Service unavailable: {url}", "module_unavailable": True}
    except httpx.TimeoutException:
        logger.error(f"Timeout: {url}")
        return {"error": "Service timeout", "module_unavailable": True}
    except Exception as e:
        logger.error(f"POST {url} error: {e}")
        return {"error": str(e), "module_unavailable": True}


async def _get(url: str, params: dict = None) -> dict:
    try:
        async with _client(_headers_for(url)) as c:
            r = await c.get(url, params=params or {})
            if r.status_code == 401:
                logger.error(f"Auth failed for {url} — check API key in config")
                return {"error": "Auth failed (401) — wrong API key", "module_unavailable": True}
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.error(f"GET {url} error: {e}")
        return {"error": str(e), "module_unavailable": True}


# ══════════════════════════════════════════════════════════════════════════════
# LINK ANALYZER  (port 8000)
# ══════════════════════════════════════════════════════════════════════════════

async def link_scan(url: str) -> dict:
    """POST /scan — single URL, full 11-layer analysis."""
    return await _post(f"{settings.link_analyzer_url}/scan", {"url": url})


async def link_bulk_scan(urls: list[str]) -> dict:
    """POST /scan/bulk — up to 10 URLs concurrently."""
    return await _post(f"{settings.link_analyzer_url}/scan/bulk", {"urls": urls[:10]})


async def link_async_submit(url: str) -> dict:
    """POST /scan/async — submit for background scan."""
    return await _post(f"{settings.link_analyzer_url}/scan/async", {"url": url})


async def link_async_status(job_id: str) -> dict:
    """GET /scan/status/{job_id} — poll async scan result."""
    return await _get(f"{settings.link_analyzer_url}/scan/status/{job_id}")


# ══════════════════════════════════════════════════════════════════════════════
# QR SCANNER  (port 8001)
# ══════════════════════════════════════════════════════════════════════════════

async def qr_scan_base64(image_b64: str) -> dict:
    """POST /scan-base64 — scan QR from base64 image."""
    return await _post(f"{settings.qr_scanner_url}/scan-base64", {"image_base64": image_b64})


async def qr_scan_batch(images_b64: list[str]) -> dict:
    """POST /scan-batch — up to 20 images."""
    return await _post(
        f"{settings.qr_scanner_url}/scan-batch",
        {"images": [{"image_base64": b} for b in images_b64]},
    )


async def qr_generate(url: str) -> dict:
    """POST /generate — generate safety-verified QR."""
    return await _post(f"{settings.qr_scanner_url}/generate", {"url": url})


async def qr_async_submit(image_b64: str) -> dict:
    """POST /scan-async — async QR scan."""
    return await _post(f"{settings.qr_scanner_url}/scan-async", {"image_base64": image_b64})


async def qr_async_status(job_id: str) -> dict:
    """GET /scan-status/{job_id} — poll async QR result."""
    return await _get(f"{settings.qr_scanner_url}/scan-status/{job_id}")


# ══════════════════════════════════════════════════════════════════════════════
# CREDENTIAL ANALYZER  (port 8002)
# ══════════════════════════════════════════════════════════════════════════════

_CRED_BASE = lambda p: f"{settings.credential_analyzer_url}{p}"

async def cred_analyze_email(email: str) -> dict:
    return await _post(_CRED_BASE("/analyze/email"), {"value": email})

async def cred_analyze_password(password: str, email: str = "", username: str = "") -> dict:
    payload: dict = {"value": password}
    if email:    payload["email"] = email
    if username: payload["username"] = username
    return await _post(_CRED_BASE("/analyze/password"), payload)

async def cred_analyze_username(username: str) -> dict:
    return await _post(_CRED_BASE("/analyze/username"), {"value": username})

async def cred_analyze_card(number: str, expiry_month: str = "", expiry_year: str = "", cvv: str = "") -> dict:
    payload: dict = {"number": number}
    if expiry_month: payload["expiry_month"] = expiry_month
    if expiry_year:  payload["expiry_year"] = expiry_year
    if cvv:          payload["cvv"] = cvv
    return await _post(_CRED_BASE("/analyze/card"), payload)

async def cred_analyze_iban(iban: str, swift: str = "") -> dict:
    payload: dict = {"iban": iban}
    if swift: payload["swift"] = swift
    return await _post(_CRED_BASE("/analyze/iban"), payload)

async def cred_analyze_crypto(address: str) -> dict:
    return await _post(_CRED_BASE("/analyze/crypto"), {"value": address})

async def cred_analyze_national_id(value: str, id_type: str = "auto") -> dict:
    return await _post(
        _CRED_BASE("/analyze/national-id"),
        {"value": value, "id_type": id_type}   # ✅ use "value", not "national_id"
    )
async def cred_analyze_passport(mrz_line1: str, mrz_line2: str) -> dict:
    return await _post(_CRED_BASE("/analyze/passport"), {
        "mrz_line1": mrz_line1,
        "mrz_line2": mrz_line2,
    })

async def cred_analyze_phone(phone: str) -> dict:
    return await _post(_CRED_BASE("/analyze/phone"), {"value": phone})

async def cred_analyze_phone_advanced(phone: str, sms_body: str = "", carrier: str = "") -> dict:
    payload: dict = {"value": phone}
    if sms_body: payload["sms_body"] = sms_body
    if carrier:  payload["carrier"] = carrier
    return await _post(_CRED_BASE("/analyze/phone/advanced"), payload)


async def enrich_phone_external(phone: str) -> dict:
    """
    Enhanced phone enrichment layer — runs Numverify + AbstractAPI in parallel.
    Returns merged dict with extra fields merged into credential result.
    Falls back gracefully if API keys not set or calls fail.
    """
    import os, asyncio as _asyncio
    results: dict = {}

    async def _numverify(ph: str) -> dict:
        key = os.getenv("NUMVERIFY_API_KEY", "")
        if not key:
            return {}
        try:
            url = f"https://apilayer.net/api/validate?access_key={key}&number={ph}&format=1"
            resp = await _get_json(url, timeout=5)
            if resp.get("valid"):
                return {
                    "nv_carrier":       resp.get("carrier",""),
                    "nv_line_type":     resp.get("line_type",""),
                    "nv_location":      resp.get("location",""),
                    "nv_country_name":  resp.get("country_name",""),
                    "nv_country_code":  resp.get("country_code",""),
                    "nv_international": resp.get("international_format",""),
                }
        except Exception:
            pass
        return {}

    async def _abstractapi(ph: str) -> dict:
        key = os.getenv("ABSTRACTAPI_PHONE_KEY", "")
        if not key:
            return {}
        try:
            url = f"https://phonevalidation.abstractapi.com/v1/?api_key={key}&phone={ph}"
            resp = await _get_json(url, timeout=5)
            if resp.get("valid"):
                return {
                    "ab_carrier":     (resp.get("carrier") or {}).get("name",""),
                    "ab_line_type":   (resp.get("type") or ""),
                    "ab_country":     (resp.get("country") or {}).get("name",""),
                    "ab_local":       resp.get("local_format",""),
                }
        except Exception:
            pass
        return {}

    nv, ab = await _asyncio.gather(_numverify(phone), _abstractapi(phone), return_exceptions=True)
    if isinstance(nv, Exception): nv = {}
    if isinstance(ab, Exception): ab = {}
    results.update(nv or {})
    results.update(ab or {})
    return results


async def enrich_email_external(email: str) -> dict:
    """
    Enhanced email enrichment layer — runs Hunter.io + mailboxlayer in parallel.
    Returns merged dict with extra fields for scam/leak context.
    Falls back gracefully if API keys not set or calls fail.
    """
    import os, asyncio as _asyncio
    results: dict = {}

    async def _hunterio(em: str) -> dict:
        key = os.getenv("HUNTER_IO_API_KEY", "")
        if not key:
            return {}
        try:
            domain = em.split("@")[-1]
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}&limit=1"
            resp = await _get_json(url, timeout=5)
            data = resp.get("data", {})
            return {
                "hunter_organization": data.get("organization",""),
                "hunter_disposable":   data.get("disposable", False),
                "hunter_webmail":      data.get("webmail", False),
                "hunter_mx_records":   bool(data.get("emails",[])),
                "hunter_domain_type":  data.get("type",""),
            }
        except Exception:
            pass
        return {}

    async def _mailboxlayer(em: str) -> dict:
        key = os.getenv("MAILBOXLAYER_API_KEY", "")
        if not key:
            return {}
        try:
            url = f"https://apilayer.net/api/check?access_key={key}&email={em}&smtp=1&format=1"
            resp = await _get_json(url, timeout=5)
            return {
                "ml_format_valid":   resp.get("format_valid", False),
                "ml_mx_found":       resp.get("mx_found", False),
                "ml_smtp_check":     resp.get("smtp_check", False),
                "ml_disposable":     resp.get("disposable", False),
                "ml_role":           resp.get("role", False),
                "ml_free":           resp.get("free", False),
                "ml_score":          resp.get("score", 0),
            }
        except Exception:
            pass
        return {}

    hunter, ml = await _asyncio.gather(_hunterio(email), _mailboxlayer(email), return_exceptions=True)
    if isinstance(hunter, Exception): hunter = {}
    if isinstance(ml, Exception): ml = {}
    results.update(hunter or {})
    results.update(ml or {})
    return results


async def _get_json(url: str, timeout: int = 8) -> dict:
    """Simple GET helper for external enrichment APIs."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {}

async def cred_analyze_api_key(value: str) -> dict:
    return await _post(_CRED_BASE("/analyze/api-key"), {"value": value})

async def cred_detect(value: str) -> dict:
    return await _post(_CRED_BASE("/detect"), {"value": value})

async def cred_scan_text(text: str) -> dict:
    return await _post(_CRED_BASE("/scan"), {"text": text})

async def cred_bulk(items: list[dict]) -> dict:
    return await _post(_CRED_BASE("/analyze/bulk"), {"items": items[:50]})


# ══════════════════════════════════════════════════════════════════════════════
# PROFILE ANALYZER  (port 8003)
# ══════════════════════════════════════════════════════════════════════════════

async def profile_analyze(profile_data: dict) -> dict:
    """POST /analyze/profile — full 4-block analysis."""
    # Ensure run_ollama=False for fast Phase 1 response
    profile_data.setdefault("run_ollama", False)
    profile_data.setdefault("run_vision", False)
    profile_data.setdefault("run_sklearn", True)
    profile_data.setdefault("run_osint", True)
    return await _post(f"{settings.profile_analyzer_url}/analyze/profile", profile_data)

async def profile_analyze_username(username: str) -> dict:
    """POST /analyze/username — quick username check."""
    return await _post(
        f"{settings.profile_analyzer_url}/analyze/username",
        {"username": username},
    )
