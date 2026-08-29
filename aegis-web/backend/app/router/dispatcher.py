"""app/router/dispatcher.py — HTTP client for microservices.

Matches services.dispatcher but for router module.
"""

import httpx
import logging
from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(30.0, connect=3.0)

async def _post(service: str, path: str, json_data: dict = None, files: dict = None) -> dict | None:
    base_map = {
        "link":       settings.link_analyzer_url,
        "qr":         settings.qr_scanner_url,
        "credential": settings.credential_analyzer_url,
        "profile":    settings.profile_analyzer_url,
        "deepfake":   settings.deepfake_service_url,
    }
    key_map = {
        "credential": settings.credential_api_key,
        "profile":    settings.profile_api_key,
        "qr":         settings.qr_api_key,
        "link":       settings.link_api_key,
    }
    base = base_map.get(service)
    if not base:
        return None
    url = f"{base}{path}"
    headers = {}
    api_key = key_map.get(service)
    if api_key:
        headers["X-API-Key"] = api_key
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            if files:
                r = await client.post(url, files=files, headers=headers)
            else:
                r = await client.post(url, json=json_data, headers=headers)
            if r.status_code == 200:
                return r.json()
            logger.warning("%s %s -> HTTP %d", service, path, r.status_code)
    except httpx.ConnectError:
        logger.debug("Service %s offline at %s", service, url)
    except Exception as e:
        logger.error("Service %s error: %s", service, e)
    return None

# ── Link module ──────────────────────────────────────────────
async def link_scan(url: str) -> dict | None:
    return await _post("link", "/scan", json_data={"url": url})

async def link_bulk_scan(urls: list) -> dict | None:
    return await _post("link", "/bulk", json_data={"urls": urls})

async def link_async_submit(url: str) -> dict | None:
    return await _post("link", "/async/scan", json_data={"url": url})

async def link_async_status(job_id: str) -> dict | None:
    return await _post("link", "/async/status", json_data={"job_id": job_id})

# ── QR module ─────────────────────────────────────────────────
async def qr_scan_base64(b64: str) -> dict | None:
    return await _post("qr", "/scan-base64", json_data={"image_base64": b64})

async def qr_generate(url: str) -> dict | None:
    return await _post("qr", "/generate", json_data={"url": url})

# ── Credential module ────────────────────────────────────────
async def cred_analyze_email(email: str) -> dict | None:
    return await _post("credential", "/analyze/email", json_data={"value": email})

async def cred_analyze_password(password: str, email: str = "", username: str = "") -> dict | None:
    return await _post("credential", "/analyze/password", json_data={"value": password, "email": email, "username": username})

async def cred_analyze_card(card: str) -> dict | None:
    return await _post("credential", "/analyze/card", json_data={"value": card})

async def cred_analyze_national_id(value: str, id_type: str = "cnic") -> dict | None:
    return await _post("credential", "/analyze/national-id", json_data={"value": value, "type": id_type})

async def cred_analyze_passport(line1: str, line2: str) -> dict | None:
    return await _post("credential", "/analyze/passport", json_data={"line1": line1, "line2": line2})

async def cred_analyze_iban(iban: str) -> dict | None:
    return await _post("credential", "/analyze/iban", json_data={"value": iban})

async def cred_analyze_crypto(address: str) -> dict | None:
    return await _post("credential", "/analyze/crypto", json_data={"value": address})

async def cred_analyze_phone(phone: str) -> dict | None:
    return await _post("credential", "/analyze/phone", json_data={"value": phone})

async def cred_analyze_phone_advanced(phone: str) -> dict | None:
    return await _post("credential", "/analyze/phone-advanced", json_data={"value": phone})

async def cred_analyze_username(username: str) -> dict | None:
    return await _post("credential", "/analyze/username", json_data={"value": username})

async def cred_analyze_api_key(key: str) -> dict | None:
    return await _post("credential", "/analyze/api-key", json_data={"value": key})

async def cred_detect(value: str) -> dict | None:
    return await _post("credential", "/detect", json_data={"value": value})

# ── Profile module ────────────────────────────────────────────
async def profile_analyze(data: dict) -> dict | None:
    return await _post("profile", "/analyze/profile", json_data=data)

# ── Deepfake module ───────────────────────────────────────────
async def analyze_image_bytes(bytes_data: bytes) -> dict | None:
    return await _post("deepfake", "/analyze/image", files={"file": ("image.jpg", bytes_data, "image/jpeg")})

async def analyze_video_bytes(bytes_data: bytes) -> dict | None:
    return await _post("deepfake", "/analyze/video", files={"file": ("video.mp4", bytes_data, "video/mp4")})

async def analyze_image_url(url: str) -> dict | None:
    return await _post("deepfake", "/analyze/image-url", json_data={"url": url})

async def deepfake_health() -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{settings.deepfake_service_url}/health")
            return r.status_code == 200
    except Exception:
        return False