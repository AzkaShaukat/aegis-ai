"""app/router/health_check.py — Startup connectivity diagnostics.

Copied from WhatsApp project — added Deepfake service.
"""
from __future__ import annotations

import logging
import httpx

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


async def check_all_modules() -> dict[str, bool]:
    """Check connectivity to all microservices. Returns {name: reachable}."""
    modules = {
        "Link Analyzer":       settings.link_analyzer_url,
        "QR Scanner":          settings.qr_scanner_url,
        "Credential Analyzer": settings.credential_analyzer_url,
        "Profile Analyzer":    settings.profile_analyzer_url,
        "Deepfake Detector":   settings.deepfake_service_url,
    }
    results = {}
    async with httpx.AsyncClient(timeout=httpx.Timeout(4.0)) as client:
        for name, url in modules.items():
            try:
                r = await client.get(f"{url}/health")
                ok = r.status_code == 200
                results[name] = ok
                if ok:
                    logger.info("✅ %-22s reachable at %s", name, url)
                else:
                    logger.warning("⚠️  %-22s returned HTTP %d", name, r.status_code)
            except httpx.ConnectError:
                results[name] = False
                logger.warning("❌ %-22s UNREACHABLE at %s", name, url)
            except Exception as e:
                results[name] = False
                logger.error("❌ %-22s error: %s", name, e)
    return results