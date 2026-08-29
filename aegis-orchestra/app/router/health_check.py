"""app/router/health_check.py — Startup connectivity diagnostics.

Called on startup to verify all 4 modules are reachable from inside
the orchestra Docker container. Logs clear actionable messages if any
module is unreachable.
"""
from __future__ import annotations

import logging
import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


async def check_all_modules() -> dict[str, bool]:
    """Check connectivity to all 4 modules. Returns {name: reachable}."""
    modules = {
        "Link Analyzer":       settings.link_analyzer_url,
        "QR Scanner":          settings.qr_scanner_url,
        "Credential Analyzer": settings.credential_analyzer_url,
        "Profile Analyzer":    settings.profile_analyzer_url,
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
                    logger.warning("⚠️  %-22s returned HTTP %d at %s", name, r.status_code, url)
            except httpx.ConnectError:
                results[name] = False
                logger.error(
                    "❌ %-22s UNREACHABLE at %s\n"
                    "   Fix: make sure the module is running and its port is exposed.\n"
                    "   If it's in Docker, ensure ports: - '%s' is in its docker-compose.\n"
                    "   On Linux: add 'extra_hosts: host.docker.internal:host-gateway' to orchestra.",
                    name, url, url.split(":")[-1]
                )
            except Exception as e:
                results[name] = False
                logger.error("❌ %-22s error: %s", name, e)
    return results
