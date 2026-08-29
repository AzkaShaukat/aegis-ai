"""
urlhaus_check.py
Aegis Link Analyzer

URLhaus malware URL database lookup via abuse.ch API.
Requires URLHAUS_API_KEY from .env (free registration at auth.abuse.ch).

Status scoring:
  "online"  → 100 (confirmed active malware)
  "offline" → 60  (was malware, now taken down)
  "unknown" → 0   (inconclusive — no score applied)
  not_found → 0   (clean)
"""

import httpx
import os
from typing import Dict
from urllib.parse import urlparse

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"


async def run_urlhaus_check(url: str) -> Dict:
    flags = []
    api_key = os.getenv("URLHAUS_API_KEY", "")

    # Parse hostname for domain-level check
    try:
        hostname = urlparse(url).netloc.lower().split(":")[0]
        if "@" in hostname:
            hostname = hostname.split("@")[-1]
    except Exception:
        hostname = ""

    # Reject obviously malformed/non-URL inputs before sending to API
    if not hostname or len(hostname) < 3 or " " in hostname or \
       not any(c.isalpha() for c in hostname):
        return {
            "found": False,
            "status": "skipped",
            "threat": None,
            "tags": [],
            "date_added": None,
            "reporter": None,
            "urlhaus_url": None,
            "flags": ["URLhaus check skipped — invalid hostname"],
            "urlhaus_score": 0,
            "is_suspicious": False,
        }

    headers = {}
    if api_key:
        headers["Auth-Key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                URLHAUS_API,
                data={"url": url},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

    except httpx.HTTPStatusError as e:
        return {
            "found": False, "status": "api_error",
            "threat": None, "tags": [], "date_added": None,
            "reporter": None, "urlhaus_url": None,
            "flags": [f"URLhaus API error: HTTP {e.response.status_code}"],
            "urlhaus_score": 0, "is_suspicious": False,
        }
    except Exception as e:
        return {
            "found": False, "status": "api_error",
            "threat": None, "tags": [], "date_added": None,
            "reporter": None, "urlhaus_url": None,
            "flags": [f"URLhaus check failed: {type(e).__name__}"],
            "urlhaus_score": 0, "is_suspicious": False,
        }

    query_status = data.get("query_status", "")

    # ── URL not in database ─────────────────────────────────────────────────
    if query_status in ("no_results", "not_found"):
        return {
            "found": False,
            "status": "not_found",
            "threat": None,
            "tags": [],
            "date_added": None,
            "reporter": None,
            "urlhaus_url": None,
            "flags": [],
            "urlhaus_score": 0,
            "is_suspicious": False,
        }

    # ── URL found ───────────────────────────────────────────────────────────
    if query_status == "is_url":
        url_status = data.get("url_status", "unknown").lower()
        threat     = data.get("threat", None)
        tags       = data.get("tags") or []
        date_added = data.get("date_added", None)
        urlhaus_url = data.get("urlhaus_reference", None)
        reporter   = data.get("reporter", None)

        # ── Score by status ─────────────────────────────────────────────────
        # IMPORTANT: "unknown" status = inconclusive hit.
        # URLhaus returns "unknown" for URLs it has in its DB but hasn't
        # confirmed recently (often malformed or redirected URLs).
        # We do NOT treat this as suspicious because it causes false positives
        # on garbage input like "not_a_url!!@#$".
        if url_status == "online":
            score = 100
            is_suspicious = True
            threat_str = f", threat: {threat}" if threat else ""
            flags.append(
                f"🚨 MALWARE URL: Confirmed active in URLhaus database "
                f"(status: online{threat_str})"
            )
        elif url_status == "offline":
            score = 60
            is_suspicious = True
            threat_str = f", threat: {threat}" if threat else ""
            flags.append(
                f"⚠️ Previously active malware URL: now offline in URLhaus "
                f"(status: offline{threat_str})"
            )
        elif url_status == "unknown":
            # Inconclusive — do NOT score as suspicious
            score = 0
            is_suspicious = False
            # No flag added — "unknown" is noise, not a confirmed threat
        else:
            score = 30
            is_suspicious = False
            flags.append(
                f"URLhaus: URL recorded (status: {url_status})"
            )

        return {
            "found": True,
            "status": url_status,
            "threat": threat,
            "tags": tags,
            "date_added": date_added,
            "reporter": reporter,
            "urlhaus_url": urlhaus_url,
            "flags": flags,
            "urlhaus_score": score,
            "is_suspicious": is_suspicious,
        }

    # ── Unexpected query status ─────────────────────────────────────────────
    return {
        "found": False,
        "status": query_status,
        "threat": None,
        "tags": [],
        "date_added": None,
        "reporter": None,
        "urlhaus_url": None,
        "flags": [],
        "urlhaus_score": 0,
        "is_suspicious": False,
    }
