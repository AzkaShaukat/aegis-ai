"""
Feature 8 — Google Safe Browsing API
Aegis Link Analyzer | Phase 2

Google Safe Browsing is Google's continuously updated threat database.
Checks URLs against: MALWARE, SOCIAL_ENGINEERING (phishing), UNWANTED_SOFTWARE,
POTENTIALLY_HARMFUL_APPLICATION threats.

Free: up to 10,000 requests/day on free Google Cloud key.
API Key Setup: console.cloud.google.com → Enable "Safe Browsing API" → Create Key
(No billing required for Safe Browsing API specifically)

API docs: https://developers.google.com/safe-browsing/v4/lookup-api
"""

import httpx
import os
from typing import Dict, List
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

GSB_API_KEY = os.getenv("GSB_API_KEY", "")
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Google's threat type codes → human-readable labels
THREAT_TYPE_LABELS = {
    "MALWARE": "Malware Distribution",
    "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
    "UNWANTED_SOFTWARE": "Unwanted Software",
    "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful Application",
}

# Severity mapping — used to set score
THREAT_SEVERITY = {
    "MALWARE": 100,
    "SOCIAL_ENGINEERING": 100,
    "UNWANTED_SOFTWARE": 75,
    "POTENTIALLY_HARMFUL_APPLICATION": 80,
}


# ─────────────────────────────────────────────
# MAIN ASYNC RUNNER
# ─────────────────────────────────────────────

async def run_gsb_check(url: str) -> Dict:
    """
    Queries Google Safe Browsing Lookup API v4 for the given URL.

    Checks against all 4 threat lists simultaneously.
    Returns immediately — no polling.

    Returns:
        dict with:
          - found: True if URL matches any GSB threat list
          - threats: list of detected threat types
          - flags: list of warning strings
          - gsb_score: 0-100 risk score
          - is_suspicious: True if any threats found
          - api_available: False if GSB_API_KEY not configured
    """
    flags: List[str] = []
    score: int = 0

    # ── Check API key is configured ──────────────────
    if not GSB_API_KEY:
        return {
            "found": False,
            "threats": [],
            "flags": [
                "Google Safe Browsing check skipped — "
                "add GSB_API_KEY to .env "
                "(free at console.cloud.google.com)"
            ],
            "gsb_score": 0,
            "is_suspicious": False,
            "api_available": False
        }

    # ── Build the v4 API request body ────────────────
    request_body = {
        "client": {
            "clientId": "aegis-link-analyzer",
            "clientVersion": "2.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{GSB_API_URL}?key={GSB_API_KEY}",
                json=request_body,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 400:
                return {
                    "found": False,
                    "threats": [],
                    "flags": ["GSB API key invalid or malformed request — check GSB_API_KEY in .env"],
                    "gsb_score": 0,
                    "is_suspicious": False,
                    "api_available": True
                }

            if response.status_code == 403:
                return {
                    "found": False,
                    "threats": [],
                    "flags": ["GSB API key doesn't have Safe Browsing API enabled in Google Cloud Console"],
                    "gsb_score": 0,
                    "is_suspicious": False,
                    "api_available": True
                }

            if response.status_code == 429:
                return {
                    "found": False,
                    "threats": [],
                    "flags": ["Google Safe Browsing daily quota (10,000 req) exceeded"],
                    "gsb_score": 0,
                    "is_suspicious": False,
                    "api_available": True
                }

            if response.status_code != 200:
                return {
                    "found": False,
                    "threats": [],
                    "flags": [f"GSB API returned status {response.status_code}"],
                    "gsb_score": 0,
                    "is_suspicious": False,
                    "api_available": True
                }

            data = response.json()

            # ── Empty response = clean URL ────────────────
            # GSB returns {} (empty JSON) when URL is not in any threat list
            if not data or "matches" not in data:
                return {
                    "found": False,
                    "threats": [],
                    "flags": [],
                    "gsb_score": 0,
                    "is_suspicious": False,
                    "api_available": True
                }

            # ── Threat matches found ──────────────────────
            matches = data.get("matches", [])
            detected_threats = []
            threat_details = []

            for match in matches:
                threat_type = match.get("threatType", "UNKNOWN")
                platform = match.get("platformType", "ANY_PLATFORM")
                entry_type = match.get("threatEntryType", "URL")

                label = THREAT_TYPE_LABELS.get(threat_type, threat_type)
                threat_score = THREAT_SEVERITY.get(threat_type, 80)

                detected_threats.append({
                    "type": threat_type,
                    "label": label,
                    "platform": platform,
                })

                score = max(score, threat_score)

                flags.append(
                    f"🚨 Google Safe Browsing: '{label}' detected on {platform}"
                )

            if len(detected_threats) > 1:
                flags.append(
                    f"URL matches {len(detected_threats)} separate Google threat categories"
                )

            if score == 100:
                flags.append(
                    "Google Safe Browsing is used to protect 5+ billion devices — "
                    "a positive match here is extremely reliable"
                )

            return {
                "found": True,
                "threats": detected_threats,
                "flags": flags,
                "gsb_score": min(score, 100),
                "is_suspicious": score > 0,
                "api_available": True
            }

    except httpx.TimeoutException:
        return {
            "found": False,
            "threats": [],
            "flags": ["Google Safe Browsing API timed out"],
            "gsb_score": 0,
            "is_suspicious": False,
            "api_available": True
        }

    except Exception as e:
        return {
            "found": False,
            "threats": [],
            "flags": [f"GSB check failed: {str(e)}"],
            "gsb_score": 0,
            "is_suspicious": False,
            "api_available": True
        }
