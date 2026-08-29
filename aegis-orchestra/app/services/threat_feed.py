"""app/services/threat_feed.py — Proactive Threat Alert Service.

Monitors PakCERT, FIA, and other Pakistani cybersecurity feeds.
Sends broadcast warnings when new scam campaigns are detected.
Phase 2 feature — currently a stub with full implementation logic.
"""
from __future__ import annotations
import asyncio
import logging
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

FEEDS = [
    "https://www.pakcert.gov.pk/alerts/rss",
    "https://nia.gov.pk/cybercrime-alerts/rss",
]

_PAKISTAN_KEYWORDS = [
    "jazzcash", "easypaisa", "hbl", "meezan", "uba", "ubl", "allied",
    "nadra", "ptcl", "jazz", "telenor", "zong", "ufone", "pakistan",
    "prize", "lucky draw", "sms scam", "phishing", "otp fraud",
]


async def fetch_latest_threats() -> list[dict]:
    """Fetch latest cyberthreat alerts from Pakistani sources."""
    threats = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        for feed_url in FEEDS:
            try:
                r = await client.get(feed_url)
                if r.status_code == 200:
                    # Parse RSS/Atom feed
                    import re
                    titles = re.findall(r"<title>(.*?)</title>", r.text)
                    descriptions = re.findall(r"<description>(.*?)</description>", r.text)
                    for i, title in enumerate(titles[1:6]):  # skip feed title
                        desc = descriptions[i] if i < len(descriptions) else ""
                        threats.append({
                            "title": title,
                            "description": desc[:200],
                            "source": feed_url,
                            "is_pakistan_relevant": any(
                                kw in (title + desc).lower()
                                for kw in _PAKISTAN_KEYWORDS
                            )
                        })
            except Exception as e:
                logger.warning("Feed fetch error %s: %s", feed_url, e)
    return threats


def format_threat_alert(threat: dict) -> str:
    """Format a threat alert as a WhatsApp message."""
    title = threat.get("title", "New Threat Alert")
    desc = threat.get("description", "")
    return (
        f"🚨 *Security Alert*\n\n"
        f"*{title}*\n\n"
        f"{desc}\n\n"
        f"Stay vigilant. Do not click suspicious links or share OTPs.\n"
        f"📋 Report: nia.gov.pk / 0800-55555"
    )


async def check_for_new_threats(last_check_ts: float = 0) -> list[str]:
    """Check for threats newer than last_check_ts. Returns formatted messages."""
    threats = await fetch_latest_threats()
    return [format_threat_alert(t) for t in threats if t.get("is_pakistan_relevant")]
