"""app/router/gemini_client.py — Google Gemini API client.

=== GEMINI vs OLLAMA — WHEN TO USE WHICH ===

Ollama (local Llama 3.2):
  ✅ PROS: Free, private (no data leaves your server), fast for simple tasks,
           works offline, no API key needed
  ❌ CONS: Lower quality for complex language, struggles with Urdu/Roman Urdu,
           slower on CPU (GPU recommended), needs 4GB+ RAM

Gemini (Google Cloud):
  ✅ PROS: Excellent multilingual (especially Urdu/Hindi/Roman Urdu), better
           reasoning for ambiguous intent, handles mixed Urdu+English sentences,
           faster for complex classification tasks
  ❌ CONS: Costs money per API call, data sent to Google, needs internet,
           rate limits on free tier

DECISION:
  - Use Ollama for: plain word explanations, simple smishing classification,
    follow-up context understanding (English only)
  - Use Gemini for: Roman Urdu intent classification, ambiguous multi-language
    messages, complex disambiguation where Ollama returns 'unknown'

FALLBACK CHAIN: Gemini → Ollama → rule-based
"""
from __future__ import annotations
import json
import logging
import re
from typing import Optional

import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

_GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
_TIMEOUT = httpx.Timeout(20.0, connect=5.0)


async def gemini_ask(prompt: str, system: str = "", max_tokens: int = 300) -> Optional[str]:
    """Call Gemini 1.5 Flash. Returns None if unavailable or API key not set."""
    if not settings.gemini_api_key:
        return None

    payload = {
        "contents": [{"parts": [{"text": f"{system}\n\n{prompt}" if system else prompt}]}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0.3,
        }
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.post(
                f"{_GEMINI_API_URL}?key={settings.gemini_api_key}",
                json=payload,
            )
            r.raise_for_status()
            data = r.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "").strip()
    except httpx.ConnectError:
        logger.warning("Gemini API not reachable")
    except Exception as e:
        logger.warning("Gemini error: %s", e)
    return None


# ── Urdu/Roman Urdu intent classification ────────────────────────────────────

_URDU_SYSTEM = """You are a cybersecurity assistant. Classify this Urdu or Roman Urdu message.
Identify if it contains: a URL to check (url), a credential to verify (credential), 
a social media profile to analyse (profile), a cybersecurity question (cyber_qa), 
or off-topic small talk (offtopic).
Also translate the core intent to English.
Respond ONLY with JSON: {"intent":"url|credential|profile|cyber_qa|offtopic","extracted":"key entity or empty","english":"brief English translation"}"""

async def classify_urdu_gemini(text: str) -> dict:
    """Use Gemini for superior Urdu/Roman Urdu understanding."""
    result = await gemini_ask(f'Message: """{text}"""', system=_URDU_SYSTEM, max_tokens=150)
    if result:
        try:
            return json.loads(re.sub(r"```json|```", "", result).strip())
        except Exception:
            pass
    # Fallback to Ollama
    from app.router.ollama_client import classify_urdu
    return await classify_urdu(text)


# ── Ambiguous intent resolution ───────────────────────────────────────────────

_DISAMBIG_SYSTEM = """You are a cybersecurity assistant routing messages for a WhatsApp bot.
Given a short message, classify it as one of:
- "link_scan": user wants to check if a URL/domain is safe
- "profile_analysis": user wants to check if a social media account is fake/scam
- "credential_breach": user wants to check if their email/phone/password was leaked
- "credential_analysis": user wants to check a password/CNIC/card/API key
- "smishing": this looks like a scam SMS
- "cyber_qa": general cybersecurity question
- "offtopic": unrelated to cybersecurity
Respond ONLY with JSON: {"route":"link_scan|profile_analysis|credential_breach|credential_analysis|smishing|cyber_qa|offtopic","confidence":0-100,"reason":"one line"}"""

async def resolve_ambiguity(text: str) -> dict:
    """Use Gemini to resolve routing ambiguity."""
    result = await gemini_ask(f'Message: "{text}"', system=_DISAMBIG_SYSTEM, max_tokens=100)
    if result:
        try:
            return json.loads(re.sub(r"```json|```", "", result).strip())
        except Exception:
            pass
    return {"route": "offtopic", "confidence": 0, "reason": "parse error"}


async def is_gemini_available() -> bool:
    """Quick check if Gemini API key is configured and working."""
    if not settings.gemini_api_key:
        return False
    result = await gemini_ask("Say OK", max_tokens=5)
    return result is not None
