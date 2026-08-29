"""app/services/smishing_service.py — Dedicated Smishing Analysis Service.

BUG-008 FIX: Use settings.ollama_host instead of hardcoded host.docker.internal URL.
"""
from __future__ import annotations
import json
import re
import logging
import asyncio
from typing import Optional

logger = logging.getLogger(__name__)

# Pakistani scam keyword scoring
_SCAM_KEYWORDS = {
    "otp": 3, "pin": 3, "cnic": 3, "bank account": 3, "account number": 3,
    "send money": 3, "transfer": 3, "click here": 3, "verify now": 3,
    "congratulations": 3, "you have won": 3, "prize": 3, "lottery": 3,
    "limited time": 3, "act now": 3, "immediate": 3, "immediately": 3,
    "suspended": 3, "blocked": 3, "expired": 3, "deactivated": 3,
    "dear customer": 2, "dear user": 2, "dear sir": 2, "dear madam": 2,
    "jazzcash": 2, "easypaisa": 2, "hbl": 2, "ubl": 2, "meezan": 2,
    "jazz": 2, "telenor": 2, "zong": 2, "ufone": 2,
    "click": 2, "verify": 2, "confirm": 2, "validate": 2,
    "urgent": 2, "asap": 2, "claim": 2, "reward": 2, "winner": 2,
    "free": 2, "win": 2, "gift": 2, "offer": 2, "discount": 2,
    "rs.": 2, "pkr": 2, "rupees": 2, "Rs": 2,
    "account": 1, "update": 1, "login": 1, "password": 1,
    "security": 1, "alert": 1, "warning": 1, "notice": 1,
    "link": 1, "visit": 1, "open": 1, "tap": 1,
}

_SUSPICIOUS_PATTERNS = [
    r"RS\s*\.?\s*\d+",
    r"\+92\d{10}",
    r"bit\.ly|tinyurl|goo\.gl",
    r"\.tk|\.ml|\.ga|\.cf|\.gq",
    r"[A-Z]{4,}\s*:",
    r"\b\d{4,6}\b",
]


def keyword_score(text: str) -> tuple[int, list[str]]:
    text_lower = text.lower()
    score = 0
    matched = []
    for kw, weight in _SCAM_KEYWORDS.items():
        if kw.lower() in text_lower:
            score += weight
            matched.append(kw)
    for pattern in _SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score += 2
            matched.append(f"pattern:{pattern[:20]}")
    return score, matched


async def analyze_smishing(
    sms_text: str,
    phone_result: Optional[dict] = None,
    link_result: Optional[dict] = None,
) -> dict:
    kw_score, kw_hits = keyword_score(sms_text)
    ollama_result = await _ask_ollama_smishing(sms_text)
    ol_is_smishing = ollama_result.get("is_smishing", False)
    ol_confidence  = int(ollama_result.get("confidence", 0))
    ol_reason      = ollama_result.get("reason", "")
    ol_category    = ollama_result.get("category", "")

    kw_confidence = min(100, int(kw_score * 2.5))
    if ol_is_smishing:
        combined_conf = max(ol_confidence, kw_confidence)
    else:
        combined_conf = max(0, kw_confidence - 20)

    is_smishing = (
        ol_is_smishing and ol_confidence >= 25
        or kw_score >= 8
        or (kw_score >= 5 and ol_is_smishing)
    )

    if combined_conf >= 80:    risk = "CRITICAL"
    elif combined_conf >= 60:  risk = "HIGH"
    elif combined_conf >= 40:  risk = "MEDIUM"
    elif combined_conf >= 20:  risk = "LOW"
    else:                      risk = "SAFE"

    phone_risk = ""
    link_risk  = ""
    if phone_result and not phone_result.get("module_unavailable"):
        phone_risk = (phone_result.get("overall_risk_level") or "").upper()
        if "HIGH" in phone_risk or "CRITICAL" in phone_risk:
            risk = "HIGH"
            is_smishing = True
    if link_result and not link_result.get("module_unavailable"):
        lr = (link_result.get("risk_level") or "").upper()
        link_risk = lr
        if "HIGH" in lr or "CRITICAL" in lr:
            risk = "CRITICAL" if risk == "HIGH" else "HIGH"
            is_smishing = True

    return {
        "is_smishing":   is_smishing,
        "confidence":    combined_conf,
        "risk_level":    risk,
        "category":      ol_category or _guess_category(sms_text, kw_hits),
        "keyword_hits":  kw_hits[:8],
        "phone_risk":    phone_risk,
        "link_risk":     link_risk,
        "ollama_reason": ol_reason,
        "keyword_score": kw_score,
    }


def _guess_category(text: str, hits: list[str]) -> str:
    text_lower = text.lower()
    if any(w in text_lower for w in ["otp","pin","verify","confirm"]):
        return "otp_theft"
    if any(w in text_lower for w in ["won","prize","lottery","congratulations","reward","rs."]):
        return "prize_scam"
    if any(w in text_lower for w in ["suspended","blocked","account","hbl","bank"]):
        return "account_alert"
    if any(w in text_lower for w in ["package","delivery","parcel","courier"]):
        return "delivery_scam"
    return "financial_fraud"


async def _ask_ollama_smishing(sms_text: str) -> dict:
    """Ask Ollama to classify SMS as smishing. BUG-008: uses settings.ollama_host."""
    from app.core.config import get_settings
    settings = get_settings()
    _SYSTEM = (
        "You are an expert at detecting SMS phishing (smishing) targeting Pakistani mobile users. "
        "Analyse the SMS. Flag as smishing if it contains ANY of: "
        "requests for OTP/PIN/CNIC/bank details; urgency about account suspension; "
        "prize/lottery notifications; fake bank/telecom alerts; payment requests; "
        "'Congratulations you won' messages; requests to click suspicious links; "
        "fake delivery fee requests. "
        "Respond ONLY with valid JSON (no markdown): "
        '{"is_smishing":true/false,"confidence":0-100,"reason":"2 sentences plain English",'
        '"category":"otp_theft|prize_scam|account_alert|delivery_scam|financial_fraud|legitimate"}'
    )
    try:
        import httpx
        payload = {
            "model": settings.ollama_model,
            "prompt": f"{_SYSTEM}\n\nSMS: \"{sms_text}\"",
            "stream": False, "options": {"temperature": 0.1}
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            r = await client.post(f"{settings.ollama_host}/api/generate", json=payload)
            if r.status_code == 200:
                raw = r.json().get("response", "")
                raw = re.sub(r"```json|```", "", raw).strip()
                m = re.search(r"\{.*\}", raw, re.DOTALL)
                if m:
                    return json.loads(m.group())
    except Exception as e:
        logger.warning("Ollama smishing error: %s", e)
    return {"is_smishing": False, "confidence": 0, "reason": "", "category": ""}


def format_smishing_result(sms_text: str, result: dict, human_exp: str = "") -> str:
    is_smishing = result.get("is_smishing", False)
    risk        = result.get("risk_level", "SAFE")
    confidence  = result.get("confidence", 0)
    category    = result.get("category", "")
    kw_hits     = result.get("keyword_hits", [])
    ol_reason   = result.get("ollama_reason", "")
    phone_risk  = result.get("phone_risk", "")
    link_risk   = result.get("link_risk", "")

    _RISK_EMOJI = {
        "CRITICAL": "🆘", "HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "🟡", "SAFE": "✅"
    }
    _CATEGORY_LABELS = {
        "otp_theft":       "OTP/PIN Theft Attempt",
        "prize_scam":      "Fake Prize / Lottery Scam",
        "account_alert":   "Fake Account Alert",
        "delivery_scam":   "Fake Delivery Fee Scam",
        "financial_fraud": "Financial Fraud Attempt",
        "legitimate":      "Legitimate SMS",
    }

    emoji     = _RISK_EMOJI.get(risk, "🔍")
    cat_label = _CATEGORY_LABELS.get(category, category.replace("_", " ").title())

    if is_smishing:
        header       = f"{emoji} {risk} — Smishing Detected"
        verdict_line = f"🚨 This is a *{cat_label}* — do NOT respond or click any links."
        advice = (
            "⚠️ *What to do:*\n"
            "• Delete this message immediately\n"
            "• Do NOT share OTP, PIN, CNIC, or bank details\n"
            "• Do NOT click any links in this message\n"
            "• Report to FIA Cyber Crime: 0800-55555"
        )
    else:
        header       = f"{emoji} SAFE — SMS Analysis"
        verdict_line = "📩 No strong smishing patterns detected."
        advice = "⚠️ Always be cautious with unexpected messages asking for personal information."

    lines = [header, ""]
    if human_exp:
        lines += [human_exp, ""]
    elif ol_reason:
        lines += [ol_reason, ""]

    lines += [
        "⚙️ *Analysis Details:*",
        f"🛡️ Risk: {emoji} {risk} ({confidence}% confidence)",
    ]
    if category and category != "legitimate":
        lines.append(f"🎭 Pattern: {cat_label}")
    if phone_risk:
        lines.append(f"📱 Phone Risk: {phone_risk}")
    if link_risk:
        lines.append(f"🔗 Link Risk: {link_risk}")

    visible_hits = [kw for kw in kw_hits if not kw.startswith("pattern:")][:5]
    if visible_hits:
        lines.append(f"🔑 Scam keywords: {', '.join(visible_hits)}")

    lines += ["", verdict_line, "", advice]
    return "\n".join(lines)
