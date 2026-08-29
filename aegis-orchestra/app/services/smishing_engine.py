"""app/services/smishing_engine.py — Dedicated Smishing Detection Engine.

Analyses suspicious SMS messages using:
1. Keyword + pattern scoring (immediate)
2. Ollama AI classification (primary)
3. Gemini AI for complex/Urdu messages (fallback)
4. Sub-analysis of any phone numbers found (credential service)
5. Sub-analysis of any links found (link analyzer)

Composes a unified reply using all results.
"""
from __future__ import annotations
import re
import logging
from typing import Optional
import asyncio

logger = logging.getLogger(__name__)

# ── Pattern scoring ──────────────────────────────────────────────────────────

_HIGH_RISK_PATTERNS = [
    # OTP/PIN theft
    (r"\b(otp|pin|password|passcode)\b.*\b(share|send|enter|provide|give)\b", 25),
    (r"\b(share|send|give|provide)\b.*\b(otp|pin|code|password)\b", 25),
    # Account threats
    (r"\b(account|sim|number|service)\b.*\b(blocked|suspended|disabled|expired|locked)\b", 20),
    (r"\b(blocked|suspended|disabled|expired)\b.*\b(account|sim|number)\b", 20),
    # Prize/lottery scams
    (r"\b(won|win|winner|prize|reward|lottery|lucky draw|congratulation)\b", 22),
    (r"\b(claim|collect|receive)\b.*\b(prize|reward|money|cash|rs\.?\d+)\b", 22),
    # Pakistani financial brands (impersonation)
    (r"\b(jazzcash|easypaisa|hbl|ubl|meezan|mcb|alfalah|askari)\b.*\b(suspended|blocked|verify|urgent)\b", 28),
    # Identity theft
    (r"\b(cnic|national id|id card|identity)\b.*\b(send|share|provide|verify)\b", 30),
    (r"\b(bank account|account number|iban)\b.*\b(send|share|provide|claim)\b", 30),
    # Urgency keywords
    (r"\b(urgent|immediately|asap|right now|last chance|expire today|limited time)\b", 10),
    # Generic verify scam
    (r"\b(verify|verification|confirm|activate|reactivate)\b.*\b(account|identity|number|sim)\b", 18),
    # Advance fee fraud
    (r"\b(fee|charge|cost|payment)\b.*\b(release|receive|claim|prize|reward)\b", 25),
    # Delivery scam
    (r"\b(package|parcel|delivery|courier)\b.*\b(hold|fee|pay|rs\.?\s*\d+)\b", 20),
    # Government impersonation
    (r"\b(nadra|fia|ptcl|pta|fbr|government)\b.*\b(verify|suspend|block|urgent)\b", 28),
]

_SAFE_PATTERNS = [
    # OTP from real services (expected, not asked for)
    r"your otp is\s+\d{4,8}",
    r"verification code:\s*\d{4,8}",
    r"do not share this code",
]


def keyword_score(text: str) -> tuple[int, list[str]]:
    """Rule-based keyword scoring. Returns (score 0-100, matched_patterns)."""
    text_lower = text.lower()
    score = 0
    matched = []

    # Check safe patterns first
    for sp in _SAFE_PATTERNS:
        if re.search(sp, text_lower):
            return 0, ["Legitimate OTP/verification message"]

    for pattern, weight in _HIGH_RISK_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            score += weight
            matched.append(f"Pattern: {pattern[:40]}...")

    # Count Rs. amount mentions (financial bait)
    rs_amounts = re.findall(r"rs\.?\s*[\d,]+", text_lower)
    if rs_amounts:
        score += min(len(rs_amounts) * 8, 20)
        matched.append(f"Financial bait: {', '.join(rs_amounts[:3])}")

    # Suspicious links
    if re.search(r"http[s]?://", text_lower):
        score += 10
        matched.append("Contains URL")
    if re.search(r"\.(tk|ml|ga|cf|gq|xyz|top|online)\b", text_lower):
        score += 15
        matched.append("Suspicious domain TLD")

    return min(score, 100), matched


async def analyse_smishing(
    sms_text: str,
    phone_numbers: list[str] = None,
    urls: list[str] = None,
    api_result: dict = None,
) -> dict:
    """
    Full smishing analysis pipeline.
    
    Returns:
    {
      "is_smishing": bool,
      "confidence": 0-100,
      "risk_level": str,
      "category": str,
      "keyword_score": int,
      "keyword_signals": [...],
      "ollama_analysis": {...},
      "phone_results": [...],
      "link_results": [...],
      "plain_explanation": str,
      "recommended_action": str,
    }
    """
    results = {
        "is_smishing": False,
        "confidence": 0,
        "risk_level": "SAFE",
        "category": "legitimate",
        "keyword_score": 0,
        "keyword_signals": [],
        "ollama_analysis": {},
        "phone_results": [],
        "link_results": [],
        "plain_explanation": "",
        "recommended_action": "",
    }

    # Step 1: Keyword scoring
    kw_score, kw_signals = keyword_score(sms_text)
    results["keyword_score"]   = kw_score
    results["keyword_signals"] = kw_signals

    # Step 2: Ollama AI analysis
    try:
        from app.router.ollama_client import classify_smishing
        ol = await classify_smishing(sms_text)
        if ol:
            results["ollama_analysis"] = ol
            ol_score = ol.get("confidence", 0) or 0
            ol_smish = ol.get("is_smishing", False)
            results["category"] = ol.get("category", "legitimate")
        else:
            ol_score, ol_smish = 0, False
    except Exception as e:
        logger.warning("Ollama smishing error: %s", e)
        ol_score, ol_smish = 0, False

    # Step 3: Combine scores (keyword 40% + Ollama 60%)
    # If keyword score is high, trust it even without Ollama
    combined_score = int(kw_score * 0.4 + ol_score * 0.6)
    if kw_score >= 40:
        combined_score = max(combined_score, kw_score)

    # Determine if smishing
    is_smishing = (
        (ol_smish and ol_score >= 25) or
        kw_score >= 45 or
        combined_score >= 40
    )
    results["is_smishing"] = is_smishing
    results["confidence"]  = combined_score

    # Step 4: Risk level
    if combined_score >= 75:   results["risk_level"] = "CRITICAL"
    elif combined_score >= 55: results["risk_level"] = "HIGH"
    elif combined_score >= 35: results["risk_level"] = "MEDIUM"
    elif is_smishing:          results["risk_level"] = "MEDIUM"
    else:                      results["risk_level"] = "SAFE"

# Step 5: Sub-analyse phone numbers if present
    if phone_numbers:
        try:
            from app.router.dispatcher import cred_analyze_phone
            for ph in phone_numbers[:2]:
                ph_result = await cred_analyze_phone(ph)
                if ph_result and not ph_result.get("module_unavailable"):
                    results["phone_results"].append({"number": ph, "result": ph_result})
        except Exception as e:
            logger.warning("Phone sub-analysis error: %s", e)

    if urls:
        try:
            from app.router.dispatcher import link_scan
            for url in urls[:2]:
                link_result = await link_scan(url)
                if link_result and not link_result.get("module_unavailable"):
                    results["link_results"].append({"url": url, "result": link_result})
                # Boost smishing score if link is high risk
                    if "high" in (link_result.get("risk_level") or "").lower():
                        results["confidence"] = min(results["confidence"] + 20, 100)
                        results["is_smishing"] = True
                        if results["risk_level"] in ("SAFE", "MEDIUM"):
                            results["risk_level"] = "HIGH"
        except Exception as e:
            logger.warning("Link sub-analysis error: %s", e)

# Step 8: Recommended action
    if is_smishing:
        cat = results["category"]
        if "prize" in cat or "lottery" in cat:
            results["recommended_action"] = (
                "⚠️ This is a prize scam. No one randomly gives away Rs.50,000. "
                "Do NOT reply, do NOT share your CNIC or bank details. Delete this message."
            )
        elif "otp" in cat or "pin" in cat:
            results["recommended_action"] = (
                "🔴 This message is trying to steal your OTP/PIN. "
                "No real bank or telecom will EVER ask for your OTP. "
                "Do NOT share it. Report to FIA: 0800-55555."
            )
        elif "account" in cat or "suspend" in cat:
            results["recommended_action"] = (
                "⚠️ Your account is fine. This is a fake threat to make you panic. "
                "Call your bank/telecom directly using the official number on their website. "
                "Do NOT click any links or call numbers in this message."
            )
        else:
            results["recommended_action"] = (
                "🚨 This is a scam message. Do NOT reply, click links, or share personal information. "
                "Report to FIA Cyber Crime: 0800-55555 or nia.gov.pk."
            )
    else:
        results["recommended_action"] = (
            "This message appears legitimate. However, always be cautious — "
            "never share OTPs or passwords with anyone, even if they claim to be from your bank."
        )

    return results


def format_smishing_result(sms_text: str, analysis: dict) -> str:
    """Format smishing analysis into a clear WhatsApp reply."""
    is_smishing  = analysis.get("is_smishing", False)
    confidence   = analysis.get("confidence", 0)
    risk_level   = analysis.get("risk_level", "SAFE")
    category     = analysis.get("category", "legitimate")
    plain        = analysis.get("plain_explanation", "")
    action       = analysis.get("recommended_action", "")
    kw_signals   = analysis.get("keyword_signals", [])
    phone_res    = analysis.get("phone_results", [])
    link_res     = analysis.get("link_results", [])
    ol_analysis  = analysis.get("ollama_analysis", {})

    # Badge
    if risk_level in ("CRITICAL", "HIGH"):
        badge = "🚨 HIGH RISK"
    elif risk_level == "MEDIUM":
        badge = "⚠️ MEDIUM RISK"
    else:
        badge = "✅ SAFE"

    lines = [f"{badge} — SMS Analysis", "📩 SMS / Text Message", ""]

    # Plain explanation (Ollama-generated)
    if plain:
        lines += [plain, ""]
    elif is_smishing:
        cat_map = {
            "prize_scam":     "This is a prize scam — you didn't win anything.",
            "otp_theft":      "This message is trying to steal your OTP/PIN.",
            "account_alert":  "This is a fake account suspension threat.",
            "financial_fraud":"This is a financial scam targeting your bank account.",
            "identity_theft": "This message is trying to steal your personal identity.",
        }
        lines += [cat_map.get(category, "This message shows signs of being a scam."), ""]

    lines += [
        "⚙️ *Technical Details:*",
        f"🛡️ Risk Level: {'🔴' if risk_level in ('HIGH','CRITICAL') else '🟠' if risk_level == 'MEDIUM' else '🟢'} {risk_level}",
        f"🤖 AI Confidence: {confidence}%",
        f"📋 Category: {category.replace('_', ' ').title()}",
    ]

    # Keyword signals
    if kw_signals:
        lines.append("\n⚠️ *Suspicious Patterns Detected:*")
        for sig in kw_signals[:4]:
            # Make signals readable
            if "Pattern:" in sig:
                sig = sig.replace("Pattern: ", "").replace("...", "")
            lines.append(f"• {sig[:80]}")

    # Ollama AI reasoning
    ol_reason = (ol_analysis or {}).get("reason", "")
    if ol_reason and ol_reason not in plain:
        lines += ["", f"🤖 *AI Analysis:* {ol_reason}"]

    # Sub-analysis results
    if phone_res:
        lines.append("\n📱 *Phone Analysis:*")
        for ph in phone_res:
            ph_r = ph.get("result", {})
            ph_risk = ph_r.get("overall_risk_level", "Unknown")
            lines.append(f"• {ph['number']}: {ph_risk}")

    if link_res:
        lines.append("\n🔗 *Link Analysis:*")
        for lr in link_res:
            lr_r = lr.get("result", {})
            lr_risk = lr_r.get("risk_level", "Unknown")
            lr_flags = lr_r.get("total_flags", 0)
            lines.append(f"• {lr['url'][:50]}: {lr_risk} ({lr_flags} flags)")

    lines += ["", action]
    lines += ["", "📋 Report: nia.gov.pk / 0800-55555"]

    return "\n".join(lines)
