"""
Feature 1.7 - Smishing & Social Engineering Pattern Detector
Analyzes QR payload text for phishing/smishing attack patterns.
Zero external API — fully local NLP-style pattern matching.
Works on: SMS, email, text payloads and vCard notes.
"""
import re
from typing import List, Tuple
from app.logger import log

# ─────────────────────────────────────────────────────────────
# Pattern Library — (regex, weight, category, description)
# Higher weight = stronger indicator of attack
# ─────────────────────────────────────────────────────────────

SMISHING_PATTERNS: List[Tuple[str, int, str, str]] = [

    # ── URGENCY / FEAR INDUCTION ──────────────────────────────
    (r"\b(urgent|urgently|immediately|right\s+away|act\s+now|respond\s+now)\b",
     40, "urgency", "Urgency language to bypass rational thinking"),

    (r"\b(expires?\s+(today|now|soon|in\s+\d+\s+(hour|minute|day)s?))\b",
     35, "urgency", "Artificial deadline to create pressure"),

    (r"\b(last\s+(warning|chance|notice)|final\s+(notice|warning|reminder))\b",
     45, "urgency", "Escalation language to induce panic"),

    (r"\b(within\s+\d+\s+(hour|minute|day)s?|in\s+the\s+next\s+\d+\s+(hour|minute)s?)\b",
     30, "urgency", "Specific time pressure"),

    # ── ACCOUNT THREAT / SUSPENSION ──────────────────────────
    (r"\b(account|card|profile|subscription).{0,30}(suspended|blocked|locked|disabled|frozen|cancelled)\b",
     50, "account_threat", "Account suspension threat — classic phishing trigger"),

    (r"\b(unauthori[sz]ed|suspicious).{0,30}(access|activity|login|attempt|transaction)\b",
     45, "account_threat", "Unauthorized activity claim"),

    (r"\b(verify|confirm|validate|authenticate).{0,30}(identity|account|information|details)\b",
     45, "credential_harvest", "Identity verification request — credential phishing"),

    # ── BANK / FINANCIAL IMPERSONATION ───────────────────────
    (r"\b(natwest|barclays|lloyds|hsbc|santander|halifax|halifax|monzo|starling|revolut)\b",
     40, "bank_impersonation", "UK bank name detected"),

    (r"\b(chase|wells\s*fargo|bank\s*of\s*america|citibank|td\s*bank|us\s*bank)\b",
     40, "bank_impersonation", "US bank name detected"),

    (r"\b(bank).{0,30}(detail|sort.?code|account.?number|iban|bic|swift)\b",
     60, "banking_detail", "Request for banking details — very high risk"),

    (r"\b(credit|debit).{0,20}card.{0,30}(detail|number|cvv|expiry|pin)\b",
     65, "card_detail", "Request for card details — credential theft"),

    # ── GOVERNMENT IMPERSONATION ─────────────────────────────
    (r"\b(hmrc|gov\.uk|dvla|nhs|dwp|hmcts|irs|social\s+security|medicare)\b",
     40, "government_impersonation", "Government agency impersonation"),

    (r"\b(tax\s+(refund|rebate|return)|overdue\s+tax|unpaid\s+(fine|penalty))\b",
     45, "government_impersonation", "Government financial claim"),

    (r"\b(court|legal\s+action|prosecution|warrant|arrest).{0,30}(unless|avoid|prevent)\b",
     55, "legal_threat", "Legal threat to coerce action"),

    # ── DELIVERY SCAM ────────────────────────────────────────
    (r"\b(dhl|fedex|ups|royal\s+mail|parcelforce|hermes|evri|yodel).{0,50}(parcel|package|delivery|shipment)\b",
     35, "delivery_scam", "Delivery company impersonation"),

    (r"\b(parcel|package|delivery).{0,30}(held|detained|pending|awaiting|failed|missed)\b",
     30, "delivery_scam", "Delivery problem claim — redirect to phishing"),

    (r"\b(customs|import)\s+(fee|charge|duty|tax).{0,30}(pay|click|link)\b",
     40, "delivery_scam", "Fake customs fee request"),

    # ── PRIZE / REWARD SCAM ──────────────────────────────────
    (r"\b(you\s+have\s+(won|been\s+selected|been\s+chosen)|congratulations.{0,20}(winner|prize|reward))\b",
     50, "prize_scam", "Prize winner claim — too-good-to-be-true"),

    (r"\b(claim|collect|redeem).{0,30}(prize|reward|gift|voucher|cashback|refund)\b",
     40, "prize_scam", "Prize claim request"),

    (r"\b(free\s+(iphone|samsung|gift|voucher|amazon|netflix)).{0,30}(click|tap|scan|visit|enter)\b",
     55, "prize_scam", "Specific free item lure"),

    # ── CREDENTIAL / OTP THEFT ───────────────────────────────
    (r"\b(one.?time.?(password|code|pin)|otp|verification\s+code).{0,30}(enter|provide|send|share)\b",
     70, "otp_theft", "OTP/verification code request — NEVER share these"),

    (r"\b(password|passphrase|login\s+detail|username).{0,30}(reset|update|change|provide|enter)\b",
     55, "credential_harvest", "Password-related action request"),

    (r"\b(pin|passcode|security\s+code).{0,30}(enter|provide|confirm|text|send)\b",
     65, "credential_harvest", "PIN request — high severity"),

    # ── SOCIAL ENGINEERING LANGUAGE ──────────────────────────
    (r"\b(do\s+not\s+(ignore|delete|discard)|important\s+(message|notice|alert|update))\b",
     25, "social_engineering", "Authority-signalling language"),

    (r"\b(click\s+(here|below|this\s+link)|tap\s+here|scan\s+(this|the)\s+(qr|code))\b",
     20, "cta_redirect", "Generic call-to-action redirect"),

    (r"\b(limited\s+time|exclusive\s+offer|special\s+offer).{0,30}(click|visit|enter)\b",
     25, "social_engineering", "FOMO/scarcity manipulation"),

    # ── TECHNICAL / URL INDICATORS ───────────────────────────
    (r"(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|rebrand\.ly|tiny\.cc|cutt\.ly)",
     35, "url_shortener", "URL shortener — hides true destination"),

    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
     40, "ip_url", "Direct IP address URL — uncommon for legitimate services"),

    (r"https?://[^\s]{0,5}(login|verify|secure|account|update|confirm)[^\s]*\.(tk|ml|ga|cf|gq|xyz|top|work|click)",
     60, "phishing_domain", "Phishing keyword + suspicious TLD combination"),

    (r"\b(multiple\s+url|https?://\S+\s.{0,50}https?://)",
     25, "multiple_links", "Multiple URLs in message body"),

    # ── PHONE NUMBER INDICATORS ──────────────────────────────
    (r"(\+?1?-?900-?|\+?0909|\+?0871|\+?0872|\+?0873)",
     50, "premium_rate", "Premium-rate phone number — calling incurs high charges"),

    (r"\b(call|ring|phone|dial).{0,15}(\d{10,13}|\+\d{10,14})",
     20, "phone_call_lure", "Request to call a specific number"),

    # ── CRYPTO SCAM ──────────────────────────────────────────
    (r"\b(bitcoin|ethereum|crypto|nft).{0,30}(invest|profit|earn|opportunity|double)\b",
     45, "crypto_scam", "Cryptocurrency investment scam"),

    (r"\b(wallet|transfer|send).{0,20}(bitcoin|eth|usdt|crypto)",
     40, "crypto_theft", "Cryptocurrency transfer request"),
]

# ─────────────────────────────────────────────────────────────
# Severity thresholds
# ─────────────────────────────────────────────────────────────
THRESHOLDS = {
    "Critical": 90,
    "High":     60,
    "Medium":   30,
    "Low":      10,
    "Safe":     0
}

def _score_to_risk(score: int) -> str:
    for level, threshold in THRESHOLDS.items():
        if score >= threshold:
            return level
    return "Safe"

# ─────────────────────────────────────────────────────────────
# PUBLIC
# ─────────────────────────────────────────────────────────────

def detect_smishing(text: str, payload_type: str = "text") -> dict:
    """
    Scores a text payload for social engineering / smishing indicators.

    Args:
        text:         The QR payload text (SMS body, email body, plain text, etc.)
        payload_type: The QR type ('sms', 'email', 'text', 'vcard', etc.)

    Returns:
    {
        "smishing_score":      int (0-100),
        "risk_level":          str,
        "patterns_matched":    int,
        "categories_triggered": [str],
        "pattern_breakdown":   [...],
        "verdict":             str,
        "recommendation":      str
    }
    """
    text_normalized = text.lower().strip()
    total_score = 0
    matched_patterns = []
    categories_hit = set()

    for pattern, weight, category, description in SMISHING_PATTERNS:
        try:
            match = re.search(pattern, text_normalized, re.IGNORECASE)
            if match:
                matched_patterns.append({
                    "category":    category,
                    "weight":      weight,
                    "description": description,
                    "matched_text": text_normalized[max(0, match.start()-10):match.end()+10].strip()
                })
                categories_hit.add(category)
                total_score += weight
        except Exception as e:
            log.warning(f"[Smishing] Pattern error ({pattern[:30]}): {e}")

    # SMS payloads get a slight multiplier — they're higher risk context
    if payload_type == "sms":
        total_score = int(total_score * 1.2)

    # Cap at 100
    total_score = min(total_score, 100)

    risk_level = _score_to_risk(total_score)

    # Multi-category bonus: if 3+ different categories triggered, boost risk assessment
    if len(categories_hit) >= 3 and risk_level in ["Low", "Medium"]:
        risk_level = "High"
        note = f"Escalated to High: {len(categories_hit)} distinct attack categories detected simultaneously"
    else:
        note = None

    recommendation = {
        "Critical": "🚨 Do NOT interact with this QR. Report to your security team immediately.",
        "High":     "⚠️ Strong signs of social engineering attack. Do not click, call, or provide any information.",
        "Medium":   "⚠️ Suspicious content detected. Verify the sender through an official channel before acting.",
        "Low":      "ℹ️ Minor indicators present. Exercise caution and verify source.",
        "Safe":     "✅ No social engineering patterns detected in text content."
    }.get(risk_level, "Review content carefully before acting.")

    if matched_patterns:
        log.info(
            f"[Smishing] Score: {total_score}/100 | Risk: {risk_level} | "
            f"Patterns: {len(matched_patterns)} | Categories: {list(categories_hit)}"
        )

    return {
        "smishing_score":       total_score,
        "risk_level":           risk_level,
        "patterns_matched":     len(matched_patterns),
        "categories_triggered": list(categories_hit),
        "pattern_breakdown":    matched_patterns,
        "multi_category_note":  note,
        "verdict": (
            f"⚠️ SMISHING DETECTED: {len(matched_patterns)} attack pattern(s) found"
            if total_score >= 30 else
            "✅ No strong smishing indicators in this payload"
        ),
        "recommendation": recommendation
    }
