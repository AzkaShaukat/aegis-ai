"""app/services/username_intelligence.py — Username Intelligence Service.

Combines BOTH credential analyzer AND profile analyzer results for any username,
email address, or social handle. Produces a unified verdict with calculated risk.

Called when:
  - User sends @handle
  - User selects "Both" from username disambiguation
  - User sends bare username like cryptoking99

Flow:
  credential_result + profile_result → score_and_rank() → UnifiedVerdict
"""
from __future__ import annotations
from dataclasses import dataclass, field
import re


@dataclass
class UsernameVerdict:
    entity: str                    # The username/email/phone checked
    final_verdict: str             # REAL | SUSPICIOUS | FAKE | SCAMMER | BREACHED | IMPERSONATOR
    risk_level: str                # SAFE | LOW | MEDIUM | HIGH | CRITICAL
    combined_score: int            # 0-100
    confidence: int                # 0-100
    top_signals: list = field(default_factory=list)
    credential_signals: list = field(default_factory=list)
    profile_signals: list = field(default_factory=list)
    breach_count: int = 0
    is_impersonator: bool = False
    fraud_type: str = ""
    recommended_action: str = ""
    plain_explanation: str = ""


# Known high-risk patterns for Pakistani users
_BRAND_IMPERSONATION = [
    "nadra", "hbl", "ubl", "meezan", "mcb", "allied", "faysal",
    "jazzcash", "easypaisa", "telenor", "jazz", "zong", "ufone", "ptcl",
    "pta", "fbr", "fia", "police", "government", "official", "support",
    "helpdesk", "customer_care", "service", "verify", "secure",
    "paypal", "ebay", "amazon", "apple", "microsoft", "google",
]

_SCAMMER_PATTERNS = [
    r"forex", r"investment", r"profit", r"doubl.*money", r"earn.*daily",
    r"crypto.*signal", r"bitcoin.*invest", r"lottery", r"prize", r"winner",
    r"lucky.*draw", r"free.*money", r"guaranteed.*return",
]


def score_and_rank(
    entity: str,
    credential_result: dict,
    profile_result: dict,
) -> UsernameVerdict:
    """
    Core intelligence function. Combines both services into one verdict.
    
    Scoring weights:
      - Profile score: 55% weight (primary for social accounts)
      - Credential score: 45% weight (primary for breach detection)
    """
    entity_lower = entity.lower().replace("@", "")

    # ── Extract from credential result ───────────────────────────────────────
    c_score  = int(credential_result.get("overall_risk_score", 0) or 0)
    c_flags  = credential_result.get("all_flags", []) or []
    c_breach = int(credential_result.get("hibp_count", 0) or 0)
    c_imp    = any("impersonat" in f.lower() or "brand" in f.lower() for f in c_flags)

    # ── Extract from profile result ───────────────────────────────────────────
    verdict  = profile_result.get("verdict", {}) or {}
    p_score  = int(verdict.get("final_score", 0) or 0)
    p_flags  = [str(f) for f in (verdict.get("top_flags", []) or [])]
    p_fraud  = (verdict.get("fraud_type") or "").lower()
    p_imp    = "impersonat" in p_fraud or any("impersonat" in f.lower() for f in p_flags)

    # ── Own impersonation detection ───────────────────────────────────────────
    own_imp  = any(brand in entity_lower for brand in _BRAND_IMPERSONATION)
    own_scam = any(re.search(pat, entity_lower) for pat in _SCAMMER_PATTERNS)

    # ── Combined score ────────────────────────────────────────────────────────
    combined = int(p_score * 0.55 + c_score * 0.45)

    # ── Boost for own analysis findings ──────────────────────────────────────
    if own_imp:    combined = max(combined, 80)
    if own_scam:   combined = max(combined, 65)
    if c_breach > 0:
        combined = max(combined, 45 + min(c_breach // 100, 30))

    # ── Determine verdict (priority order) ───────────────────────────────────
    is_impersonator = c_imp or p_imp or own_imp
    final_verdict   = "REAL"
    confidence      = 70

    if is_impersonator:
        final_verdict, confidence = "IMPERSONATOR", 88
        combined = max(combined, 78)
    elif "scammer" in p_fraud or own_scam:
        final_verdict, confidence = ("SCAMMER" if p_score >= 45 else "SUSPICIOUS"), 80
    elif "bot" in p_fraud or "fake" in p_fraud:
        final_verdict, confidence = "FAKE", 75
    elif c_breach > 0:
        final_verdict, confidence = "BREACHED", 92
    elif combined >= 65:
        final_verdict, confidence = "SUSPICIOUS", 72
    elif combined >= 40:
        final_verdict, confidence = "SUSPICIOUS", 58
    else:
        final_verdict, confidence = "REAL", 82

    # ── Risk level ────────────────────────────────────────────────────────────
    risk_level = ("CRITICAL" if combined >= 85 else
                  "HIGH"     if combined >= 65 else
                  "MEDIUM"   if combined >= 40 else
                  "LOW"      if combined >= 20 else "SAFE")

    # ── Collect signals ───────────────────────────────────────────────────────
    cred_signals = [f"[Credential] {f}" for f in c_flags[:3]]
    prof_signals = [f"[Profile] {f.replace('_', ' ').title()}" for f in p_flags[:3]]
    own_signals  = []
    if own_imp:    own_signals.append("[⚠️ Impersonation] Username matches known brand/organization")
    if own_scam:   own_signals.append("[⚠️ Scam Pattern] Investment/forex/crypto scam keywords detected")
    if c_breach > 0:
        cred_signals.insert(0, f"[🔴 Breach] Found in {c_breach:,} data breach records")

    all_signals = (own_signals + cred_signals + prof_signals)[:6]

    # ── Recommended action ────────────────────────────────────────────────────
    _ACTIONS = {
        "REAL":         "This account appears legitimate. No immediate action needed.",
        "SUSPICIOUS":   "Exercise caution. Verify through official channels before sharing information.",
        "FAKE":         "Bot/automated account detected. Do not engage or share personal data.",
        "SCAMMER":      "⚠️ Active scam signals. Block and report this account immediately.",
        "BREACHED":     f"Credentials found in {c_breach:,} data breaches. Change passwords and enable 2FA now.",
        "IMPERSONATOR": "This account impersonates a real person/brand. Report to the platform immediately.",
    }
    action = _ACTIONS.get(final_verdict, "Exercise caution.")

    # ── Plain explanation ─────────────────────────────────────────────────────
    _PLAINS = {
        "REAL":         f"@{entity_lower} appears to be a genuine account. No major red flags were found in breach databases or social profile analysis.",
        "SUSPICIOUS":   f"@{entity_lower} has some unusual signals that suggest caution, but it's not conclusive. Verify before trusting.",
        "FAKE":         f"@{entity_lower} shows signs of being a bot or fake account, including patterns common in automated profiles.",
        "SCAMMER":      f"@{entity_lower} has active scam signals. The username pattern and profile behavior match known fraud profiles.",
        "BREACHED":     f"@{entity_lower} was found in {c_breach:,} data breach records. This means login details for this account may be circulating online.",
        "IMPERSONATOR": f"@{entity_lower} appears to be impersonating a real brand or organization. This is a common tactic used for phishing.",
    }
    plain = _PLAINS.get(final_verdict, f"Analysis complete for @{entity_lower}.")

    return UsernameVerdict(
        entity=entity, final_verdict=final_verdict,
        risk_level=risk_level, combined_score=combined,
        confidence=confidence, top_signals=all_signals,
        credential_signals=cred_signals, profile_signals=prof_signals,
        breach_count=c_breach, is_impersonator=is_impersonator,
        fraud_type=p_fraud, recommended_action=action, plain_explanation=plain,
    )
