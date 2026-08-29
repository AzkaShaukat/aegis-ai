"""app/services/profile_intelligence.py — Unified Profile Intelligence Engine."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class UnifiedVerdict:
    final_verdict: str
    confidence: int
    combined_score: int
    risk_level: str
    top_signals: list
    recommended_action: str
    credential_summary: str
    profile_summary: str
    plain_explanation: str


def compute_unified_verdict(identifier: str, credential_result: dict, profile_result: dict) -> UnifiedVerdict:
    c_risk  = (credential_result.get("overall_risk_level") or "").lower()
    c_score = int(credential_result.get("overall_risk_score", 0) or 0)
    c_flags = credential_result.get("all_flags", []) or []
    c_breach = int(credential_result.get("hibp_count", 0) or 0)

    verdict = profile_result.get("verdict", {}) or {}
    p_risk  = (verdict.get("risk_level") or "").lower()
    p_score = int(verdict.get("final_score", 0) or 0)
    p_flags = verdict.get("top_flags", []) or []
    p_fraud = (verdict.get("fraud_type") or "").lower()

    combined = int(p_score * 0.6 + c_score * 0.4)
    final_verdict = "REAL"
    confidence = 70

    imp_signals = [s for s in (c_flags + [str(f) for f in p_flags])
                   if any(w in str(s).lower() for w in ["impersonat","brand","typosquat","official"])]
    if imp_signals or "impersonat" in p_fraud:
        final_verdict, confidence, combined = "IMPERSONATOR", 85, max(combined, 75)
    elif "scammer" in p_fraud or "fraud" in p_fraud:
        final_verdict = "SCAMMER" if p_score >= 50 else "SUSPICIOUS"
        confidence = 80 if p_score >= 50 else 60
    elif "bot" in p_fraud or "fake" in p_fraud:
        final_verdict, confidence = "FAKE", 75
    elif c_breach > 0:
        final_verdict, confidence, combined = "BREACHED", 95, max(combined, 60)
    elif combined >= 70:
        final_verdict, confidence = "SUSPICIOUS", 70
    elif combined >= 40:
        final_verdict, confidence = "SUSPICIOUS", 55
    else:
        final_verdict, confidence = "REAL", 80

    risk_level = ("HIGH" if combined >= 75 else "MEDIUM" if combined >= 50
                  else "LOW" if combined >= 25 else "SAFE")

    all_signals = [f"[Credential] {f}" for f in c_flags[:3]]
    all_signals += [f"[Profile] {str(f).replace('_',' ').title()}" for f in p_flags[:3]]
    if c_breach > 0:
        all_signals.insert(0, f"Found in {c_breach:,} breach records (HIBP)")

    actions = {
        "REAL":         "This appears legitimate. No immediate action needed.",
        "SUSPICIOUS":   "Treat with caution. Verify through official channels.",
        "FAKE":         "Bot/fake signals detected. Do not engage or share personal data.",
        "SCAMMER":      "⚠️ Active scam signals. Block and report immediately.",
        "BREACHED":     "Credentials exposed in data breaches. Change passwords and enable 2FA now.",
        "IMPERSONATOR": "This impersonates a real person/brand. Report and block immediately.",
    }

    plains = {
        "REAL":         f"{identifier} appears to be a genuine account with no major red flags.",
        "SUSPICIOUS":   f"{identifier} has some suspicious signals worth investigating further.",
        "FAKE":         f"{identifier} shows patterns of a fake or automated account.",
        "SCAMMER":      f"{identifier} has active fraud and scam indicators — stay away.",
        "BREACHED":     f"{identifier} was found in {c_breach:,} data breach records.",
        "IMPERSONATOR": f"{identifier} appears to be impersonating a known brand or person.",
    }

    c_sum = f"Risk: {c_risk.upper() or 'Unknown'}, Score: {c_score}/100"
    if c_breach > 0: c_sum += f", Breached: {c_breach:,} records"
    p_sum = f"Risk: {p_risk.upper() or 'Unknown'}, Score: {p_score}/100"
    if p_fraud and p_fraud not in ("unknown",""): p_sum += f", Pattern: {p_fraud.replace('_',' ').title()}"

    return UnifiedVerdict(
        final_verdict=final_verdict, confidence=confidence, combined_score=combined,
        risk_level=risk_level, top_signals=all_signals[:6],
        recommended_action=actions.get(final_verdict, "Exercise caution."),
        credential_summary=c_sum, profile_summary=p_sum,
        plain_explanation=plains.get(final_verdict, f"Analysis complete for {identifier}."),
    )
