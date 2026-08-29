"""
utils.py
Aegis Link Analyzer

Weighted multi-source risk classification engine.

CHANGELOG (scoring fix)
───────────────────────
Problem: New/dead phishing domains (NXDOMAIN) with 0 VirusTotal detections
         were scoring too low because:
           1. VT weight was 30% — when VT is clean, 30 pts vanish before scoring starts.
              VirusTotal routinely misses brand-new or already-taken-down phishing domains.
           2. DNS weight was only 8% — an NXDOMAIN score of 70 contributed only 5.6 pts.
              A domain that doesn't even resolve is a major red flag.
           3. Heuristics critical-signal threshold was 60; a heuristic_score of 53
              (brand typosquatting + phishing keyword) narrowly missed the threshold.
           4. The structural-phishing floor was set to 35 — exactly the Medium/High
              boundary, so the URL landed at the very bottom of Medium Risk.
           5. ML prediction was run AFTER classify_risk() and its result was never
              fed back into the final score.

Fixes applied:
  • VT weight reduced:       0.30 → 0.18
  • Heuristics weight raised: 0.15 → 0.26
  • DNS weight raised:        0.08 → 0.16
  • Heuristics critical threshold lowered: 60 → 45
  • WHOIS critical threshold lowered:      50 → 40
  • n_critical == 1 now applies a floor of 20 (was no floor)
  • n_critical == 2 floor raised: 45 → 55
  • New high-heuristics-only floors:
      heuristic_score >= 90 → floor 65  (High Risk)
      heuristic_score >= 80 → floor 55
      heuristic_score >= 70 → floor 40
  • Structural phishing pattern floor raised: 35 → 65
      (brand typosquat + dead DNS + no WHOIS = almost certainly phishing)
  • New "brand embedding + dead domain" override:
      heuristic_score >= 35 AND dns_score >= 60 → floor 65
  • ML-assisted floor added (conservative):
      ml_phishing_probability >= 70% AND current score < 28 → floor 28
  • Risk thresholds adjusted:
      High Risk:   >= 65 → >= 60
      Medium Risk: >= 35 → >= 28
      Low Risk:    >= 15 → >= 10
      Safe:         < 15 →  < 10

Result for amazon-deals-pk.net/login:
  Before: combined_final = 35  → Medium Risk  ✗
  After:  combined_final = 65  → High Risk    ✓
"""

from typing import Dict, List, Optional, Tuple

# ─── Source weights ──────────────────────────────────────────────────────────
# Must sum to exactly 1.0.
# VT is still the highest single weight but reduced — it lags badly on new
# phishing domains that haven't been submitted to any threat feed yet.
# Heuristics and DNS are the most reliable *local* signals when feeds are cold.
WEIGHTS = {
    "virustotal":  0.18,   # reduced from 0.30
    "heuristics":  0.26,   # raised  from 0.15
    "whois":       0.13,   # reduced from 0.15
    "dns":         0.16,   # raised  from 0.08
    "ssl":         0.08,   # raised  from 0.07
    "redirects":   0.09,   # reduced from 0.10
    "urlhaus":     0.05,   # reduced from 0.07
    "phishtank":   0.03,   # reduced from 0.05
    "gsb":         0.02,   # reduced from 0.03
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9, "WEIGHTS must sum to 1.0"

# ─── Risk level thresholds ───────────────────────────────────────────────────
HIGH_THRESHOLD   = 60    # was 65
MEDIUM_THRESHOLD = 28    # was 35
LOW_THRESHOLD    = 10    # was 15


def vt_stats_to_score(stats: Dict[str, int]) -> float:
    """Convert raw VirusTotal detection counts to a 0-100 score."""
    if not stats:
        return 0.0
    return float(min(stats.get("malicious", 0) * 20 + stats.get("suspicious", 0) * 10, 100))


def _critical_signals(
    vt_stats: Dict[str, int],
    heuristic_score: float,
    whois_score: float,
    dns_score: float,
    ssl_score: float,
    redirect_score: float,
    urlhaus_score: float,
    phishtank_score: float,
    gsb_score: float,
) -> Tuple[int, List[str]]:
    """
    Identify which sources crossed their individual alert thresholds.

    A "critical signal" means that source alone has enough evidence to
    indicate a real threat — even if the weighted sum is low.

    Returns (count, list_of_source_labels).
    """
    malicious  = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)
    triggered: List[str] = []

    # VirusTotal
    if malicious >= 3:
        triggered.append("VirusTotal (malicious≥3)")
    elif malicious >= 1 and suspicious >= 2:
        triggered.append("VirusTotal (malicious+suspicious)")

    # Local analysis — thresholds lowered to catch more subtle patterns
    if heuristic_score >= 45:   # was 60
        triggered.append(f"Heuristics (score={heuristic_score})")
    if whois_score >= 40:       # was 50
        triggered.append(f"WHOIS (score={whois_score})")
    if dns_score >= 40:         # unchanged
        triggered.append(f"DNS (score={dns_score})")
    if redirect_score >= 50:    # unchanged
        triggered.append(f"Redirects (score={redirect_score})")

    # Definitive feed hits
    if urlhaus_score >= 80:
        triggered.append("URLhaus")
    if phishtank_score >= 80:
        triggered.append("OpenPhish")
    if gsb_score >= 80:
        triggered.append("Google Safe Browsing")

    return len(triggered), triggered


def classify_risk(
    vt_stats: Dict[str, int],
    heuristic_score: float = 0.0,
    whois_score: float = 0.0,
    dns_score: float = 0.0,
    ssl_score: float = 0.0,
    redirect_score: float = 0.0,
    urlhaus_score: float = 0.0,
    phishtank_score: float = 0.0,
    gsb_score: float = 0.0,
    ml_phishing_probability: float = 0.0,
) -> Tuple[str, float, Dict]:
    """
    Compute the combined risk level, confidence score, and score breakdown.

    Parameters
    ----------
    vt_stats : dict
        Raw VirusTotal detection-count dict from the API.
    heuristic_score … gsb_score : float
        Per-source risk scores on a 0–100 scale.
    ml_phishing_probability : float
        0–100 probability output from the ML classifier.
        Used as a conservative floor only — the ML model is known to
        overfit on training data so it never overrides strong feed evidence.

    Returns
    -------
    risk_level : str
        One of "Safe", "Low Risk", "Medium Risk", "High Risk".
    confidence : float
        Combined final score 0–100 (same as breakdown["combined_final"]).
    breakdown : dict
        Per-source weighted contributions + metadata.
    """
    vt_score  = vt_stats_to_score(vt_stats)
    malicious  = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)

    # ── Base weighted sum ────────────────────────────────────────────────────
    score = (
        vt_score         * WEIGHTS["virustotal"] +
        heuristic_score  * WEIGHTS["heuristics"] +
        whois_score      * WEIGHTS["whois"]      +
        dns_score        * WEIGHTS["dns"]         +
        ssl_score        * WEIGHTS["ssl"]         +
        redirect_score   * WEIGHTS["redirects"]   +
        urlhaus_score    * WEIGHTS["urlhaus"]     +
        phishtank_score  * WEIGHTS["phishtank"]   +
        gsb_score        * WEIGHTS["gsb"]
    )

    # ── Hard overrides — VirusTotal confirmations ────────────────────────────
    # VT with many detections = confirmed threat; floors override the weighted sum.
    if malicious >= 5:
        score = max(score, 90.0)
    elif malicious >= 3 or (malicious >= 1 and suspicious >= 2):
        score = max(score, 65.0)

    # ── Hard overrides — definitive feed hits ────────────────────────────────
    # A single positive hit in a curated threat feed is highly reliable.
    if phishtank_score >= 90 or urlhaus_score >= 90 or gsb_score >= 90:
        score = max(score, 90.0)

    # ── Hard overrides — critical signal agreement ───────────────────────────
    # Multiple independent sources crossing their own thresholds = corroborated threat.
    n_critical, critical_sources = _critical_signals(
        vt_stats, heuristic_score, whois_score, dns_score,
        ssl_score, redirect_score, urlhaus_score, phishtank_score, gsb_score,
    )
    if n_critical >= 3:
        score = max(score, 80.0)
    elif n_critical == 2:
        score = max(score, 55.0)   # was 45 — two corroborating sources = Medium-High minimum
    elif n_critical == 1:
        score = max(score, 20.0)   # NEW — even a single alert source = at least Low Risk

    # ── Hard overrides — redirect corroboration ──────────────────────────────
    if redirect_score >= 50 and malicious >= 1:
        score = max(score, 38.0)
    elif redirect_score >= 70:
        score = max(score, 25.0)

    # ── Hard overrides — high heuristic score alone ──────────────────────────
    # When local structural analysis is very confident, we don't need feed
    # confirmation to escalate — new phishing domains are routinely missed
    # by VT/URLhaus for days after they go live.
    if heuristic_score >= 90:
        score = max(score, 65.0)   # Near-certain phishing pattern → High Risk
    elif heuristic_score >= 80:
        score = max(score, 55.0)
    elif heuristic_score >= 70:
        score = max(score, 40.0)

    # ── Hard override — structural phishing: brand + dead DNS + no WHOIS ─────
    # A URL that has brand typosquatting AND a dead/blackhole domain (NXDOMAIN
    # or no NS) AND no WHOIS is almost certainly a phishing domain that was
    # recently registered, used for a campaign, and may already be taken down.
    # This is the pattern for amazon-deals-pk.net/login and similar URLs.
    #
    # Raised from 35 → 65 (was just barely Medium Risk; should be High Risk).
    if heuristic_score >= 50 and dns_score >= 60 and whois_score >= 10:
        score = max(score, 65.0)

    # ── Hard override — brand embedding + dead domain ────────────────────────
    # Brand name in domain (paypal, amazon, etc.) + NXDOMAIN/no-NS = phishing.
    # Covers cases where whois_score is low but DNS clearly shows a dead domain.
    if heuristic_score >= 35 and dns_score >= 60:
        score = max(score, 65.0)

    # ── ML-assisted floor (conservative) ────────────────────────────────────
    # The ML classifier is known to overfit (training_accuracy = 1.0), so we
    # use its output only as a conservative Medium-Risk floor and never to
    # escalate directly to High Risk.
    if ml_phishing_probability >= 70 and score < 28:
        score = max(score, 28.0)

    # ── Final score → risk level ─────────────────────────────────────────────
    final = round(min(score, 100.0), 2)

    if final >= HIGH_THRESHOLD:
        risk = "High Risk"
    elif final >= MEDIUM_THRESHOLD:
        risk = "Medium Risk"
    elif final >= LOW_THRESHOLD:
        risk = "Low Risk"
    else:
        risk = "Safe"

    breakdown = {
        "heuristics": round(heuristic_score  * WEIGHTS["heuristics"], 2),
        "whois":      round(whois_score       * WEIGHTS["whois"],      2),
        "dns":        round(dns_score         * WEIGHTS["dns"],         2),
        "ssl":        round(ssl_score         * WEIGHTS["ssl"],         2),
        "redirects":  round(redirect_score    * WEIGHTS["redirects"],   2),
        "virustotal": round(vt_score          * WEIGHTS["virustotal"],  2),
        "urlhaus":    round(urlhaus_score     * WEIGHTS["urlhaus"],     2),
        "phishtank":  round(phishtank_score   * WEIGHTS["phishtank"],   2),
        "gsb":        round(gsb_score         * WEIGHTS["gsb"],         2),
        "combined_final":              final,
        "critical_signals_triggered":  n_critical,
        "critical_sources":            critical_sources,
    }

    return risk, final, breakdown


def render_message(url: str, risk: str, confidence: float) -> str:
    safe_pct = round(100 - confidence, 1)
    if risk == "High Risk":
        return (
            f"⚠️ HIGH RISK: The link ({url}) shows strong indicators of being malicious. "
            f"Threat confidence: {confidence}%. Do not visit this URL."
        )
    elif risk == "Medium Risk":
        return (
            f"⚠️ CAUTION: The link ({url}) has suspicious characteristics. "
            f"Threat confidence: {confidence}%. Proceed only if you trust the source."
        )
    elif risk == "Low Risk":
        return (
            f"🟡 LOW RISK: The link ({url}) has minor suspicious signals. "
            f"Appears mostly safe ({safe_pct}% confidence). Stay cautious."
        )
    return (
        f"✅ SAFE: The link ({url}) shows no significant threat indicators. "
        f"({safe_pct}% confidence it is not malicious)"
    )
