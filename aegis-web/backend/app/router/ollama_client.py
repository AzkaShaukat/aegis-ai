"""app/router/ollama_client.py — Local Ollama LLM client.

All calls have a hard 60-second timeout so they never block tests.
Fallback text is meaningful when Ollama is unavailable.

ENH-001: explain_result now always produces:
  "Legitimate/Suspicious because <reason>.
   Verdict: <verdict>.
   Action: <action>."
"""
from __future__ import annotations
import json, logging, re, random
from typing import Optional
import httpx
from app.core.config import get_settings
settings = get_settings()
OLLAMA_HOST = settings.ollama_host
MODEL = settings.ollama_model
settings = get_settings()
logger = logging.getLogger(__name__)
_TIMEOUT = httpx.Timeout(60.0, connect=4.0)


async def _ask(prompt: str, system: str = "", max_tokens: int = 350) -> Optional[str]:
    if not settings.ollama_enabled:
        return None
    payload = {
        "model":   settings.ollama_model,
        "prompt":  prompt,
        "stream":  False,
        "options": {"num_predict": max_tokens, "temperature": 0.85},
    }
    if system:
        payload["system"] = system
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(f"{settings.ollama_host}/api/generate", json=payload)
            if r.status_code == 200:
                return r.json().get("response", "").strip()
            else:
                logger.warning(f"Ollama returned {r.status_code}: {r.text[:100]}")
                return None
    except httpx.TimeoutException:
        logger.warning("Ollama timeout — skipping LLM enrichment")
        return None
    except Exception as e:
        logger.warning(f"Ollama error: {e}")
        return None


async def is_ollama_available() -> bool:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as c:
            r = await c.get(f"{settings.ollama_host}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


# ── ENH-001: Consistent explanation format ────────────────────────────────────
_EXPLAIN_SYSTEM = """You are Aegis AI, a cybersecurity expert writing scan explanations for WhatsApp users.

ALWAYS follow this EXACT format (no markdown headers, no bullet points inside):

Write 1-2 sentences explaining WHY the item is safe or dangerous using plain everyday words.
Address the user's specific context if they mentioned one (e.g. "your boss's email", "this phone number", etc.)
Then on a new line write:
Verdict: [SAFE / SUSPICIOUS / DANGEROUS / BREACHED / SCAM / NOT FOUND / VALID / etc.]
Then on a new line write:
Action: [one concrete action the user should take right now]

Rules:
- No jargon (no "entropy", "MX record", "heuristic", "HIBP"). Explain in simple words.
- For breach checks: say "appeared in X hacked databases" not "HIBP records".
- For safe credentials: say "not found in any leaked or hacked databases".
- Be direct and confident. No weak language like "looks like" or "might be".
- For phone/email belonging to someone else (boss, friend, stranger), address it as "their" not "your".
- Every response must feel different — vary sentence structure and vocabulary.
- Keep the full response under 120 words.

Example for breached email:
This email address appeared in 3 hacked database leaks, meaning someone may have access to accounts using this email and password combination.
Verdict: Breached.
Action: Change the password for any account linked to this email immediately, and enable two-factor authentication.

Example for safe phone:
This phone number shows no fraud signals — it's registered to a legitimate Pakistani carrier and hasn't appeared in any scammer databases.
Verdict: Safe.
Action: No immediate action needed, but always be cautious if this number contacts you unexpectedly."""


async def explain_result(
    module: str,
    risk_level: str,
    result: dict,
    user_question: str = "",
    custom_facts: str = ""
) -> Optional[str]:
    """Generate consistent security explanation in Reason → Verdict → Action format."""
    if custom_facts:
        facts = custom_facts
    else:
        facts = _extract_facts(module, result)
    if not facts:
        return None

    context_part = ""
    if user_question and len(user_question) > 3:
        context_part = f'User context: "{user_question[:150]}"\n'

    prompt = (
        f"{context_part}"
        f"Security scan results:\n{facts}\n\n"
        f"Risk level: {risk_level}\n\n"
        f"Write the explanation following the format in your instructions."
    )

    result_text = await _ask(prompt, system=_EXPLAIN_SYSTEM, max_tokens=200)
    if result_text:
        return result_text

    # Deterministic fallback — still in the required format
    risk_lower = (risk_level or "").lower()
    if "high" in risk_lower or "critical" in risk_lower:
        return (
            "Multiple security scanners flagged this item as malicious.\n"
            "Verdict: Dangerous.\n"
            "Action: Do not interact with this item under any circumstances."
        )
    elif "medium" in risk_lower:
        return (
            "Suspicious signals were detected but no confirmed malicious activity.\n"
            "Verdict: Suspicious.\n"
            "Action: Verify through official channels before proceeding."
        )
    elif "low" in risk_lower:
        return (
            "Minor anomalies were found but no active threats detected.\n"
            "Verdict: Low risk.\n"
            "Action: Proceed with caution and avoid sharing sensitive information."
        )
    else:
        return (
            "No threats or malicious indicators were found during the scan.\n"
            "Verdict: Safe.\n"
            "Action: You may proceed normally."
        )


def _extract_facts(module: str, result: dict) -> str:
    lines = []
    if module == "link":
        url = result.get("url", "")
        score = result.get("confidence_score", 0)
        vt = result.get("detection_counts", {})
        whois = result.get("whois", {})
        flags = result.get("all_flags", [])
        ml = result.get("ml_prediction", {})
        if url:        lines.append(f"URL: {url}")
        if score:      lines.append(f"Risk score: {score}/100")
        if vt:         lines.append(f"VirusTotal: {vt.get('malicious',0)}/{result.get('scanners_count',94)} flagged")
        age = whois.get("domain_age_days")
        if age is not None: lines.append(f"Domain age: {age} days")
        if flags:      lines.append(f"Warning flags: {', '.join(flags[:6])}")
        ml_prob = ml.get("phishing_probability")
        if ml_prob:    lines.append(f"AI phishing probability: {ml_prob:.0f}%")
        ssl = result.get("ssl", {})
        if ssl.get("is_valid") is False:
            lines.append("SSL certificate: Invalid or missing")
        elif ssl.get("is_valid"):
            lines.append("SSL certificate: Valid")
        redirects = result.get("redirects", {})
        if redirects.get("hop_count", 0) > 1:
            lines.append(f"Redirects: {redirects.get('hop_count')} hops to {redirects.get('final_url', '')[:60]}")

    elif module == "qr":
        qtype = result.get("qr_type", "")
        payload = result.get("decoded_payload", "")
        score = result.get("risk_score", 0)
        flags = result.get("all_flags", [])
        if qtype:   lines.append(f"QR type: {qtype}")
        if payload: lines.append(f"Content: {payload[:200]}")
        if score:   lines.append(f"Risk score: {score}/100")
        if flags:   lines.append(f"Warning flags: {', '.join(flags[:4])}")
        wifi = result.get("wifi", {})
        if wifi.get("security"):
            lines.append(f"WiFi security: {wifi.get('security')}")

    elif module == "credential":
        ctype  = result.get("credential_type", "")
        score  = result.get("overall_risk_score", 0)
        flags  = result.get("all_flags", [])
        breach = result.get("hibp_count")
        if ctype:   lines.append(f"Credential type: {ctype}")
        if score:   lines.append(f"Risk score: {score}/100")
        if flags:   lines.append(f"Issues: {', '.join(flags[:4])}")
        # HIBP / breach info — key for context-aware explanation
        if breach is not None:
            if breach > 0:
                lines.append(f"Found in {breach:,} data breach records (exposed in hacked databases)")
            else:
                lines.append("Not found in any known data breach databases")
        # Phone-specific
        ph = result.get("phone", {})
        if ph.get("carrier"): lines.append(f"Carrier: {ph.get('carrier')}")
        if ph.get("line_type"): lines.append(f"Line type: {ph.get('line_type')}")
        ipqs = result.get("ipqs_fraud_score")
        if ipqs: lines.append(f"Fraud score: {ipqs}/100")
        # Email-specific
        if result.get("is_disposable"): lines.append("Disposable/throwaway email address")
        if result.get("domain_has_mx") is False: lines.append("No mail server found for this domain")

    elif module == "profile":
        verdict = result.get("verdict", {})
        score = verdict.get("final_score", 0)
        ftype = verdict.get("fraud_type", "")
        flags = verdict.get("top_flags", [])
        if score:   lines.append(f"Suspicion score: {score}/100")
        if ftype:   lines.append(f"Fraud type: {ftype.replace('_',' ')}")
        if flags:   lines.append(f"Signals: {', '.join(str(f) for f in flags[:4])}")

    elif module == "deepfake":
        score = result.get("overall_risk_score", 0)
        prob = result.get("ensemble_probability", 0)
        flags = result.get("all_flags", [])
        face = result.get("face_info", {})
        note = result.get("confidence_note", "")
        if score: lines.append(f"Risk score: {score}/100")
        if prob:  lines.append(f"Fake probability: {int(prob*100)}%")
        if flags: lines.append(f"Flags: {', '.join(flags[:4])}")
        if face.get("faces_detected"): lines.append(f"Faces detected: {face['faces_detected']}")
        if note:  lines.append(f"Note: {note}")

    elif module in ("link_bulk", "smishing", "cyber_qa"):
        summary = result.get("summary", result.get("topic", ""))
        if summary: lines.append(summary)

    return "\n".join(lines)


# ── Follow-up context-aware explanation ───────────────────────────────────────
_FOLLOWUP_SYSTEM = """You are Aegis AI, a cybersecurity assistant answering follow-up questions on WhatsApp.
The user already received a scan result and is asking a follow-up question.
Answer in 2-4 short sentences using everyday language.
No jargon. Be direct and helpful.
Every response should feel different — vary wording and structure.
End with one concrete action if relevant."""


async def explain_followup(question: str, scan_context: str) -> Optional[str]:
    """Answer a follow-up question about a previous scan result using Ollama."""
    prompt = (
        f"Previous scan context:\n{scan_context}\n\n"
        f"User follow-up question: \"{question}\"\n\n"
        f"Answer the question based on the scan context."
    )
    return await _ask(prompt, system=_FOLLOWUP_SYSTEM, max_tokens=200)


# ── Social platform detector ──────────────────────────────────────────────────
def _rule_based_platform(u: str) -> dict:
    if re.match(r"^[a-z0-9._]{1,30}$", u) and "." in u:
        return {"platform": "instagram", "confidence": "medium"}
    if re.match(r"^[a-z0-9_]{1,15}$", u) and len(u) <= 15:
        return {"platform": "twitter", "confidence": "medium"}
    return {"platform": "unknown", "confidence": "low"}


async def detect_social_platform(username: str) -> dict:
    u = username.lower()
    rule = _rule_based_platform(u)
    if rule["confidence"] == "high":
        return rule
    result = await _ask(
        f'Username: "{username}". Most likely social platform?',
        system='Respond ONLY with JSON: {"platform":"instagram|twitter|tiktok|facebook|linkedin|unknown","confidence":"high|medium|low"}',
        max_tokens=60,
    )
    if not result:
        return rule
    try:
        return json.loads(re.sub(r"```json|```", "", result).strip())
    except Exception:
        return rule


# ── Smishing (with keyword fallback) ─────────────────────────────────────────
_SMISH_SYS = """You are a Pakistani cybersecurity analyst detecting SMS phishing (smishing).
Respond ONLY with JSON: {"is_smishing":true/false,"confidence":0-100,"reason":"one plain sentence","category":"financial_fraud|otp_theft|prize_scam|account_alert|legitimate"}"""


async def classify_smishing(sms_text: str) -> dict:
    result = await _ask(f'Analyse this SMS:\n"""{sms_text}"""', system=_SMISH_SYS, max_tokens=120)
    if not result:
        return _keyword_smishing_fallback(sms_text)
    try:
        return json.loads(re.sub(r"```json|```", "", result).strip())
    except Exception:
        return _keyword_smishing_fallback(sms_text)


def _keyword_smishing_fallback(text: str) -> dict:
    t = text.lower()
    SMISH_KW = {
        "otp":25, "pin":20, "jazzcash":30, "easypaisa":30, "hbl":25,
        "meezan":20, "ubl":20, "account blocked":40, "account suspended":40,
        "urgent":15, "immediately":15, "verify":10, "claim":20,
        "prize":25, "won":25, "winner":30, "congratulations":20,
        "cnic":20, "national id":20, "bank account":25, "send money":30,
        "suspended":20, "expired":15, "free":10, "limited":10,
        "dear customer":30, "click here":20, "bit.ly":15, "tinyurl":15,
    }
    score = sum(v for kw, v in SMISH_KW.items() if kw in t)
    score = min(score, 100)
    is_s = score >= 40
    cats = []
    if any(k in t for k in ["prize", "won", "winner", "congratulations"]): cats.append("prize_scam")
    if any(k in t for k in ["otp", "pin", "verify", "account blocked"]):   cats.append("otp_theft")
    if any(k in t for k in ["bank", "transfer", "jazzcash", "easypaisa"]): cats.append("financial_fraud")
    cat = cats[0] if cats else ("legitimate" if not is_s else "financial_fraud")
    reasons = []
    if "cnic" in t:             reasons.append("asks for CNIC number")
    if any(k in t for k in ["prize", "won"]): reasons.append("fake prize claim")
    if any(k in t for k in ["otp", "pin"]):   reasons.append("requests OTP/PIN")
    if any(k in t for k in ["account blocked", "suspended"]): reasons.append("fake account suspension")
    reason = "Message contains " + " and ".join(reasons) if reasons else "No clear smishing pattern"
    return {"is_smishing": is_s, "confidence": score, "reason": reason, "category": cat}


# ── Urdu intent ───────────────────────────────────────────────────────────────
_URDU_SYS = """You are a cybersecurity assistant. User sent Urdu or Roman Urdu.
Determine: 1=URL/link  2=credential  3=social profile  4=cyber question  5=small talk
Respond ONLY with JSON: {"intent":"url|credential|profile|cyber_qa|offtopic","extracted":"key entity","english_summary":"brief summary"}"""


async def classify_urdu(text: str) -> dict:
    result = await _ask(f'Classify:\n"""{text}"""', system=_URDU_SYS, max_tokens=100)
    if not result:
        return {"intent": "offtopic", "extracted": "", "english_summary": ""}
    try:
        return json.loads(re.sub(r"```json|```", "", result).strip())
    except Exception:
        return {"intent": "offtopic", "extracted": "", "english_summary": ""}


# ── Follow-up intent ──────────────────────────────────────────────────────────
_FOL_SYS = """You are a context-aware cybersecurity bot assistant.
Given the last scan summary and user follow-up, determine intent.
Respond ONLY with JSON: {"intent":"rescan|explain|action_advice|ask_more|unrelated","detail":"brief"}"""


async def classify_followup(message: str, last_scan_summary: str) -> dict:
    prompt = f"Last scan: {last_scan_summary}\nUser says: \"{message}\""
    result = await _ask(prompt, system=_FOL_SYS, max_tokens=80)
    if not result:
        return {"intent": "unrelated", "detail": ""}
    try:
        return json.loads(re.sub(r"```json|```", "", result).strip())
    except Exception:
        return {"intent": "unrelated", "detail": ""}


# ── Cyber Q&A ─────────────────────────────────────────────────────────────────
_CYBER_QA_SYSTEM = """You are Aegis AI, a cybersecurity expert on WhatsApp helping Pakistani users.
Answer the cybersecurity question in 3-5 short sentences.
Use simple everyday words — no jargon.
Mention Pakistani context where relevant (FIA Cyber Crime: 0800-55555, JazzCash, HBL, NADRA).
Use WhatsApp markdown: *bold* for key terms.
End with one concrete action the user can take right now.
Every answer must feel fresh — vary structure, examples, and phrasing."""


async def answer_cyber_qa(question: str) -> Optional[str]:
    """Answer a cybersecurity question using Ollama. Always different response."""
    return await _ask(question, system=_CYBER_QA_SYSTEM, max_tokens=350)
