"""app/formatters/responses.py — All WhatsApp message templates.

New unified format for ALL scan types:
  Header line (emoji + type + verdict)
  URL/item line
  Human explanation (from Ollama, passed in)
  ⚙️ Technical Details block
  VT Report / Screenshot link

Covers all Phase 1 scenarios.
"""
from __future__ import annotations
from typing import Optional
import re

import time

def _format_ts(ts: float) -> str:
    """Convert timestamp to HH:MM string."""
    if not ts:
        return ""
    local_time = time.localtime(ts)
    return time.strftime("%H:%M", local_time)

# ── Risk helpers ──────────────────────────────────────────────────────────────

def _risk_emoji(risk: str) -> str:
    r = (risk or "").lower()
    if "high" in r or "critical" in r: return "🔴"
    if "medium" in r:                  return "🟠"
    if "low" in r:                     return "🟡"
    return "🟢"

def _risk_badge(risk: str) -> str:
    r = (risk or "").lower()
    if "high" in r or "critical" in r: return "🚨 HIGH RISK"
    if "medium" in r:                  return "⚠️ MEDIUM RISK"
    if "low" in r:                     return "🟡 LOW RISK"
    return "✅ SAFE"

def _age_str(days: int) -> str:
    if not days: return "Unknown"
    y, d = divmod(int(days), 365)
    return f"{y}y {d}d" if y else f"{d}d"

def _short(url: str, max_len: int = 50) -> str:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return (p.netloc or url).replace("www.", "")[:max_len]
    except Exception:
        return url[:max_len]

def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n-3] + "..."

_PRIVACY_NOTE = "🔒 _Raw value not stored. SHA-256 hash only._"


# ═══════════════════════════════════════════════════════════════════════════════
# LINK ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

def format_link_scan(url: str, result: dict, human_explanation: str = "") -> str:
    """Unified link scan result — new format."""
    risk    = result.get("risk_level", "Unknown")
    score   = result.get("confidence_score", 0)
    flags   = result.get("total_flags", 0)
    bd      = result.get("score_breakdown", {})
    ml      = result.get("ml_prediction", {})
    whois   = result.get("whois", {})
    vt_det  = result.get("detection_counts", {})
    vt_rep  = result.get("virustotal_report", "")
    redir   = result.get("redirects", {})
    ssl_d   = result.get("ssl", {})
    all_flags = result.get("all_flags", [])
    scanners  = result.get("scanners_count", 94)
    screenshot = result.get("screenshot_url", "")
    report_url = result.get("report_url", "")

    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)
    domain = _short(url)

    lines = [f"{badge} — Link Analysis"]
    lines.append(f"🔗 {url}")
    lines.append("")

    # Human explanation (centre of the reply, most prominent)
    # Plain explanation — always show something (Ollama if available, fallback if not)
    if human_explanation:
        lines.append(human_explanation)
    else:
        # Static fallback explanation based on risk
        _risk_lower = risk.lower() if risk else ""
        _domain_age = whois.get("domain_age_days", 0) or 0
        _vt_clean = vt_det.get("malicious", 0) == 0
        _flags_count = len(all_flags)
        if "safe" in _risk_lower or "low" in _risk_lower:
            lines.append(
                f"This link looks safe. "
                f"{'The domain has been around for ' + str(int(_domain_age/365)) + ' years, which is a good sign. ' if _domain_age > 365 else ''}"
                f"{'All ' + str(scanners) + ' antivirus engines gave it a clean result.' if _vt_clean else ''}"
            )
        elif "high" in _risk_lower or "critical" in _risk_lower:
            lines.append(
                f"⚠️ This link is dangerous. "
                f"{str(_flags_count) + ' warning signals were detected. ' if _flags_count else ''}"
                f"Do not click, visit, or share it."
            )
        else:
            lines.append(
                f"This link has some suspicious signals. "
                f"{'It triggered ' + str(_flags_count) + ' warning flags. ' if _flags_count else ''}"
                f"Proceed with caution."
            )
    lines.append("")

    # Technical details block
    lines.append("⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk Level: {emoji} {risk.upper()}")
    lines.append(f"🤖 Confidence: {score:.1f}%")
    lines.append(f"🚩 Flags: {flags}")

    # VT
    mal = vt_det.get("malicious", 0)
    sus = vt_det.get("suspicious", 0)
    if mal > 0:
        lines.append(f"🦠 Antivirus: 🔴 {mal}/{scanners} engines flagged")
    else:
        lines.append(f"🦠 Antivirus: ✅ Clean ({scanners} engines checked)")

    # Domain age
    age = whois.get("domain_age_days")
    if age:
        lines.append(f"📅 Domain Age: {_age_str(age)}")

    # Redirect chain
    hops = redir.get("hop_count", 0)
    final_url = redir.get("final_url", "")
    if hops > 1 and final_url and final_url != url:
        lines.append(f"   ↪️ Final URL: {final_url}")

    # Top flags (only if any)
    if all_flags:
        lines.append("")
        lines.append("⚠️ *Signals:*")
        for f in all_flags[:5]:
            lines.append(f"• {f}")
        if len(all_flags) > 5:
            lines.append(f"• ...and {len(all_flags)-5} more")

    # Action advice
    rl = risk.lower()
    lines.append("")
    if "high" in rl or "critical" in rl:
        lines.append("🚫 *Do NOT visit this URL.*")
    elif "medium" in rl:
        lines.append("⚠️ Verify through another channel before proceeding.")
    else:
        lines.append("✅ Safe to visit.")

    # VT report only (no URLScan link, no reportphishing email)
    if vt_rep:
        lines.append(f"📋 Report: {vt_rep}")

    return "\n".join(lines)


def format_link_bulk(results: list[dict], user_context: str = "", human_explanation: str = "") -> str:
    has_high = any("high" in r.get("risk_level","").lower() or "critical" in r.get("risk_level","").lower() for r in results)
    has_safe = any("safe" in r.get("risk_level","").lower() or "low" in r.get("risk_level","").lower() for r in results)

    if user_context and ("check these" in user_context.lower() or len(results) > 1):
        if has_high and has_safe:
            opening = f"I checked all {len(results)} links. Here's what I found — one is safe, but another is dangerous:"
        elif has_high:
            opening = f"⚠️ I checked all {len(results)} links. Be careful — I found threats:"
        else:
            opening = f"✅ I checked all {len(results)} links. They all look safe:"
    else:
        opening = f"🔍 *Found {len(results)} URLs — scanning concurrently...*"

    lines = [opening, ""]

    # Human explanation (if provided)
    if human_explanation:
        lines.append(human_explanation)
    elif has_high:
        lines.append("Some of these links are dangerous. Do not click on any that show high risk. I'll mark them below.")
    else:
        lines.append("All links appear safe based on my checks. However, always be cautious. Details for each link:")
    lines.append("")

    for i, r in enumerate(results, 1):
        url = r.get("url", "")
        risk = r.get("risk_level", "Unknown")
        score = r.get("confidence_score", 0)
        badge = _risk_badge(risk)
        all_flags = r.get("all_flags", [])
        vt = r.get("detection_counts", {})
        vt_mal = vt.get("malicious", 0)
        vt_total = r.get("scanners_count", 95)
        whois = r.get("whois", {})
        age_days = whois.get("domain_age_days", 0)
        age_str = _age_str(age_days) if age_days else "Unknown"

        lines.append(f"━━━ *URL {i}:* {url}")   # full URL, not truncated
        lines.append(f"{badge} — Score: {score:.1f}/100")
        if all_flags:
            lines.append(f"• Top flag: {all_flags[0]}")
        if vt_mal > 0:
            lines.append(f"• 🦠 {vt_mal}/{vt_total} antivirus engines flagged as malicious")
        else:
            lines.append(f"• 🦠 Clean by all {vt_total} antivirus engines")

        # FIX-002: Replace "Unknown" domain age with next best available field
        if age_days and age_days > 0:
            lines.append(f"• 📅 Domain age: {_age_str(age_days)}")
        else:
            # Try SSL status
            ssl_d = r.get("ssl", {})
            if ssl_d.get("is_valid") is True:
                issuer = ssl_d.get("issuer", "")
                ssl_line = f"• 🔒 SSL: Valid" + (f" ({issuer})" if issuer else "")
                lines.append(ssl_line)
            elif ssl_d.get("is_valid") is False:
                lines.append("• 🔓 SSL: Invalid or missing (warning)")
            else:
                # Try redirect chain
                redir = r.get("redirects", {})
                hops  = redir.get("hop_count", 0)
                if hops and hops > 0:
                    lines.append(f"• ↪️ Redirects: {hops} hop(s)")
                else:
                    # Try ML phishing probability
                    ml = r.get("ml_prediction", {})
                    ml_prob = ml.get("phishing_probability")
                    if ml_prob is not None:
                        lines.append(f"• 🤖 AI phishing probability: {ml_prob:.0f}%")
                    else:
                        # Fallback: total flags count
                        n_flags = len(all_flags)
                        lines.append(f"• 🚩 Warning signals: {n_flags}")

        vt_rep = r.get("virustotal_report", "")
        if vt_rep:
            lines.append(f"• 📋 Report: {vt_rep}")
        lines.append("")

    if has_high:
        lines.append("🔴 *Do NOT open any of the high-risk URLs.*")
    else:
        lines.append("✅ All clear. You can safely visit these links.")
    return "\n".join(lines)

    
def format_link_social_dual(url: str, result: dict, handle: str, human_explanation: str = "") -> str:
    link_part = format_link_scan(url, result, human_explanation)
    return (
        link_part
        + f"\n\n━━━━━━━━━━━━━━━━━━━\n"
        + f"👤 This is a social media profile URL.\n"
        + f"Want me to also analyse *@{handle}* for fake account / bot signals?\n"
        + f"Reply *YES* to run a profile analysis."
    )


def format_link_async_submitted(job_id: str, url: str) -> str:
    short_id = job_id[:8] if len(job_id) >= 8 else job_id
    return (
        f"📤 *Scan submitted!* Job ID: `{short_id}`\n\n"
        f"🔍 Scanning: {url}\n"
        f"⏱️ I'll notify you when done (~60–90 seconds).\n\n"
        f"Send: `/status {short_id}` to check manually."
    )


def format_link_async_complete(url: str, result: dict, human_explanation: str = "") -> str:
    domain = _short(url)
    return (
        f"🔔 *Scan Complete* — {domain}\n\n"
        + format_link_scan(url, result, human_explanation)
    )


def format_link_domain_disambig(domain: str) -> str:
    return (
        f"🔍 `{domain}` — it looks like a domain name.\n\n"
        f"What would you like to do?\n"
        f"1️⃣ Scan as a URL — check if {domain} is safe to visit\n"
        f"2️⃣ Check as a credential / username — impersonation risk\n\n"
        f"Reply *1* or *2*."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# QR SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def format_qr_result(result: dict, human_explanation: str = "") -> str:
    """Type-specific QR result format."""
    risk      = result.get("overall_risk", result.get("risk_level", "Safe"))
    score     = result.get("risk_score", result.get("confidence_score", 0))
    n_flags   = result.get("total_flags", 0)
    qr_type   = (result.get("qr_type", "") or "").lower()
    payload   = result.get("decoded_payload", result.get("payload", "")) or ""
    stego     = result.get("steganography_detected", False)
    all_flags = result.get("all_flags", [])
    vt_report = result.get("link_scan", {}).get("virustotal_report", "") if isinstance(result.get("link_scan"), dict) else ""
    vt_count  = result.get("link_scan", {}).get("detection_counts", {}).get("malicious", 0) if isinstance(result.get("link_scan"), dict) else 0
    vt_total  = result.get("link_scan", {}).get("scanners_count", 95) if isinstance(result.get("link_scan"), dict) else 95

    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)
    rl    = (risk or "").lower()

    # Type labels
    type_map = {
        "url":"URL / Link","wifi":"WiFi Configuration","vcard":"Contact Card (vCard)",
        "email":"Email Address","sms":"SMS Message","crypto":"Crypto Wallet",
        "geo":"Geographic Location","text":"Plain Text","mecard":"Contact (MeCard)",
    }
    type_label = type_map.get(qr_type, "Unknown")
    type_emoji = {
        "url":"🌐","wifi":"📶","vcard":"👤","email":"📧","sms":"💬",
        "crypto":"₿","geo":"📍","text":"📄","mecard":"👤",
    }.get(qr_type, "📋")

    lines = [f"{badge} — QR Code Analysis"]
    lines.append(f"{type_emoji} Type: *{type_label}*")
    lines.append("")

    # Human explanation
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")

    # Type-specific payload display
    if qr_type == "url" and payload:
        lines.append(f"🌐 *Payload (URL)*")
        lines.append(f"  {_truncate(str(payload), 80)}")
        if vt_count is not None:
            lines.append(f"  🦠 Antivirus: {'✅ ' + str(vt_count) + ' flagged' if vt_count == 0 else '🔴 ' + str(vt_count) + ' flagged'} / {vt_total} engines")
        if vt_report:
            lines.append(f"  📋 Report: {vt_report}")

    elif qr_type == "wifi":
        wifi = result.get("wifi", {})
        if wifi.get("ssid"):    lines.append(f"📶 Network: `{wifi['ssid']}`")
        if wifi.get("security"): lines.append(f"🔒 Security: {wifi['security']}")
        lines.append("🔑 Password: [Hidden]")

    elif qr_type in ("vcard","mecard"):
        vcard = result.get("vcard", {})
        for k, em in [("name","👤"),("phone","📱"),("email","📧"),("company","🏢"),("url","🌐")]:
            if vcard.get(k): lines.append(f"{em} {k.title()}: {vcard[k]}")

    elif qr_type == "email":
        email_data = result.get("email_data", {})
        if email_data.get("to"):      lines.append(f"📧 To: {email_data['to']}")
        if email_data.get("subject"): lines.append(f"📌 Subject: {_truncate(email_data['subject'],60)}")
        if email_data.get("body"):    lines.append(f"📝 Body: _{_truncate(email_data['body'],100)}_")

    elif qr_type == "sms":
        sms_data = result.get("sms_data", {})
        if sms_data.get("number"): lines.append(f"📱 To: {sms_data['number']}")
        if sms_data.get("body"):   lines.append(f"💬 Message: _{_truncate(sms_data['body'],100)}_")

    elif qr_type == "crypto":
        if payload: lines.append(f"₿ Address: `{_truncate(str(payload),50)}`")

    elif payload and str(payload).strip():
        lines.append(f"📄 Content: `{_truncate(str(payload), 80)}`")

    lines.append("")

    # Technical block
    obfuscation = result.get("obfuscation_layers", 0)
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"📊 Score: {score:.0f}/100")
    lines.append(f"🔍 Obfuscation Detected: {obfuscation} encoding layer(s)")

    if stego:
        hidden = result.get("steganography", {}).get("hidden_bytes", 0)
        lines.append(f"🕵️ Steganography: ~{hidden}KB hidden data detected in image pixels")

    if all_flags:
        lines.append("")
        for f in all_flags[:5]:
            lines.append(f"• {f}")

    lines.append("")
    if "high" in rl or "critical" in rl:
        lines.append(f"🆘 *{risk.upper()} THREAT — DO NOT interact with this QR.*")
        if qr_type in ("url", "payment", ""):
            lines.append("⚠️ *QRLjacking Risk:* Check for stickers placed over legitimate QRs.")
        lines.append("Report to FIA Cyber Crime: nia.gov.pk / 0800-55555")
    elif "medium" in rl:
        lines.append("⚠️ Treat with caution. Verify before interacting.")
    else:
        lines.append("✅ This QR code appears safe. No significant threat indicators detected.")

    lines.append("_Aegis AI — QR Scanner_")
    return "\n".join(lines)


def format_qr_vcard(result: dict, human_explanation: str = "") -> str:
    vcard = result.get("vcard", {})
    risk  = result.get("overall_risk", "Safe")
    score = result.get("risk_score", 0)
    badge = _risk_badge(risk)

    lines = [f"{badge} — QR Code Analysis"]
    lines.append("📋 Type: Contact (vCard)")
    lines.append("")

    if human_explanation:
        lines.append(human_explanation)
        lines.append("")

    lines.append("👤 *Contact Details:*")
    for key in ("name", "phone", "email", "company", "url"):
        val = vcard.get(key, "")
        if val:
            lines.append(f"• {key.capitalize()}: {val}")

    lines.append(f"\n⚙️ Risk Score: {score:.1f}/100")
    lines.append("✅ This appears to be a legitimate business contact QR." if score < 30
                 else "⚠️ Treat with caution.")
    return "\n".join(lines)


def format_qr_wifi(result: dict) -> str:
    wifi  = result.get("wifi", {})
    risk  = result.get("overall_risk", "Low")
    score = result.get("risk_score", 15)
    badge = _risk_badge(risk)
    flags = result.get("all_flags", [])

    lines = [
        f"{badge} — QR Code Analysis",
        "📋 Type: WiFi Configuration",
        "",
        f"📡 Network: `{wifi.get('ssid', 'Unknown')}`",
        f"🔒 Security: {wifi.get('security', 'WPA2')}",
        "🔑 Password: [Hidden for your privacy]",
        "",
        f"⚙️ Risk Score: {score:.1f}/100",
    ]
    for f in flags[:3]:
        lines.append(f"• {f}")
    lines += [
        "",
        "⚠️ Only connect if you can verify this network belongs to this location.",
        "🔒 Avoid banking on public WiFi without a VPN.",
    ]
    return "\n".join(lines)


def format_qr_crypto_scam(address: str) -> str:
    return (
        f"🚨 HIGH RISK — QR Code Analysis\n"
        f"📋 Type: Crypto Address\n"
        f"💰 Address: `{_truncate(address, 40)}`\n\n"
        f"⛔ *SCAM ALERT*\n\n"
        f"'Send crypto to verify your account' is a documented advance-fee scam.\n"
        f"No legitimate service requires you to send crypto to verify anything.\n\n"
        f"🚫 *DO NOT send any cryptocurrency. Block this contact immediately.*"
    )


def format_qr_no_qr_found() -> str:
    return (
        "📷 Image received — scanning for QR codes...\n\n"
        "❌ *No QR code detected in this image.*\n\n"
        "💡 Try again with:\n"
        "• Better lighting\n"
        "• Camera closer to the QR\n"
        "• At least 300×300 pixel resolution\n\n"
        "Or send a screenshot if this is a digital QR."
    )


def format_qr_blurry() -> str:
    return (
        "📷 Image received — attempting QR decode...\n\n"
        "❌ *Could not decode QR code.*\n\n"
        "💡 Try again with:\n"
        "• Better lighting\n"
        "• Steady hand (no motion blur)\n"
        "• Camera closer to the QR code"
    )


def format_qr_generated(url: str, b64: str = None) -> str:
    return (
        f"✅ *QR Code Generated & Safety-Verified*\n\n"
        f"🔗 Encoded: {url}\n"
        f"🛡️ Safety Verified: ✅ Safe\n"
        f"📐 Error Correction: Level H\n\n"
        f"Safe to share."
    )


def format_qr_generate_refused(url: str, score: float) -> str:
    return (
        f"🚫 *QR Generation Refused*\n\n"
        f"I cannot generate a QR code for this URL.\n"
        f"Reason: URL flagged as HIGH RISK (Score: {score:.0f})\n\n"
        f"Aegis will not encode malicious links. Please provide a safe URL."
    )


def format_qr_multi(results: list) -> str:
    lines = [f"📷 *{len(results)} QR Codes Detected* — scanning all...\n"]
    for i, r in enumerate(results, 1):
        payload = _truncate(str(r.get("decoded_payload", "")), 50)
        badge   = _risk_badge(r.get("overall_risk", "Safe"))
        score   = r.get("risk_score", 0)
        lines.append(f"━━━ QR #{i}: {badge}")
        if payload: lines.append(f"• Content: {payload}")
        lines.append(f"• Score: {score:.0f}/100")
        fl = r.get("all_flags", [])
        if fl: lines.append(f"• {fl[0]}")
        lines.append("")
    highest = max(results, key=lambda x: x.get("risk_score", 0))
    rl = highest.get("overall_risk", "").lower()
    if "high" in rl or "critical" in rl:
        idx = results.index(highest) + 1
        lines.append(f"⚠️ Multi-QR Alert: Mixing safe and malicious QRs is a social engineering tactic.")
        lines.append(f"🔴 *DO NOT scan QR #{idx}.*")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# CREDENTIAL ANALYZER — Unified format
# ═══════════════════════════════════════════════════════════════════════════════
# Credential Type Table (all handled):
# ┌──┬────────────────────────────────┬─────────────────────────────────┐
# │ #│ Type                           │ Key checks                      │
# ├──┼────────────────────────────────┼─────────────────────────────────┤
# │ 1│ Email address                  │ Breach (HIBP), disposable, MX   │
# │ 2│ Password                       │ Entropy, HIBP k-anon breach     │
# │ 3│ Username                       │ Entropy, impersonation, breach  │
# │ 4│ Credit/Debit card number       │ Luhn, brand, expiry, CVV        │
# │ 5│ IBAN                           │ MOD-97, country, SWIFT          │
# │ 6│ Bitcoin address (legacy/bech32)│ Base58Check, chain              │
# │ 7│ Ethereum address               │ EIP-55 checksum                 │
# │ 8│ Other crypto (LTC/XRP/etc)     │ Format validation               │
# │ 9│ Crypto private key             │ CRITICAL — immediate alert      │
# │10│ CNIC (Pakistan)                │ Province, check digit, NADRA    │
# │11│ SSN (USA)                      │ Structure, area number          │
# │12│ Aadhaar (India)                │ Verhoeff check digit            │
# │13│ Passport MRZ                   │ ICAO 9303 all 7 check digits    │
# │14│ Phone (Pakistani operators)    │ Jazz/Telenor/Zong/Ufone, VoIP   │
# │15│ AWS access key                 │ Prefix AKIA, entropy            │
# │16│ Stripe live/test key           │ sk_live / sk_test prefix        │
# │17│ GitHub PAT                     │ ghp_ / github_pat_ prefix        │
# │18│ JWT token                      │ Base64 decode, expiry           │
# │19│ Generic API key                │ Entropy, length, service detect │
# │20│ Smishing SMS text              │ OTP steal, financial fraud      │
# │21│ Email + Password pair          │ Both analysed concurrently      │
# │22│ Mixed/bulk credentials         │ Each type analysed separately   │
# └──┴────────────────────────────────┴─────────────────────────────────┘

def _cred_header(ctype: str, item: str, risk: str, score: int) -> str:
    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)
    return f"{badge} — {ctype}\n🔑 `{_truncate(item, 40)}`\n\n⚙️ *Details:*\n🛡️ Risk: {emoji} {risk.upper()} ({score}/100)"


def format_credential_email(email: str, result: dict, human_explanation: str = "") -> str:
    risk   = result.get("overall_risk_level", "Unknown")
    score  = result.get("overall_risk_score", 0)
    flags  = result.get("all_flags", [])
    badge  = _risk_badge(risk)
    emoji  = _risk_emoji(risk)

    lines = [f"{badge} — Email Analysis", f"📧 `{email}`", ""]
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")
    lines.append(f"⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")

    is_disposable = result.get("is_disposable", False)
    if is_disposable:
        # Disposable emails are ALWAYS HIGH RISK regardless of score
        badge = "🚨 HIGH RISK"
        emoji = "🔴"
        score = max(score, 80)
        lines[0] = "🚨 HIGH RISK — Email Analysis"
        lines.append("• 🗑️ Disposable/throwaway email provider — this address has no real identity behind it")
        lines.append("• ⚠️ Anyone can create and abandon this instantly — never trust it for identity")
    if result.get("breach_found"):
        lines.append(f"• 🔴 Found in breach databases")
    if result.get("domain_has_mx") is False:
        lines.append("• ⚠️ Domain has no mail server (MX records missing)")
    ipqs = result.get("ipqs_fraud_score")
    if ipqs:
        lines.append(f"• IPQS Fraud Score: {ipqs}/100")
    for f in flags[:4]:
        lines.append(f"• {f}")
    lines.append(f"\n{_PRIVACY_NOTE}")
    return "\n".join(lines)


def format_credential_password(result: dict, human_explanation: str = "") -> str:
    risk   = result.get("overall_risk_level", "Unknown")
    score  = result.get("overall_risk_score", 0)
    flags  = result.get("all_flags", [])
    badge  = _risk_badge(risk)
    emoji  = _risk_emoji(risk)
    breach = result.get("hibp_count", 0)
    s      = result.get("strength", {})
    entropy = result.get("entropy", {}).get("entropy_per_char", 0)

    lines = [f"{badge} — Password Analysis", "🔐 `[hidden for privacy]`", ""]

    if human_explanation:
        lines.append(human_explanation)
        lines.append("")

    lines.append(f"⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")

    # Single clear breach line — remove the duplicate
    if breach > 0:
        lines.append(f"• 🔴 Found in {breach:,} known breach records — change this password immediately")
    # (no breach — no extra line needed)


    length = s.get("length", 0)
    if length: lines.append(f"• 📏 Length: {length} characters")
    if entropy: lines.append(f"• 🎲 Entropy: {entropy:.1f} bits/char")

    # Show relevant flags only — skip any flag that mentions HIBP (already shown above)
    shown = 0
    for f in flags:
        if "hibp" in f.lower() or "breach check" in f.lower():
            continue
        lines.append(f"• {f}")
        shown += 1
        if shown >= 5:
            break

    lines.append(f"\n{_PRIVACY_NOTE}")
    lines.append("🔒 _Only 5-char SHA-1 prefix sent to HIBP — full password never transmitted._")
    return "\n".join(lines)


def format_credential_card(result: dict, human_explanation: str = "") -> str:
    risk  = result.get("overall_risk_level", "Unknown")
    score = result.get("overall_risk_score", 0)
    flags = result.get("all_flags", [])
    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)
    card  = result.get("card", {})
    brand = card.get("brand", "Unknown")
    last4 = card.get("last4", "****")
    luhn  = card.get("luhn_valid", False)

    lines = [f"{badge} — Payment Card Analysis", f"💳 `****{last4}` ({brand})", ""]
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")
    lines.append(f"⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    lines.append(f"• Card Brand: {brand if brand != 'Unknown' else 'Not detected — check card brand manually'}")
    if luhn:
        lines.append("• ✅ Luhn Checksum: Valid — card number structure is correct")
    else:
        lines.append("• ❌ Luhn Checksum: Invalid — this card number has an error or is not real")
    for f in [f for f in flags if "luhn" not in f.lower()][:4]:
        lines.append(f"• {f}")
    lines.append(f"\n{_PRIVACY_NOTE}")
    return "\n".join(lines)


def format_credential_iban(iban: str, result: dict, human_explanation: str = "") -> str:
    risk  = result.get("overall_risk_level", "Unknown")
    score = result.get("overall_risk_score", 0)
    flags = result.get("all_flags", [])
    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)

    lines = [f"{badge} — IBAN Analysis", f"🏦 `{iban}`", ""]
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")
    lines.append(f"⚙️ *Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    if not flags:
        lines.append("• MOD-97 Checksum: ✅ Valid")
        lines.append("• BBAN structure: ✅ Correct for country")
    for f in flags[:4]:
        lines.append(f"• {f}")
    return "\n".join(lines)


def format_credential_crypto(address: str, result: dict, human_explanation: str = "") -> str:
    risk   = result.get("overall_risk_level", "Unknown")
    score  = result.get("overall_risk_score", 0)
    flags  = result.get("all_flags", [])
    badge  = _risk_badge(risk)
    emoji  = _risk_emoji(risk)
    crypto = result.get("crypto", {})
    chain  = crypto.get("chain", "Unknown")
    is_pk  = crypto.get("is_private_key", False)

    if is_pk:
        return (
            "🚨 CRITICAL — Private Key Detected!\n\n"
            "⛔ You appear to have shared a *cryptocurrency private key*.\n\n"
            "🚨 *Immediate actions required:*\n"
            "• Transfer ALL funds to a new wallet immediately\n"
            "• Never share private keys with anyone\n"
            "• Anyone with this key has full access to your funds\n\n"
            f"{_PRIVACY_NOTE}"
        )

    lines = [f"{badge} — Crypto Address Analysis", f"₿ `{_truncate(address, 30)}...`", ""]
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")
    lines.append(f"⚙️ *Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    lines.append(f"• Chain: {chain}")
    for f in flags[:4]:
        lines.append(f"• {f}")
    return "\n".join(lines)


def format_credential_national_id(value: str, result: dict, human_explanation: str = "") -> str:
    risk  = result.get("overall_risk_level", "Unknown")
    score = result.get("overall_risk_score", 0)
    flags = result.get("all_flags", [])
    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)
    nid   = result.get("national_id", {})
    id_type = nid.get("id_type", "National ID").upper()

    lines = [f"{badge} — {id_type} Analysis", f"🪪 `{value}`", ""]
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")
    lines.append(f"⚙️ *Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    prov = nid.get("province", "")
    if prov: lines.append(f"• Province Code: {prov}")
    if not flags:
        lines.append("• Structure: ✅ Valid format")
    for f in flags[:5]:
        lines.append(f"• {f}")
    if any("tampered" in f.lower() or "forged" in f.lower() or "check digit" in f.lower() or "invalid" in f.lower() for f in flags):
        lines.append("\n⚠️ *Document data may have been altered. Verify through official channels.*")
    lines.append(f"\n{_PRIVACY_NOTE}")
    return "\n".join(lines)


def format_credential_passport(result: dict, human_explanation: str = "") -> str:
    risk  = result.get("overall_risk_level", "Unknown")
    score = result.get("overall_risk_score", 0)
    flags = result.get("all_flags", [])
    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)

    lines = [f"{badge} — Passport MRZ Analysis", "🛂 `[MRZ Data]`", ""]
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")
    lines.append(f"⚙️ *Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    if not flags:
        lines.append("• All 7 MRZ check digits: ✅ Valid")
        lines.append("• ICAO 9303 compliance: ✅ Passed")
    for f in flags[:5]:
        lines.append(f"• {f}")
    if any("check digit" in f.lower() or "forged" in f.lower() for f in flags):
        lines.append("\n⚠️ *Check digit failure — document data may have been altered.*")
    lines.append(f"\n{_PRIVACY_NOTE}")
    return "\n".join(lines)


def format_credential_phone(phone: str, result: dict, human_explanation: str = "") -> str:
    risk  = result.get("overall_risk_level", "Unknown")
    score = result.get("overall_risk_score", 0)
    flags = result.get("all_flags", [])
    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)
    ph    = result.get("phone", {})
    adv   = result.get("advanced_phone", {})
    otp   = adv.get("otp_bypass_risk", {})
    sim   = adv.get("sim_swap", {})

    # Determine Pakistani operator
    operator = ""
    num = phone.replace("+92", "0").replace(" ", "")
    if re.match(r"0(300|301|302|303|304|305|306|307)", num): operator = "Jazz/Warid"
    elif re.match(r"0(340|341|342|343|344|345)", num): operator = "Telenor"
    elif re.match(r"0(310|311|312|313|314|315|316|317|318|319)", num): operator = "Zong"
    elif re.match(r"0(333|334|335|336|337)", num): operator = "Ufone"
    elif re.match(r"0(320|321|322|323|324|325|326|327|328|329)", num): operator = "Zong"
    elif re.match(r"0(342|343|344|345)", num): operator = "Telenor"
    elif ph.get("carrier"): operator = ph["carrier"]

    lines = [f"{badge} — Phone Analysis", f"📱 `{phone}`", ""]
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")
    lines.append(f"⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    if operator:       lines.append(f"• Operator: {operator}")
    if ph.get("country"): lines.append(f"• Country: {ph.get('country','')}")
    if ph.get("line_type"): lines.append(f"• Line Type: {ph['line_type']}")
    voip = ph.get("is_voip") or (ph.get("line_type","").lower() == "voip")
    if voip:           lines.append("• ⚠️ VoIP number — commonly used in fraud")
    otp_risk = otp.get("otp_bypass_risk", 0)
    if otp_risk and otp_risk > 30:
        lines.append(f"• OTP Bypass Risk: {otp_risk}/100")
    sim_risk = sim.get("sim_swap_risk", 0)
    if sim_risk and sim_risk > 30:
        lines.append(f"• SIM Swap Risk: {sim_risk}/100")
    for f in flags[:4]:
        lines.append(f"• {f}")
    if not flags and not operator:
        lines.append("• Format valid, no risk indicators found")
    return "\n".join(lines)


def format_credential_api_key(result: dict, human_explanation: str = "") -> str:
    risk    = result.get("overall_risk_level", "Unknown")
    score   = result.get("overall_risk_score", 0)
    flags   = result.get("all_flags", [])
    badge   = _risk_badge(risk)
    emoji   = _risk_emoji(risk)
    svc_det = result.get("service_detection", {})
    service = svc_det.get("primary_service", "Unknown Service")
    is_test = svc_det.get("is_test_key", False)

    lines = [f"{badge} — API Key Analysis", ""]
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")
    lines.append(f"⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    lines.append(f"• Service: *{service}*" + (" _(test key)_" if is_test else ""))
    for f in flags[:5]:
        lines.append(f"• {f}")

    rl = risk.lower()
    if "critical" in rl or "high" in rl:
        lines += [
            "",
            "⚠️ *This appears to be a LIVE production key.*",
            "• Rotate immediately in your service dashboard",
            "• Check access logs for unauthorized usage",
            "• Never commit API keys to public repositories",
        ]
    lines.append(f"\n{_PRIVACY_NOTE}")
    return "\n".join(lines)


def format_credential_smishing(text: str, result: dict, ollama_analysis: dict = None) -> str:
    adv      = result.get("advanced_phone", {})
    smish    = adv.get("smishing", {})
    api_score = smish.get("smishing_score", 0)
    api_is_s  = smish.get("is_likely_smishing", False)
    patterns  = smish.get("patterns_matched", [])

    # Ollama is the primary smishing engine when API score is 0
    ol_is_s   = False
    ol_reason = ""
    ol_cat    = ""
    if ollama_analysis:
        ol_is_s   = ollama_analysis.get("is_smishing", False)
        ol_reason = ollama_analysis.get("reason", "")
        ol_cat    = ollama_analysis.get("category", "")
        ol_conf   = ollama_analysis.get("confidence", 0)

    # Ollama is the PRIMARY smishing engine — API score is unreliable (often returns 0)
    # Trust Ollama at confidence >= 30 (it's specifically prompted for Pakistani scams)
    ol_confidence = (ollama_analysis or {}).get("confidence", 0)
    is_smishing = api_is_s or (ol_is_s and ol_confidence >= 30)
    final_score = max(api_score, (ollama_analysis or {}).get("confidence", 0) if ol_is_s else 0)

    if is_smishing:
        risk_badge = "🚨 HIGH RISK" if final_score >= 70 else "⚠️ MEDIUM RISK"
        lines = [
            f"{risk_badge} — Smishing Detected",
            "📩 SMS / Text Message Analysis",
            "",
        ]
        if ol_reason:
            lines.append(ol_reason)
            lines.append("")
        lines += [
            f"⚙️ *Technical Details:*",
            f"🛡️ Smishing Score: {final_score:.0f}/100",
        ]
        if ol_cat and ol_cat != "legitimate":
            lines.append(f"• Category: {ol_cat.replace('_',' ').title()}")
        for p in patterns[:5]:
            lines.append(f"• {p}")
        lines += [
            "",
            "🚫 *Do NOT click any links or reply with OTPs/PINs.*",
            "📋 Report to FIA Cyber Crime: nia.gov.pk / 0800-55555",
        ]
    else:
        # Even "safe" SMS - show Ollama's reasoning
        lines = [
            "✅ SAFE — SMS Analysis",
            "📩 No strong smishing patterns detected.",
            "",
        ]
        if ol_reason:
            lines += [ol_reason, ""]
        lines.append(f"⚙️ Smishing Score: {final_score:.0f}/100")
        if final_score > 10:
            lines.append("⚠️ Stay alert — never share OTPs or personal details via SMS.")
    return "\n".join(lines)


def format_credential_scan(result: dict) -> str:
    findings = result.get("findings", [])
    total    = result.get("total_findings", 0)
    critical = result.get("critical", 0)
    risk_lvl = result.get("risk_level", "Safe")

    if total == 0:
        return "🔍 *Secret Scanner*\n\n✅ No secrets or credentials found in the provided text."

    badge = _risk_badge(risk_lvl)
    lines = [f"{badge} — Secret Scanner", f"🔍 {total} finding(s) detected", ""]
    for f in findings[:10]:
        sev    = f.get("severity", "")
        ftype  = f.get("type", "Unknown")
        masked = f.get("masked_value", "")
        line_n = f.get("line_number", "")
        em = "🔴" if sev == "critical" else "🟠" if sev == "high" else "🟡"
        lines.append(f"{em} Line {line_n}: *{ftype}* — `{masked}`")
    if critical > 0:
        lines.append("\n⚠️ *Rotate all detected secrets immediately.*")
    return "\n".join(lines)


def format_credential_bulk(results: list) -> str:
    lines = [f"🔍 *Bulk Credential Check — {len(results)} items*\n"]
    for r in results:
        t     = r.get("credential_type", "")
        risk  = r.get("overall_risk_level", "Safe")
        score = r.get("overall_risk_score", 0)
        em = _risk_emoji(risk)
        lines.append(f"{em} *{t.upper()}* — {risk} ({score}/100)")
    crit = sum(1 for r in results if "critical" in r.get("overall_risk_level","").lower())
    high = sum(1 for r in results if "high"     in r.get("overall_risk_level","").lower())
    lines.append(f"\n📊 {len(results)} checked — {crit} Critical, {high} High Risk")
    return "\n".join(lines)


def format_credential_detect(result: dict) -> str:
    primary     = result.get("primary_suggestion", "Unknown")
    suggestions = result.get("suggestions", [])
    lines = [
        f"🔍 *Auto-Detection Result*",
        f"Most likely type: *{primary.replace('_',' ').title()}*",
        "",
    ]
    if suggestions:
        lines.append("*All possibilities:*")
        for s in suggestions[:4]:
            conf = s.get("confidence", "")
            typ  = s.get("type", "").replace("_"," ").title()
            lines.append(f"• {typ} ({conf} confidence)")
    lines.append("\nSend /check to analyse this credential in detail.")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# PROFILE ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

def format_profile_result(username: str, result: dict, human_explanation: str = "") -> str:
    verdict   = result.get("verdict", {})
    risk      = verdict.get("risk_level", "Unknown")
    score     = verdict.get("final_score", 0)
    fraud_typ = verdict.get("fraud_type", "")
    summary   = verdict.get("summary", "")
    top_flags = verdict.get("top_flags", [])
    recommend = verdict.get("recommendation", "")
    b1 = verdict.get("block1_score", 0)
    b2 = verdict.get("block2_score", 0)
    b3 = verdict.get("block3_score", 0)
    b4 = verdict.get("block4_score", 0)

    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)

    lines = [f"{badge} — Profile Analysis", f"👤 @{username}", ""]

    if human_explanation:
        lines.append(human_explanation)
        lines.append("")

    lines.append("⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    # Only show fraud type for medium+ risk
    if fraud_typ and fraud_typ.lower() not in ("unknown", "") and "low" not in risk.lower():
        lines.append(f"🎭 Detected Pattern: *{fraud_typ.replace('_',' ').title()}*")

    lines.append(f"\n📊 *Block Scores:*")
    lines.append(f"• Identity & Metadata: {b1}")
    lines.append(f"• Content & Language: {b2}")
    lines.append(f"• Network & Engagement: {b3}")
    lines.append(f"• AI/ML Analysis: {b4}")

    if top_flags:
        lines.append("\n⚠️ *Signals:*")
        for f in top_flags[:5]:
            lines.append(f"• {str(f).replace('_',' ').title()}")

    # Only show summary for medium+ risk (not for low)
    if summary and "low" not in risk.lower():
        lines.append(f"\n📋 {summary}")
    if recommend and "log and watch" not in recommend.lower():
        lines.append(f"💡 {recommend}")

    return "\n".join(lines)


def format_profile_collect_prompt(fields_needed: list = None) -> str:
    return (
        "👤 *Profile Analysis — Data Collection*\n\n"
        "To run a thorough analysis, please provide some details.\n"
        "_All fields are optional — provide what you have._\n\n"
        "Please send any of these:\n"
        "• Bio / description\n"
        "• Follower count\n"
        "• Following count\n"
        "• Account age (days or date)\n"
        "• Platform (Instagram, Twitter, etc.)\n"
        "• Recent posts (paste text)\n\n"
        "Or send `/cancel` to stop."
    )


def format_profile_minimal(username: str) -> str:
    return (
        f"👤 *Profile: @{username}*\n\n"
        f"1️⃣ Run quick username scan now\n"
        f"2️⃣ Provide more data for deeper analysis\n\n"
        f"Reply *1* or *2*."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-MODULE / CLASH
# ═══════════════════════════════════════════════════════════════════════════════

def format_consolidated_report(results: dict) -> str:
    lines = ["🛡️ *Aegis AI — Consolidated Report*\n"]
    for module, result in results.items():
        risk  = (result.get("risk_level") or result.get("overall_risk_level")
                 or result.get("verdict", {}).get("risk_level", "Unknown"))
        score = (result.get("confidence_score") or result.get("overall_risk_score")
                 or result.get("verdict", {}).get("final_score", 0))
        badge = _risk_badge(risk)
        em    = {"link": "🔗", "credential": "🔑", "profile": "👤", "qr": "📷"}.get(module, "🛡️")
        lines.append(f"━━━ {em} *{module.title()} Analysis*")
        lines.append(f"{badge} — Score: {score:.1f}")
        flags = (result.get("all_flags") or result.get("verdict", {}).get("top_flags", []))
        if flags: lines.append(f"• {flags[0]}")
        lines.append("")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SPECIAL / SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════
GENERAL_CAPABILITY_MENU = """🛡️ *Aegis AI — What I Can Check*

Here's everything I can analyse for you:

🔗 *Links & Websites*
  Send any URL → Safety check, malware, phishing detection
  Send a bare domain (e.g. `paypal.com`) → 3 options shown

📷 *QR Codes*
  Send a QR code image → Decode + safety check
  `/generate <url>` → Create a safe QR code

🎭 *Deepfake Detection*
  Send an image or video → Detect AI manipulation

📧 *Email Addresses*
  Send email → Choose: 🔑 Breach check  OR  👤 Fraud/scam analysis
  e.g. `user@example.com`

📱 *Phone Numbers*
  Send phone → Choose: 🔑 Breach check  OR  👤 Fraud/scam analysis
  e.g. `+923001234567` or `03001234567`

🔐 *Credentials* (via `/check` or just send directly)
  1️⃣ Email → breach check     2️⃣ Password → strength + breaches
  3️⃣ Username → breach check  4️⃣ Payment card → fraud check
  5️⃣ IBAN → validation        6️⃣ Crypto wallet → risk check
  7️⃣ CNIC / ID → validation   8️⃣ Passport MRZ → check
  9️⃣ Phone → breach check     🔟 API key / token → exposure check

👤 *Social Media Profiles*
  Send `@username` → Full profile intelligence (fake/scammer/breached)
  Send `cryptoking99` → 4 options: Profile / Credential / Both / Password

📩 *SMS / Smishing*
  Paste any suspicious SMS → AI-powered scam detection

🎓 *Cybersecurity Q&A*
  Ask anything: `what is phishing?`, `how do I use 2FA?`, etc.

⚙️ *Commands*
  `/check` — Credential analysis menu
  `/history` — Your scan history
  `/clear` — Delete session data (GDPR)
  `/language urdu` — Switch to Urdu
  `/help` — Show this menu

_Just send me anything suspicious and I'll analyse it!_ 🔍"""

HELP_MENU = """🛡️ *Welcome to Aegis AI — Cybersecurity on WhatsApp*

I can analyse:
🔗 *Links* — Send any URL to check for phishing/malware
📷 *QR Codes* — Send a QR code image to scan it
🎭 *Deepfake Detection* — Send an image or video to check for AI manipulation
🔑 *Credentials* — Passwords, emails, cards, CNICs, API keys, crypto
👤 *Social Profiles* — Send @handle or use /profile

    📌 *Tip:* For best quality, send the image as a *Document* (not as a photo) to avoid compression.

*Quick Commands:*
• `/scan <url>` — Scan a link
• `/qr` — Scan a QR code (send image)
• `/deepfake` — Check an image/video for AI fakery
• `/profile <username>` — Analyse a social profile
• `/check` — Guided credential check menu
• `/generate <url>` — Create a safety-verified QR
• `/history` — View your session history
• `/clear` — Delete your session data
• `/help` — Show this menu

_All data auto-deleted after 30 minutes of inactivity._"""

CREDENTIAL_MENU = """🔑 *Credential Check — What would you like to check?*

1️⃣ Email address
2️⃣ Password strength & breach check
3️⃣ Username
4️⃣ Payment card
5️⃣ IBAN (bank account)
6️⃣ Crypto wallet address
7️⃣ National ID (CNIC / SSN / Aadhaar)
8️⃣ Passport (MRZ)
9️⃣ Phone number
🔟 API key / token

Reply with a number, or just send the credential directly."""

SESSION_TIMEOUT_MSG = "⏰ *Session expired.* Starting fresh — send /help to see all options."
RATE_LIMIT_MSG      = "⏱️ *Rate limit reached.* Please wait 60 seconds before sending another request."


def format_disambiguation_prompt(opts: dict, entity: str) -> str:
    emojis = ["1️⃣", "2️⃣", "3️⃣"]
    lines = [f"🔍 `{entity}` — what would you like to do?\n"]
    for i, (key, (module, val, desc)) in enumerate(opts.items()):
        em = emojis[i] if i < len(emojis) else "•"
        lines.append(f"{em} {desc}")
    lines.append("\nReply with a number.")
    return "\n".join(lines)


def format_session_cleared() -> str:
    return "🗑️ *Session cleared.*\n\nAll data deleted. GDPR request fulfilled. ✅"


def format_cancel() -> str:
    return "❌ *Cancelled.* Send anything to start a new analysis."


def format_history(history: list) -> str:
    if not history:
        return "📋 *Session History*\n\nNo scans in this session yet."
    lines = ["📋 *Session History*\n"]
    for i, h in enumerate(history[-20:], 1):
        role = h.get("role", "")
        cnt  = h.get("content", "").strip()
        mod  = h.get("module", "")
        ts   = _format_ts(h.get("timestamp", 0))
        if role == "user":
            lines.append(f"{i}. 👤 `{_truncate(cnt, 50)}` _{ts}_")
        # Skip bot replies in history — show user inputs only for cleanliness
    return "\n".join(lines)


def format_scan_log(scan_log: list, filter_module: str = "") -> str:
    """Enhanced scan history: two categories (Safe/Risky), grouped by type."""
    if not scan_log:
        return "📋 *Scan History*\n\nNo scans yet in this session. Send a link, QR, credential, or image to get started!"

    filtered = [s for s in scan_log if not filter_module or s.get("module","") == filter_module]
    if not filtered:
        _names = {"link":"links","qr":"QR codes","credential":"credentials",
                  "profile":"profiles","deepfake":"deepfake scans","smishing":"smishing messages"}
        return f"📋 No {_names.get(filter_module, filter_module)} scans recorded yet."

    # Module display config
    _MOD_ICON = {
        "link":       "🔗",
        "qr":         "📷",
        "credential": "🔑",
        "profile":    "👤",
        "deepfake":   "🎭",
        "smishing":   "🚨",
    }
    _MOD_LABEL = {
        "link":       "Link",
        "qr":         "QR Code",
        "credential": "Credential",
        "profile":    "Profile",
        "deepfake":   "Deepfake",
        "smishing":   "SMS/Smishing",
    }

    def _is_risky(risk: str) -> bool:
        r = (risk or "").lower()
        return any(w in r for w in ("high","critical","medium","suspicious","scam","danger","risky","breached","fraud","compromised","leaked"))

    def _is_safe(risk: str) -> bool:
        r = (risk or "").lower()
        return any(w in r for w in ("safe","clean","low","valid","legitimate","not found","no breach"))

    risky_items = [s for s in filtered if _is_risky(s.get("risk",""))]
    safe_items  = [s for s in filtered if _is_safe(s.get("risk",""))  and not _is_risky(s.get("risk",""))]
    other_items = [s for s in filtered if s not in risky_items and s not in safe_items]

    title = "📋 *Scan History*" + (f" — {_MOD_LABEL.get(filter_module, filter_module.title())}" if filter_module else "")
    lines = [title, ""]

    # ── Risky section ──────────────────────────────────────────────────────
    if risky_items:
        lines.append("🔴 *Threats Detected*")
        # Group by module
        by_mod: dict = {}
        for s in risky_items:
            m = s.get("module","other")
            by_mod.setdefault(m, []).append(s)
        for mod, items in by_mod.items():
            icon  = _MOD_ICON.get(mod, "🔍")
            label = _MOD_LABEL.get(mod, mod.title())
            lines.append(f"  {icon} *{label}s ({len(items)}):*")
            for s in items[-5:]:   # show last 5 per type
                itm = _truncate(s.get("item",""), 35)
                risk = s.get("risk","")
                ts   = _format_ts(s.get("timestamp", 0))
                risk_short = risk.split()[0].title() if risk else "?"
                lines.append(f"    🚨 `{itm}` — {risk_short} _{ts}_")
        lines.append("")

    # ── Safe section ───────────────────────────────────────────────────────
    if safe_items:
        lines.append("🟢 *Clean / Safe*")
        by_mod2: dict = {}
        for s in safe_items:
            m = s.get("module","other")
            by_mod2.setdefault(m, []).append(s)
        for mod, items in by_mod2.items():
            icon  = _MOD_ICON.get(mod, "🔍")
            label = _MOD_LABEL.get(mod, mod.title())
            lines.append(f"  {icon} *{label}s ({len(items)}):*")
            for s in items[-5:]:
                itm = _truncate(s.get("item",""), 35)
                ts   = _format_ts(s.get("timestamp", 0))
                lines.append(f"    ✅ `{itm}` _{ts}_")
        lines.append("")

    # ── Other (pending/unknown) ────────────────────────────────────────────
    if other_items:
        lines.append("🔵 *Other Scans*")
        for s in other_items[-5:]:
            icon = _MOD_ICON.get(s.get("module",""), "🔍")
            itm  = _truncate(s.get("item",""), 35)
            risk = s.get("risk","")
            ts   = _format_ts(s.get("timestamp", 0))
            lines.append(f"  {icon} `{itm}` — {risk} _{ts}_")
        lines.append("")

    # ── Summary ────────────────────────────────────────────────────────────
    total  = len(filtered)
    n_risky = len(risky_items)
    n_safe  = len(safe_items)
    n_other = len(other_items)
    lines.append(f"📊 *Summary:* {total} scans — 🔴 {n_risky} Risky · 🟢 {n_safe} Safe · 🔵 {n_other} Other")

    # Type breakdown
    mod_counts: dict = {}
    for s in filtered:
        m = s.get("module","other")
        mod_counts[m] = mod_counts.get(m, 0) + 1
    if len(mod_counts) > 1:
        parts = [f"{_MOD_ICON.get(m,'🔍')} {_MOD_LABEL.get(m,m.title())}: {c}" for m,c in sorted(mod_counts.items())]
        lines.append("   " + " · ".join(parts))

    return "\n".join(lines)


def format_privacy_reminder(credential_type: str) -> str:
    return (
        f"🔒 *Privacy Notice — {credential_type}*\n\n"
        f"• Your raw value is *never* stored\n"
        f"• Only SHA-256 hash kept (for caching)\n"
        f"• Passwords: only 5-char SHA-1 prefix sent to HIBP\n"
        f"• Session auto-deletes after 30 min\n"
        f"• Send /clear at any time to delete all your data"
    )


def format_irrelevant(action: str) -> str:
    msgs = {
        "bot_who": (
            "I'm *Aegis AI* — a cybersecurity assistant built at Lahore Garrison University "
            "as a Final Year Project.\n\n"
            "My mission is simple: protect you from online threats.\n\n"
            "🔗 *Link Analysis* — I check URLs for phishing, malware and scams\n"
            "📷 *QR Scanning* — I decode and analyse QR codes for hidden threats\n"
            "🔑 *Credential Monitoring* — I check if your email, password, phone, CNIC "
            "or API keys have been leaked in data breaches\n"
            "👤 *Profile Intelligence* — I detect fake, bot and scammer social accounts\n\n"
            "Send me anything suspicious and I'll tell you what it is!"
        ),
        "off_topic": (
            "That's outside my area of expertise — I'm a cybersecurity specialist. 🛡️\n\n"
            "Here's what I *can* help you with:\n"
            "• 🔗 *Links* — Is this URL safe to click? Paste it and I'll check\n"
            "• 📷 *QR Codes* — Send a QR image and I'll decode + analyse it\n"
            "• 🔑 *Credentials* — Email, password, CNIC, card — check for breaches\n"
            "• 👤 *Profiles* — Is this Instagram/Twitter account fake or a scammer?\n"
            "• 🎭 *Deepfakes* — Is this photo or video AI-generated?\n\n"
            "Just send me something suspicious and I'll take a look!"
        ),
        "no_voice": (
            "🎙️ *Voice messages are not supported.*\n\n"
            "Please type your message or send:\n"
            "• A URL to scan\n"
            "• A QR code image\n"
            "• A credential to check\n\n"
            "Type /help for all options."
        ),
        "urdu_message": (
            "🛡️ *Aegis AI yahan hai!*\n\n"
            "Aap mujhe bhej sakte hain:\n"
            "• 🔗 Koi bhi suspicious *link* — main check karoonga safe hai ya nahi\n"
            "• 📷 *QR code* image — main decode aur analyse karoonga\n"
            "• 🔑 *Password, email, ya CNIC* — data breach check ke liye\n"
            "• 👤 *@username* — fake profile detect karne ke liye\n\n"
            "Ya /help bhejain complete menu ke liye."
        ),
        "emoji_only": (
            "🛡️ Hi there! I'm Aegis — your cybersecurity assistant.\n\n"
            "Send me a link, QR code image, credential, or social handle to analyse.\n"
            "Type /help to see everything I can do!"
        ),
        "gibberish": (
            "🤔 I couldn't quite understand that message.\n\n"
            "I work best with specific things to check:\n"
            "• URLs (https://...)\n"
            "• QR code images\n"
            "• Passwords, emails, CNICs, card numbers\n"
            "• @social handles or profile URLs\n\n"
            "Send /help for the full list of what I can do."
        ),
        "angry_user": (
            "I'm sorry to hear that. 😔\n\n"
            "I understand it can be frustrating when things don't work as expected. "
            "I'm still learning and improving.\n\n"
            "If something specific went wrong, please describe it and I'll do my best to help. "
            "Your feedback helps make me better!"
        ),
        "jailbreak_block": (
            "🛡️ I'm Aegis AI — a cybersecurity assistant with a clear purpose.\n\n"
            "I can't change my role or ignore my guidelines."
        ),
        "deepfake_phase2": (
            "🎬 *Video / Deepfake Analysis*\n\n"
            "Deepfake detection is coming in Phase 2. 🔜\n\n"
            "I can help with links, QR codes, credentials, and social profiles right now."
        ),
    }
    return msgs.get(action, msgs["off_topic"])


def format_error(message: str = "An error occurred.") -> str:
    return f"❌ *Something went wrong.*\n\n{message}\n\nPlease try again. Send /help for options."


def format_module_unavailable(module: str) -> str:
    return f"⚠️ *{module.title()} service is temporarily unavailable.*\n\nPlease try again in a few moments."


# ═══════════════════════════════════════════════════════════════════════════════
# QR — UPDATED TYPE-SPECIFIC FORMATS (Issues 5,6,7)
# ═══════════════════════════════════════════════════════════════════════════════

def format_qr_full(result: dict, human_explanation: str = "") -> str:
    """
    Master QR formatter. Routes to type-specific sub-formatter.
    result: full API response from QR scanner
    FIX-4d: decoded payload shown prominently at top so user immediately
            knows what was inside the QR before seeing the risk analysis.
    """
    qr_type   = (result.get("qr_type") or "unknown").lower()
    risk      = result.get("overall_risk", result.get("risk_level", "Safe"))
    score     = result.get("risk_score", result.get("confidence_score", 0))
    all_flags = result.get("all_flags", [])
    payload   = result.get("decoded_payload", result.get("payload", ""))
    stego     = result.get("steganography_detected", False)

    badge = _risk_badge(risk)
    emoji = _risk_emoji(risk)

    type_labels = {
        "url":    "URL / Link",
        "wifi":   "WiFi Network",
        "vcard":  "Contact Card (vCard)",
        "email":  "Email Message",
        "sms":    "SMS / Text Message",
        "crypto": "Cryptocurrency Address",
        "geo":    "Geographic Location",
        "text":   "Plain Text",
        "phone":  "Phone Number",
        "event":  "Calendar Event",
    }
    type_label = type_labels.get(qr_type, qr_type.title() if qr_type != "unknown" else "Unknown")

    threat_banner = ""
    gsb_hit = any("safe browsing" in f.lower() or "gsb" in f.lower() for f in all_flags)
    if gsb_hit:
        threat_banner = "☣️ Google SafeBrowse Hit"

    lines = [f"{badge} — QR Code Analysis"]
    if qr_type and qr_type not in ("unknown", ""):
        lines.append(f"🌐 Type: {type_label}" + (f"  |  {threat_banner}" if threat_banner else ""))
    else:
        lines.append(f"🌐 Type: Scanning..." + (f"  |  {threat_banner}" if threat_banner else ""))
    lines.append("")

    # ── FIX-4d: Decoded content FIRST — user needs to know what's inside ──────
    _payload_str = str(payload).strip() if payload else ""
    if _payload_str:
        if qr_type == "url" or _payload_str.startswith(("http://","https://","www.")):
            lines.append(f"📦 *Decoded Content (URL):*")
            lines.append(f"`{_payload_str}`")
        elif qr_type == "wifi":
            wifi = result.get("wifi", {})
            ssid = wifi.get("ssid", _payload_str[:60])
            sec  = wifi.get("security", "")
            lines.append(f"📦 *Decoded Content (WiFi):*")
            lines.append(f"  Network: `{ssid}`")
            if sec: lines.append(f"  Security: {sec}")
        elif qr_type == "vcard":
            vcard = result.get("vcard", {})
            name  = vcard.get("name", "")
            phone_v = vcard.get("phone","")
            email_v = vcard.get("email","")
            lines.append(f"📦 *Decoded Content (Contact):*")
            if name:    lines.append(f"  👤 Name: {name}")
            if phone_v: lines.append(f"  📱 Phone: {phone_v}")
            if email_v: lines.append(f"  📧 Email: {email_v}")
        elif qr_type == "crypto":
            lines.append(f"📦 *Decoded Content (Crypto Address):*")
            lines.append(f"`{_payload_str[:80]}`")
        elif qr_type == "phone":
            lines.append(f"📦 *Decoded Content (Phone Number):*")
            lines.append(f"`{_payload_str}`")
        elif qr_type == "sms":
            sms_data = result.get("sms_payload", {})
            # Parse SMSTO:number:body format if sms_payload dict is empty
            if not sms_data and _payload_str.upper().startswith("SMSTO:"):
                parts = _payload_str[6:].split(":", 1)
                sms_data = {"number": parts[0], "body": parts[1] if len(parts) > 1 else ""}
            elif not sms_data and ":" in _payload_str:
                # Try generic number:body split
                parts = _payload_str.split(":", 1)
                if parts[0].replace("+","").replace(" ","").isdigit():
                    sms_data = {"number": parts[0], "body": parts[1] if len(parts) > 1 else ""}
            to_num   = sms_data.get("number", _payload_str[:60])
            body     = sms_data.get("body", "")
            lines.append(f"📦 *Decoded Content (SMS):*")
            lines.append(f"  📱 To: {to_num}")
            if body: lines.append(f"  💬 Message: _{body[:120]}_")
        elif qr_type == "email":
            email_data = result.get("email_payload", {})
            to_addr    = email_data.get("to", _payload_str[:60])
            subj       = email_data.get("subject","")
            lines.append(f"📦 *Decoded Content (Email):*")
            lines.append(f"  📧 To: {to_addr}")
            if subj: lines.append(f"  📌 Subject: {subj[:80]}")
        elif qr_type == "geo":
            lines.append(f"📦 *Decoded Content (Location):*")
            lines.append(f"  📍 Coordinates: `{_payload_str[:60]}`")
        else:
            # Generic text / unknown type
            # Truncate long payloads but show at least 120 chars
            display = _payload_str[:200] + ("..." if len(_payload_str) > 200 else "")
            lines.append(f"📦 *Decoded Content:*")
            lines.append(f"`{display}`")
        lines.append("")
    else:
        lines.append("📦 *Decoded Content:* Could not decode payload")
        lines.append("")

    # ── Human explanation ──────────────────────────────────────────────────────
    if human_explanation:
        lines.append(human_explanation)
        lines.append("")

    lines.append(f"{emoji} {risk.upper()}")
    lines.append(f"📊 Score: {score:.0f}/100")
    lines.append("")

    # ── Type-specific link scan details (URL type only) ───────────────────────
    if qr_type == "url" and _payload_str:
        ls = result.get("link_scan", {})
        if ls:
            ls_risk  = ls.get("risk_level", "")
            ls_score = ls.get("confidence_score", 0)
            vt_det   = ls.get("detection_counts", {})
            vt_mal   = vt_det.get("malicious", 0)
            vt_total = ls.get("scanners_count", 95)
            vt_rep   = ls.get("virustotal_report", "")
            lines.append(f"  Link Risk: {_risk_emoji(ls_risk)} {ls_risk} (score: {ls_score:.0f}/100)")
            if vt_mal > 0:
                lines.append(f"  🦠 Antivirus: 🔴 {vt_mal} flagged / {vt_total} engines")
            else:
                lines.append(f"  🦠 Antivirus: ✅ 0 flagged / {vt_total} engines")
            if vt_rep:
                lines.append(f"  📋 VT Report: {vt_rep}")

    # ── Obfuscation info ────────────────────────────────────────────────────────
    enc_layers = result.get("encoding_layers", 0)
    if enc_layers:
        lines.append(f"🔍 Obfuscation: {enc_layers} encoding layer(s) detected")

    # ── Stego ──────────────────────────────────────────────────────────────────
    if stego:
        hidden = result.get("steganography", {}).get("hidden_bytes", 0)
        lines.append(f"🕵️ Steganography: ~{hidden}KB hidden payload in image pixels")

    # ── Flags ──────────────────────────────────────────────────────────────────
    if all_flags:
        lines.append("")
        for f in all_flags[:4]:
            lines.append(f"• {f}")

    lines.append(f"\n{'━'*32}")

    # ── Final verdict ──────────────────────────────────────────────────────────
    rl = risk.lower()
    if "high" in rl or "critical" in rl:
        lines.append(f"🆘 {risk.upper()} — DO NOT interact with this QR code.")
        if qr_type in ("url", "email", "sms"):
            lines.append("⚠️ QRLjacking Risk: Check physical terminal for stickers placed over legitimate QR.")
    elif "medium" in rl:
        lines.append(f"⚠️ Treat with caution before interacting.")
    else:
        lines.append(f"✅ This QR code appears safe. No significant threat indicators detected.")

    lines.append("Aegis AI — QR Scanner")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# CYBERCRIME Q&A — 10 scenarios (Phase 2)
# ═══════════════════════════════════════════════════════════════════════════════

CYBER_QA_RESPONSES = {
    "phishing": (
        "🎣 *What is Phishing?*\n\n"
        "Phishing is when criminals pretend to be a trusted organisation "
        "(like HBL, JazzCash, or NADRA) to steal your personal information.\n\n"
        "🚨 *Common Pakistani phishing tactics:*\n"
        "• Fake SMS saying your JazzCash account is blocked — asks for OTP\n"
        "• Fake HBL/UBL email asking you to 'verify your account'\n"
        "• WhatsApp message claiming you won Rs.50,000\n\n"
        "✅ *How to protect yourself:*\n"
        "• Never share OTP/PIN with anyone, even 'bank staff'\n"
        "• Always check the sender's real email/number\n"
        "• When in doubt, call the official helpline directly\n"
        "• Report to FIA Cyber Crime: nia.gov.pk / 0800-55555"
    ),
    "password": (
        "🔐 *How to Create a Strong Password*\n\n"
        "A strong password has at least 16 characters combining:\n"
        "• UPPERCASE letters\n• lowercase letters\n"
        "• Numbers (0-9)\n• Symbols (@#$%!&*)\n\n"
        "✅ *Recommended approach:*\n"
        "Use a passphrase: *I_Love_Lahore_2024!* is stronger than *L@h0r3*\n\n"
        "🔑 *Best password managers (free):*\n"
        "• Bitwarden (best free option)\n"
        "• Google Password Manager (built into Chrome/Android)\n\n"
        "⚠️ *Never:*\n"
        "• Reuse passwords across sites\n"
        "• Share passwords on WhatsApp\n"
        "• Use your name, phone, or CNIC as password"
    ),
    "2fa": (
        "🔒 *What is 2FA (Two-Factor Authentication)?*\n\n"
        "2FA adds a second lock to your account — even if someone steals "
        "your password, they still can't log in without the second code.\n\n"
        "📱 *Types of 2FA (best to worst):*\n"
        "1. 🏆 Authentication app (Google Authenticator, Authy) — BEST\n"
        "2. 🔑 Hardware key (YubiKey) — BEST for high security\n"
        "3. 📧 Email OTP — Good\n"
        "4. 📱 SMS OTP — OK but can be intercepted via SIM swap\n\n"
        "✅ *Enable 2FA on:*\n"
        "• Gmail / Google account\n"
        "• Facebook / Instagram\n"
        "• JazzCash / EasyPaisa\n"
        "• WhatsApp (Settings → Account → Two-step verification)"
    ),
    "ransomware": (
        "💀 *What is Ransomware?*\n\n"
        "Ransomware is malware that encrypts your files and demands payment "
        "(usually cryptocurrency) to restore them.\n\n"
        "🇵🇰 *Pakistani targets:* hospitals, banks, SMEs, government offices\n\n"
        "🚨 *How it spreads:*\n"
        "• Email attachments (.exe, .zip, .docx with macros)\n"
        "• Malicious downloads\n"
        "• Unpatched Windows systems\n\n"
        "✅ *Prevention:*\n"
        "• Keep Windows/software updated\n"
        "• Back up files to external drive weekly\n"
        "• Use Malwarebytes (free antivirus)\n"
        "• Never enable macros in Word/Excel from unknown sources"
    ),
    "vpn": (
        "🌐 *What is a VPN and Do You Need One?*\n\n"
        "A VPN (Virtual Private Network) encrypts your internet traffic and "
        "hides your real IP address.\n\n"
        "✅ *Use a VPN when:*\n"
        "• Using public WiFi (café, airport, hotel)\n"
        "• Accessing banking apps on public networks\n"
        "• Wanting privacy from your ISP\n\n"
        "🇵🇰 *Recommended free VPNs for Pakistan:*\n"
        "• Proton VPN (best free, no logs)\n"
        "• Windscribe (10GB/month free)\n\n"
        "⚠️ *Avoid:* Free VPNs that sell your data (most app store VPNs)"
    ),
    "sim_swap": (
        "📱 *How to Protect Against SIM Swap Fraud*\n\n"
        "SIM swap fraud is when criminals convince your telecom operator "
        "to transfer your number to a new SIM — giving them your OTPs.\n\n"
        "🇵🇰 *Common in Pakistan:* Jazz, Telenor, Zong customers targeted\n\n"
        "✅ *Protection steps:*\n"
        "• Call your operator and ask them to add a PIN/password to your account\n"
        "• Jazz: 111-78-3333 | Telenor: 345 | Zong: 310\n"
        "• Use an authenticator app instead of SMS for 2FA\n"
        "• Monitor for sudden loss of phone signal\n\n"
        "🚨 *If you suspect SIM swap:* Call your bank and telecom immediately"
    ),
    "wifi": (
        "📶 *Is Public WiFi Safe?*\n\n"
        "Public WiFi in cafés, hotels, and airports is *not* safe for "
        "sensitive activities. Here's why:\n\n"
        "⚠️ *Risks:*\n"
        "• Hackers can intercept your traffic (Man-in-the-Middle attack)\n"
        "• Fake hotspots with names like 'Free_WiFi_Cafe'\n"
        "• Packet sniffing to steal passwords\n\n"
        "✅ *Safe practices:*\n"
        "• Use a VPN (Proton VPN is free)\n"
        "• Never do banking on public WiFi\n"
        "• Check the network name is official before connecting\n"
        "• Use mobile data for sensitive tasks"
    ),
    "report": (
        "📋 *How to Report Cybercrime in Pakistan*\n\n"
        "🏛️ *FIA Cyber Crime Wing (Official)*\n"
        "• Website: nia.gov.pk\n"
        "• Helpline: 0800-55555 (toll-free)\n"
        "• Email: complaint@fia.gov.pk\n"
        "• Online complaint: complaint.fia.gov.pk\n\n"
        "📱 *PTA Consumer Support (telecom fraud):*\n"
        "• SMS: 9000\n"
        "• Online: complaint.pta.gov.pk\n\n"
        "🏦 *Bank fraud:*\n"
        "• HBL: 111-111-425\n"
        "• UBL: 111-825-888\n"
        "• MCB: 111-000-111\n\n"
        "📸 *What to include in your report:*\n"
        "• Screenshots of messages/profiles\n"
        "• Transaction IDs if money was transferred\n"
        "• Date, time, and phone number of fraudster"
    ),
    "hacked": (
        "🔓 *Signs Your Account/Phone May Be Hacked*\n\n"
        "🚨 *Warning signs:*\n"
        "• Unusual login alerts from unknown locations\n"
        "• Messages sent you didn't write\n"
        "• Contacts say they received strange messages from you\n"
        "• Battery draining faster than usual\n"
        "• Unknown apps installed\n\n"
        "✅ *Immediate steps:*\n"
        "1. Change your email password immediately\n"
        "2. Change passwords for banking/social apps\n"
        "3. Check connected apps in your Google/Facebook account\n"
        "4. Enable 2FA on all accounts\n"
        "5. Factory reset your phone if problems persist\n\n"
        "📋 Report if money was stolen: FIA 0800-55555"
    ),
    "social_engineering": (
        "🎭 *What is Social Engineering?*\n\n"
        "Social engineering tricks people (not computers) into giving up "
        "sensitive information by building fake trust.\n\n"
        "🇵🇰 *Common Pakistani examples:*\n"
        "• Fake 'bank employee' calling to verify your card\n"
        "• Pretending to be NADRA asking for CNIC verification\n"
        "• WhatsApp message: 'I'm from Telenor, your account will be blocked'\n"
        "• Job offer requiring advance payment\n\n"
        "✅ *Golden rules:*\n"
        "• No real bank/telecom will ask for your OTP or PIN\n"
        "• Hang up and call back using the official number\n"
        "• Urgency + pressure = scam signal\n"
        "• When in doubt, say 'I'll call back through the official number'"
    ),
        "deepfake": (
        "🎭 *What is a Deepfake?*\n\n"
        "Deepfakes are AI-generated videos, images, or audio that convincingly "
        "manipulate or replace a person's face, voice, or expressions.\n\n"
        "🚨 *Why it matters:*\n"
        "• Scammers use deepfakes to impersonate CEOs, family members, or celebrities\n"
        "• Fake videos can spread misinformation and fraud\n"
        "• Voice cloning is used to trick people into sending money\n\n"
        "✅ *How to spot deepfakes:*\n"
        "• Unnatural blinking or eye movements\n"
        "• Blurry face edges or inconsistent lighting\n"
        "• Strange audio artifacts or mismatched lip sync\n"
        "• Use Aegis's deepfake detection to analyse suspicious media\n\n"
        "📋 Report suspicious AI-generated content to FIA Cyber Crime: nia.gov.pk"
    ),
}

def format_cyber_qa(topic: str, explanation: str = "") -> str:
    """Format a cybersecurity Q&A response."""
    # Find best matching topic
    topic_lower = topic.lower()
    best_key = None
    best_score = 0
    for key in CYBER_QA_RESPONSES:
        score = sum(1 for kw in [key, key.replace("_"," ")] if kw in topic_lower)
        if score > best_score:
            best_score, best_key = score, key

    # Also match by keywords
    if not best_key:
        keyword_map = {
            "phishing": ["phish","scam sms","smishing","fake email","fake sms"],
            "password": ["password","passcode","passphrase","strong pass"],
            "2fa": ["2fa","two factor","otp","verification code","authenticat"],
            "ransomware": ["ransomware","ransom","encrypted files","malware"],
            "vpn": ["vpn","virtual private","proxy","hide ip"],
            "sim_swap": ["sim","sim swap","sim cloning","mobile number","hijack"],
            "wifi": ["wifi","wi-fi","public wifi","hotspot","network"],
            "report": ["report","complaint","fia","cybercrime","lodge","file complaint"],
            "hacked": ["hacked","hack","compromise","breach","account taken"],
            "social_engineering": ["social engineer","pretexting","manipulation","trick","deceive"],
        }
        for key, kws in keyword_map.items():
            if any(kw in topic_lower for kw in kws):
                best_key = key
                break

    base = CYBER_QA_RESPONSES.get(best_key or "phishing")
    if explanation:
        base = base + f"\n\n💬 {explanation}"
    return base


# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-LANGUAGE SUPPORT (Phase 2)
# ═══════════════════════════════════════════════════════════════════════════════

HELP_MENU_URDU = """🛡️ *Aegis AI mein khush aamdeed!*

Main aapki in cheezein analyse kar sakta hoon:
🔗 *Links* — Koi bhi URL bhejain phishing check ke liye
📷 *QR Codes* — QR code ki image bhejain scan ke liye
🔑 *Credentials* — Password, email, card, CNIC, API keys
👤 *Social Profiles* — @handle bhejain ya /profile use karein

*Quick Commands:*
• `/scan <url>` — Link scan karein
• `/qr` — QR code scan karein
• `/profile <username>` — Social profile analyse karein
• `/check` — Credential check menu
• `/history` — Apni scan history dekhain
• `/clear` — Session data delete karein
• `/language english` — Switch to English

_Sab data 30 days ke baad delete ho jata hai._"""

IRRELEVANT_URDU = """Yeh mere kaam ki baat nahi. Main sirf cybersecurity ke liye bana hoon.

Main aapki maddad kar sakta hoon:
• 🔗 Link safe hai ya nahi check karne mein
• 📷 QR code scan karne mein
• 🔑 Credential breach check karne mein
• 👤 Fake profile detect karne mein

Koi suspicious cheez bhejain aur main check karoonga!"""


def get_language_preference(session: dict) -> str:
    """Get user's preferred language from session."""
    return session.get("language", "english")


def format_in_language(english_text: str, language: str) -> str:
    """Apply language preference — Urdu translation via Gemini if available."""
    if language == "english":
        return english_text
    # For Urdu: return as-is (Gemini will translate in orchestrator if available)
    return english_text



# ═══════════════════════════════════════════════════════════════════════════════
# FULL CAPABILITY MENU (Bug 6 fix — general help menu with all services)
# ═══════════════════════════════════════════════════════════════════════════════

FULL_CAPABILITY_MENU = """🛡️ *Aegis AI — Cybersecurity Assistant*

Here's everything I can check for you:

🔗 *Links & Websites*
  Send any URL → Safety check, malware, phishing detection
  Send a bare domain (e.g. `paypal.com`) → 3 options shown

📷 *QR Codes*
  Send a QR code image → Decode + safety check
  `/generate <url>` → Create a safe QR code

📧 *Email Addresses*
  Send email → Choose: 🔑 Breach check  OR  👤 Fraud/scam analysis
  e.g. `user@example.com`

📱 *Phone Numbers*
  Send phone → Choose: 🔑 Breach check  OR  👤 Fraud/scam analysis
  e.g. `+923001234567` or `03001234567`

🔐 *Credentials* (via `/check` or just send directly)
  1️⃣ Email → breach check     2️⃣ Password → strength + breaches
  3️⃣ Username → breach check  4️⃣ Payment card → fraud check
  5️⃣ IBAN → validation        6️⃣ Crypto wallet → risk check
  7️⃣ CNIC / ID → validation   8️⃣ Passport MRZ → check
  9️⃣ Phone → breach check     🔟 API key / token → exposure check

👤 *Social Media Profiles*
  Send `@username` → Full profile intelligence (fake/scammer/breached)
  Send `cryptoking99` → 4 options: Profile / Credential / Both / Password

📩 *SMS / Smishing*
  Paste any suspicious SMS → AI-powered scam detection

🎓 *Cybersecurity Q&A*
  Ask anything: `what is phishing?`, `how do I use 2FA?`, etc.

⚙️ *Commands*
  `/check` — Credential analysis menu
  `/history` — Your scan history
  `/clear` — Delete session data (GDPR)
  `/language urdu` — Switch to Urdu
  `/help` — Show this menu

_Just send me anything suspicious and I'll analyse it!_ 🔍"""