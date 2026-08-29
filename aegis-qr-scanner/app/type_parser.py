"""
Feature 1.3 - Full QR Type Parser (15 Types)
Identifies every QR payload type and extracts structured data + all embedded URLs
for Link Analyzer deep-scan.
"""
import re
from urllib.parse import urlparse, parse_qs, unquote
from app.logger import log

# ─────────────────────────────────────────────────────────────
# Pattern registry — ordered by specificity (most specific first)
# ─────────────────────────────────────────────────────────────
QR_TYPE_PATTERNS = [
    ("wifi",         r"^WIFI:",                                    "Wi-Fi Configuration"),
    ("vcard",        r"^BEGIN:VCARD",                              "Contact Card (vCard)"),
    ("mecard",       r"^MECARD:",                                  "Contact Card (MeCard)"),
    ("calendar",     r"^BEGIN:VEVENT",                             "Calendar Event (iCal)"),
    ("bitcoin",      r"^(bitcoin|ethereum|litecoin|monero|bnb):",  "Cryptocurrency Payment"),
    ("geo",          r"^geo:",                                     "GPS Coordinates"),
    ("app_deeplink", r"^(intent|market|fb|twitter|instagram|whatsapp|tg|viber)://", "App Deep Link"),
    ("data_uri",     r"^data:",                                    "Data URI (HTML/JS Injection Risk)"),
    ("ftp",          r"^ftps?://",                                 "FTP Connection"),
    ("ssh",          r"^ssh://",                                   "SSH Connection"),
    ("magnet",       r"^magnet:\?",                                "Magnet/Torrent Link"),
    ("email",        r"^mailto:",                                  "Email Address"),
    ("sms",          r"^(sms|smsto):",                             "SMS Message"),
    ("tel",          r"^tel:",                                     "Phone Number"),
    ("url",          r"^https?://",                                "URL / Website"),
]

# ─────────────────────────────────────────────────────────────
# Individual parsers — return structured dict + urls_to_scan
# ─────────────────────────────────────────────────────────────

def _parse_wifi(raw: str) -> dict:
    ssid_m = re.search(r"S:([^;\\]+)", raw)
    type_m = re.search(r"T:([^;\\]+)", raw)
    pass_m = re.search(r"P:([^;\\]+)", raw)
    hidden_m = re.search(r"H:(true|false)", raw, re.IGNORECASE)

    ssid = ssid_m.group(1) if ssid_m else "Unknown"
    security = type_m.group(1) if type_m else "nopass"
    password = pass_m.group(1) if pass_m else None
    is_hidden = hidden_m and hidden_m.group(1).lower() == "true"

    return {
        "qr_type":     "wifi",
        "label":       "Wi-Fi Configuration",
        "ssid":        ssid,
        "security":    security,
        "has_password": bool(password),
        "password_in_qr": bool(password),   # Password exposed in QR = risk
        "is_hidden":   bool(is_hidden),
        "urls_to_scan": []
    }

def _parse_vcard(raw: str) -> dict:
    lines = raw.strip().split("\n")
    fields = {}
    for line in lines:
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.split(";")[0].strip().upper()
            if key in fields:
                existing = fields[key] if isinstance(fields[key], list) else [fields[key]]
                existing.append(value.strip())
                fields[key] = existing
            else:
                fields[key] = value.strip()

    phones = fields.get("TEL", [])
    emails = fields.get("EMAIL", [])
    if isinstance(phones, str): phones = [phones]
    if isinstance(emails, str): emails = [emails]

    # Extract all embedded URLs
    embedded_urls = re.findall(r'https?://[^\s"\'<>\r\n]+', raw)
    url_field = fields.get("URL", "")
    if isinstance(url_field, str) and url_field: embedded_urls.append(url_field)
    if isinstance(url_field, list): embedded_urls.extend(url_field)
    embedded_urls = list(set(embedded_urls))

    return {
        "qr_type":     "vcard",
        "label":       "Contact Card (vCard)",
        "name":        fields.get("FN", fields.get("N", "Unknown")),
        "organization": fields.get("ORG"),
        "title":       fields.get("TITLE"),
        "phones":      phones,
        "emails":      emails,
        "urls":        embedded_urls,
        "note":        fields.get("NOTE"),
        "risk_note":   "Check all embedded URLs and phone numbers — contact injection attack vector",
        "urls_to_scan": embedded_urls    # These go to Link Analyzer
    }

def _parse_mecard(raw: str) -> dict:
    # MECARD:N:Doe,John;TEL:+441234567890;EMAIL:john@evil.com;URL:https://evil.com;;
    def _extract(field, text):
        m = re.search(rf"{field}:([^;]+)", text)
        return m.group(1).strip() if m else None

    url = _extract("URL", raw)
    return {
        "qr_type":     "mecard",
        "label":       "Contact Card (MeCard)",
        "name":        _extract("N", raw),
        "phone":       _extract("TEL", raw),
        "email":       _extract("EMAIL", raw),
        "url":         url,
        "address":     _extract("ADR", raw),
        "urls_to_scan": [url] if url else []
    }

def _parse_calendar(raw: str) -> dict:
    def _extract(field, text):
        m = re.search(rf"{field}[;:][^\r\n]+", text)
        return m.group(0).split(":", 1)[1].strip() if m else None

    urls = re.findall(r'https?://[^\s\r\n"\']+', raw)
    location = _extract("LOCATION", raw)
    url = _extract("URL", raw)

    # Detect suspicious patterns
    flags = []
    summary = _extract("SUMMARY", raw) or ""
    if any(w in summary.lower() for w in ["verify", "login", "account", "urgent", "bank", "payment"]):
        flags.append("Suspicious event title — may be social engineering")
    if urls:
        flags.append(f"{len(urls)} URL(s) embedded in calendar event")

    return {
        "qr_type":     "calendar",
        "label":       "Calendar Event",
        "summary":     summary,
        "start":       _extract("DTSTART", raw),
        "end":         _extract("DTEND", raw),
        "location":    location,
        "organizer":   _extract("ORGANIZER", raw),
        "description": (_extract("DESCRIPTION", raw) or "")[:200],
        "embedded_urls": urls,
        "flags":       flags,
        "risk_note":   "Calendar events can embed malicious URLs — verify organizer",
        "urls_to_scan": urls
    }

def _parse_bitcoin(raw: str) -> dict:
    scheme_m = re.match(r"(\w+):([^?]+)", raw)
    params = parse_qs(raw.split("?")[1]) if "?" in raw else {}
    coin = scheme_m.group(1).lower() if scheme_m else "unknown"
    address = scheme_m.group(2).strip() if scheme_m else None
    amount = params.get("amount", [None])[0]
    label = params.get("label", [None])[0]
    message = params.get("message", [None])[0]

    # Basic address format validation
    address_flags = []
    if address:
        if coin == "bitcoin":
            if not re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$', address):
                address_flags.append("Bitcoin address format invalid — may be a scam")
        if len(address) < 20:
            address_flags.append("Suspiciously short wallet address")

    return {
        "qr_type":       "bitcoin",
        "label":         "Cryptocurrency Payment",
        "coin":          coin,
        "wallet_address": address,
        "amount_requested": amount,
        "label":         label,
        "message":       message,
        "address_flags": address_flags,
        "risk_note":     "Verify wallet address independently — crypto transactions are irreversible",
        "blockchain_explorer": f"https://www.blockchain.com/explorer/addresses/btc/{address}" if coin == "bitcoin" and address else None,
        "urls_to_scan":  []
    }

def _parse_geo(raw: str) -> dict:
    m = re.match(r"geo:(-?\d+\.?\d*),(-?\d+\.?\d*)(?:,(-?\d+\.?\d*))?(?:\?(.*))?", raw, re.IGNORECASE)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        altitude = float(m.group(3)) if m.group(3) else None
        # Basic bounds check
        valid = -90 <= lat <= 90 and -180 <= lon <= 180
        return {
            "qr_type":       "geo",
            "label":         "GPS Coordinates",
            "latitude":      lat,
            "longitude":     lon,
            "altitude":      altitude,
            "coordinates_valid": valid,
            "google_maps_url": f"https://maps.google.com/?q={lat},{lon}",
            "risk_note":     "QR code directs to physical location — verify before travelling",
            "urls_to_scan":  []
        }
    return {"qr_type": "geo", "label": "GPS Coordinates", "parse_error": True, "raw": raw, "urls_to_scan": []}

def _parse_app_deeplink(raw: str) -> dict:
    package_m = re.search(r"package=([^;&#\s]+)", raw)
    scheme_m = re.search(r"scheme=([^;&#\s]+)", raw)
    host_m = re.search(r"host=([^;&#\s]+)", raw)
    parsed = urlparse(raw)

    # Reconstruct target URL if possible
    target_url = None
    if scheme_m and host_m:
        target_url = f"{scheme_m.group(1)}://{host_m.group(1)}"

    # Extract any http/https URLs embedded in the deep link
    embedded_urls = re.findall(r'https?://[^\s"\'<>;]+', unquote(raw))

    return {
        "qr_type":        "app_deeplink",
        "label":          "App Deep Link",
        "scheme":         parsed.scheme,
        "target_package": package_m.group(1) if package_m else None,
        "target_scheme":  scheme_m.group(1) if scheme_m else None,
        "target_host":    host_m.group(1) if host_m else None,
        "reconstructed_url": target_url,
        "embedded_urls":  embedded_urls,
        "raw_intent":     raw,
        "risk_note":      "Deep links bypass browser security — can launch apps or trigger actions silently",
        "urls_to_scan":   embedded_urls + ([target_url] if target_url and target_url.startswith("http") else [])
    }

def _parse_email(raw: str) -> dict:
    # mailto:victim@evil.com?subject=Hello&body=Click+here+http://evil.com
    address_m = re.match(r"mailto:([^?]+)", raw, re.IGNORECASE)
    address = address_m.group(1).strip() if address_m else None
    params = parse_qs(raw.split("?")[1]) if "?" in raw else {}
    body = params.get("body", [None])[0] or ""

    embedded_urls = re.findall(r'https?://[^\s"\'<>]+', body)
    flags = []
    if any(w in body.lower() for w in ["verify", "login", "account", "password", "urgent", "bank"]):
        flags.append("Suspicious keywords in email body — possible phishing pre-draft")
    if embedded_urls:
        flags.append(f"{len(embedded_urls)} URL(s) embedded in pre-drafted email body")

    return {
        "qr_type":    "email",
        "label":      "Email Address",
        "address":    address,
        "subject":    params.get("subject", [None])[0],
        "body":       body[:300],
        "flags":      flags,
        "embedded_urls_in_body": embedded_urls,
        "urls_to_scan": embedded_urls
    }

def _parse_sms(raw: str) -> dict:
    # smsto:+441234567890:Message body here
    parts = raw.split(":", 2)
    number = parts[1].strip() if len(parts) > 1 else None
    body = parts[2].strip() if len(parts) > 2 else ""
    embedded_urls = re.findall(r'https?://[^\s"\'<>]+', body)

    flags = []
    if any(w in body.lower() for w in ["verify", "click", "urgent", "bank", "won", "prize", "free"]):
        flags.append("Suspicious keywords in SMS body — possible smishing")
    premium_rate = bool(re.match(r'\+?1?900|0909|0871|0872|0873|09\d{2}', number or ""))
    if premium_rate:
        flags.append("Premium-rate number detected — calling may incur high charges")

    return {
        "qr_type":    "sms",
        "label":      "SMS Message",
        "number":     number,
        "body":       body[:300],
        "is_premium_rate": premium_rate,
        "flags":      flags,
        "embedded_urls_in_body": embedded_urls,
        "urls_to_scan": embedded_urls
    }

def _parse_tel(raw: str) -> dict:
    number = raw.replace("tel:", "").strip()
    premium = bool(re.match(r'\+?1?900|0909|0871|0872|0873|09\d{2}', number))
    return {
        "qr_type":    "tel",
        "label":      "Phone Number",
        "number":     number,
        "is_premium_rate": premium,
        "risk_note":  "Premium-rate number — verify before calling" if premium else None,
        "urls_to_scan": []
    }

def _parse_url(raw: str) -> dict:
    parsed = urlparse(raw)
    return {
        "qr_type":    "url",
        "label":      "URL / Website",
        "url":        raw,
        "scheme":     parsed.scheme,
        "domain":     parsed.netloc,
        "path":       parsed.path,
        "has_query":  bool(parsed.query),
        "urls_to_scan": [raw]    # Primary URL goes to Link Analyzer
    }

def _parse_ftp_ssh(raw: str, qr_type: str) -> dict:
    parsed = urlparse(raw)
    return {
        "qr_type":    qr_type,
        "label":      "FTP Connection" if qr_type == "ftp" else "SSH Connection",
        "host":       parsed.hostname,
        "port":       parsed.port,
        "user":       parsed.username,
        "path":       parsed.path,
        "risk_note":  f"{'FTP is unencrypted — credentials sent in plain text' if qr_type == 'ftp' else 'SSH connection string — verify host fingerprint'}",
        "urls_to_scan": []
    }

def _parse_magnet(raw: str) -> dict:
    dn_m = re.search(r"dn=([^&]+)", raw)
    xt_m = re.search(r"xt=urn:btih:([a-fA-F0-9]+)", raw)
    return {
        "qr_type":    "magnet",
        "label":      "Magnet/Torrent Link",
        "display_name": unquote(dn_m.group(1)) if dn_m else None,
        "info_hash":  xt_m.group(1) if xt_m else None,
        "risk_note":  "Torrent links may reference pirated or malicious content",
        "urls_to_scan": []
    }

def _parse_data_uri(raw: str) -> dict:
    header, _, data_part = raw.partition(",")
    media_type = header.split(":")[1].split(";")[0].strip() if ":" in header else "unknown"
    return {
        "qr_type":    "data_uri",
        "label":      "Data URI",
        "media_type": media_type,
        "is_base64":  ";base64" in header.lower(),
        "data_preview": data_part[:100],
        "risk_note":  "Data URIs can embed full HTML pages with JavaScript — high injection risk",
        "urls_to_scan": []
    }

def _parse_generic_text(raw: str) -> dict:
    embedded_urls = re.findall(r'https?://[^\s"\'<>]+', raw)
    return {
        "qr_type":    "text",
        "label":      "Plain Text",
        "content":    raw[:500],
        "embedded_urls": embedded_urls,
        "urls_to_scan": embedded_urls   # Any URLs found still go to Link Analyzer
    }

# ─────────────────────────────────────────────────────────────
# PUBLIC
# ─────────────────────────────────────────────────────────────

def identify_and_parse(raw: str) -> dict:
    """
    Identifies the QR payload type and returns fully parsed structured data.
    The 'urls_to_scan' field in the result contains all URLs that should
    be sent to the Link Analyzer microservice.
    """
    raw = raw.strip()

    for type_id, pattern, label in QR_TYPE_PATTERNS:
        if re.match(pattern, raw, re.IGNORECASE):
            log.info(f"[TypeParser] Identified type: {type_id} — {label}")
            try:
                if type_id == "wifi":          return _parse_wifi(raw)
                elif type_id == "vcard":       return _parse_vcard(raw)
                elif type_id == "mecard":      return _parse_mecard(raw)
                elif type_id == "calendar":    return _parse_calendar(raw)
                elif type_id == "bitcoin":     return _parse_bitcoin(raw)
                elif type_id == "geo":         return _parse_geo(raw)
                elif type_id == "app_deeplink": return _parse_app_deeplink(raw)
                elif type_id == "email":       return _parse_email(raw)
                elif type_id == "sms":         return _parse_sms(raw)
                elif type_id == "tel":         return _parse_tel(raw)
                elif type_id == "url":         return _parse_url(raw)
                elif type_id in ("ftp", "ssh"): return _parse_ftp_ssh(raw, type_id)
                elif type_id == "magnet":      return _parse_magnet(raw)
                elif type_id == "data_uri":    return _parse_data_uri(raw)
            except Exception as e:
                log.error(f"[TypeParser] Parser for '{type_id}' crashed: {e}")
                break

    # Fallback — generic text (also scans for embedded URLs)
    log.info("[TypeParser] No pattern matched — treating as plain text")
    return _parse_generic_text(raw)
