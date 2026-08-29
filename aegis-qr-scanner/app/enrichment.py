"""
enrichment.py — Phase 3 External Intelligence Engine (v5.2)
============================================================
Fixes in v5.2:
  - URLHaus REMOVED from enrich_url() — Link Analyzer already runs it internally
    (visible in url_deep_scans[].urlhaus). Calling it here caused 401 errors.
  - Chainabuse: multi-endpoint fallback (GraphQL → REST → v0 REST)
  - Blockchain.com: result handling hardened against concurrent failure
  - enrich_url() now returns GSB + AbuseIPDB only (cleaner, no redundancy)

APIs active:
  GSB   — Google Safe Browsing     URL phishing/malware  (reuse existing key)
  ABDB  — AbuseIPDB                IP reputation         (IP-based URLs only)
  EREP  — EmailRep.io              Email breach/spam     (free, no key)
  NVRFY — NumVerify                Phone validation      (reuse existing key)
  CHNAB — Chainabuse               Crypto scam reports   (user has key)
  BCHN  — Blockchain.com           BTC tx history        (free, no key)
"""

import os
import re
import asyncio
import urllib.parse
from typing import Optional

import httpx
from app.logger import log


# ─── API Keys ────────────────────────────────────────────────
GSB_API_KEY    = os.getenv("GSB_API_KEY", "")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY", "")
NUMVERIFY_KEY  = os.getenv("NUMVERIFY_KEY", "")
CHAINABUSE_KEY = os.getenv("CHAINABUSE_KEY", "")
EMAILREP_KEY   = os.getenv("EMAILREP_KEY", "")

TIMEOUT = 8.0

_RISK_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Safe": 1}


def _max_risk(risks: list) -> str:
    return max(risks, key=lambda r: _RISK_ORDER.get(r, 0)) if risks else "Safe"


def _collect_flags(*sources) -> list:
    flags = []
    for src in sources:
        if isinstance(src, dict):
            flags.extend(src.get("flags", []))
    return flags


async def _skipped(note: str = "") -> dict:
    return {"status": "skipped", "note": note}


# ═══════════════════════════════════════════════════════════════
# 1. Google Safe Browsing — URL Phishing / Malware
# ═══════════════════════════════════════════════════════════════

async def gsb_check_url(url: str) -> dict:
    """
    Google Safe Browsing v4 — reuses existing GSB_API_KEY from Link Analyzer.
    Note: Link Analyzer also calls GSB; this QR-side call gives a direct result
    in phase3_enrichment independent of the link analyzer result.
    Free: 10,000/day. Checks: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, PHA.
    """
    if not GSB_API_KEY:
        return {"status": "skipped", "note": "Copy GSB_API_KEY from Link Analyzer .env"}

    try:
        payload = {
            "client": {"clientId": "aegis-qr-scanner", "clientVersion": "5.2"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}],
            },
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": GSB_API_KEY},
                json=payload,
                timeout=TIMEOUT,
            )

        if resp.status_code != 200:
            return {"status": "api_error", "http_code": resp.status_code}

        matches = resp.json().get("matches", [])
        if not matches:
            return {"status": "ok", "source": "google_safe_browsing",
                    "matched": False, "risk_level": "Safe", "flags": []}

        threat_labels = {
            "MALWARE":                         "Malware Distribution",
            "SOCIAL_ENGINEERING":              "Phishing / Social Engineering",
            "UNWANTED_SOFTWARE":               "Unwanted Software",
            "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful App",
        }
        threat_severity = {"MALWARE": 100, "SOCIAL_ENGINEERING": 100,
                           "POTENTIALLY_HARMFUL_APPLICATION": 80, "UNWANTED_SOFTWARE": 75}

        threat_types = list({m.get("threatType", "UNKNOWN") for m in matches})
        max_sev      = max(threat_severity.get(t, 70) for t in threat_types)
        risk_level   = "Critical" if max_sev >= 90 else "High"
        flags        = [f"GSB: {threat_labels.get(t, t)} — Google confirmed"
                        for t in threat_types]

        log.info(f"[GSB] {url[:60]} → threats={threat_types} risk={risk_level}")
        return {
            "status": "ok", "source": "google_safe_browsing",
            "matched": True, "threat_types": threat_types,
            "risk_level": risk_level, "flags": flags,
        }

    except Exception as e:
        log.warning(f"[GSB] check failed: {e}")
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════════
# 2. AbuseIPDB — IP Reputation (triggered only for IP-based URLs)
# ═══════════════════════════════════════════════════════════════

_IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _extract_ip_from_url(url: str) -> Optional[str]:
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        if _IP_PATTERN.match(host):
            return host
    except Exception:
        pass
    return None


async def abuseipdb_check(ip: str) -> dict:
    """
    AbuseIPDB — 100M+ abuse reports. Only triggered when URL has raw IP address.
    Free: 1,000/day. https://www.abuseipdb.com/
    """
    if not ABUSEIPDB_KEY:
        return {"status": "skipped", "note": "Set ABUSEIPDB_KEY in .env"}

    private = ("10.", "192.168.", "127.", "169.254.", "::1",
                "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                "172.28.", "172.29.", "172.30.", "172.31.")
    if any(ip.startswith(p) for p in private):
        return {"status": "skipped", "note": f"Private IP ({ip})"}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                timeout=TIMEOUT,
            )

        if resp.status_code != 200:
            return {"status": "api_error", "http_code": resp.status_code}

        data       = resp.json().get("data", {})
        confidence = data.get("abuseConfidenceScore", 0)
        total      = data.get("totalReports", 0)
        is_tor     = data.get("isTor", False)
        usage_type = data.get("usageType")

        flags = []
        if confidence >= 80: flags.append(f"AbuseIPDB: High abuse confidence ({confidence}%)")
        if is_tor:           flags.append("AbuseIPDB: Tor exit node")
        if total >= 50:      flags.append(f"AbuseIPDB: {total} reports in 90 days")
        if usage_type and "Data Center" in usage_type:
            flags.append("AbuseIPDB: Datacenter IP — unusual for end-user URL")

        risk_level = ("Critical" if (confidence >= 80 or is_tor) else
                      "High"     if confidence >= 50 else
                      "Medium"   if confidence >= 25 else
                      "Low"      if total > 0 else "Safe")

        log.info(f"[AbuseIPDB] {ip} → confidence={confidence}% risk={risk_level}")
        return {
            "status": "ok", "source": "abuseipdb", "ip": ip,
            "abuse_confidence": confidence, "total_reports": total,
            "is_tor": is_tor, "isp": data.get("isp"),
            "country": data.get("countryCode"), "usage_type": usage_type,
            "risk_level": risk_level, "flags": flags,
        }

    except Exception as e:
        log.warning(f"[AbuseIPDB] {ip} failed: {e}")
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════════
# 3. EmailRep.io — Email Reputation (Free, replaces HIBP)
# ═══════════════════════════════════════════════════════════════

async def emailrep_check(email: str) -> dict:
    """
    EmailRep.io — free, no key required.
    Covers: breach, credential leak, disposable, spam, blacklisted, spoofable.
    Rate limit: 10/hr without key, 1000+/hr with key.
    Register (optional): https://emailrep.io/key
    """
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"status": "skipped", "note": "Invalid email format"}

    try:
        headers = {"User-Agent": "Aegis-QR-Scanner/5.2"}
        if EMAILREP_KEY:
            headers["Key"] = EMAILREP_KEY

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://emailrep.io/{urllib.parse.quote(email)}",
                headers=headers,
                timeout=TIMEOUT,
            )

        if resp.status_code == 400:
            return {"status": "invalid_email"}
        if resp.status_code == 429:
            return {"status": "rate_limited",
                    "note": "EmailRep rate limit — add EMAILREP_KEY for 1000+/hr"}
        if resp.status_code != 200:
            return {"status": "api_error", "http_code": resp.status_code}

        data    = resp.json()
        details = data.get("details", {})

        reputation        = data.get("reputation", "none")
        suspicious        = data.get("suspicious", False)
        references        = data.get("references", 0)
        blacklisted       = details.get("blacklisted", False)
        malicious_activity = details.get("malicious_activity", False)
        malicious_recent  = details.get("malicious_activity_recent", False)
        credentials_leaked = details.get("credentials_leaked", False)
        credentials_recent = details.get("credentials_leaked_recent", False)
        data_breach       = details.get("data_breach", False)
        spam              = details.get("spam", False)
        disposable        = details.get("disposable", False)
        spoofable         = details.get("spoofable", False)
        domain_reputation = details.get("domain_reputation", "none")
        last_seen         = details.get("last_seen")

        flags = []
        if blacklisted:          flags.append("EmailRep: BLACKLISTED — known malicious actor")
        if malicious_recent:     flags.append("EmailRep: Recent malicious activity")
        elif malicious_activity: flags.append("EmailRep: Historical malicious activity")
        if credentials_recent:   flags.append("EmailRep: Credentials RECENTLY leaked in breach")
        elif credentials_leaked: flags.append("EmailRep: Credentials in credential dump")
        elif data_breach:        flags.append("EmailRep: Found in known data breach")
        if disposable:           flags.append("EmailRep: DISPOSABLE/throwaway email address")
        if spam:                 flags.append("EmailRep: Linked to spam campaigns")
        if spoofable:            flags.append("EmailRep: Domain has no SPF/DMARC — spoofable")
        if reputation == "none" and references == 0:
            flags.append("EmailRep: Zero references — brand-new or unseen email")

        if blacklisted or malicious_recent or credentials_recent:
            risk_level = "Critical"
        elif malicious_activity or credentials_leaked or suspicious:
            risk_level = "High"
        elif data_breach or spam or disposable:
            risk_level = "Medium"
        elif reputation == "low" or spoofable:
            risk_level = "Low"
        else:
            risk_level = "Safe"

        log.info(f"[EmailRep] {email} → reputation={reputation} breach={data_breach} "
                 f"disposable={disposable} risk={risk_level}")

        return {
            "status": "ok", "source": "emailrep.io", "email": email,
            "reputation": reputation, "suspicious": suspicious, "references": references,
            "blacklisted": blacklisted, "malicious_activity": malicious_activity,
            "malicious_recent": malicious_recent, "credentials_leaked": credentials_leaked,
            "credentials_recent": credentials_recent, "data_breach": data_breach,
            "spam": spam, "disposable": disposable, "spoofable": spoofable,
            "domain_reputation": domain_reputation, "last_seen": last_seen,
            "risk_level": risk_level, "flags": flags,
        }

    except Exception as e:
        log.warning(f"[EmailRep] {email} failed: {e}")
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════════
# 4. NumVerify — Phone Validation (existing key from Phase 1)
# ═══════════════════════════════════════════════════════════════

async def numverify_check(phone: str) -> dict:
    """
    NumVerify — validates phone numbers, returns line type (VOIP/mobile/landline/special).
    NUMVERIFY_KEY already in system from Phase 1. Free: 100/month.
    """
    if not NUMVERIFY_KEY:
        return {"status": "skipped", "note": "Set NUMVERIFY_KEY (reuse Phase 1 key)"}
    if not phone:
        return {"status": "skipped", "note": "No phone number"}

    try:
        clean = re.sub(r"[^\d+]", "", phone)
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://apilayer.net/api/validate",
                params={"access_key": NUMVERIFY_KEY, "number": clean, "format": 1},
                timeout=TIMEOUT,
            )

        if resp.status_code != 200:
            return {"status": "api_error", "http_code": resp.status_code}

        data = resp.json()
        if "error" in data and not data.get("valid"):
            err = data["error"]
            return {"status": "auth_error", "code": err.get("code"), "info": err.get("info")}

        is_valid  = data.get("valid", False)
        line_type = data.get("line_type")
        carrier   = data.get("carrier")
        country   = data.get("country_name")
        intl_fmt  = data.get("international_format", clean)

        flags = []
        if not is_valid:                    flags.append("NumVerify: INVALID/unassigned number")
        if line_type == "voip":             flags.append("NumVerify: VOIP — commonly used by scammers")
        if line_type == "special_services": flags.append("NumVerify: Premium-rate/special number")
        if not country and is_valid:        flags.append("NumVerify: Country unknown — possibly spoofed")

        risk_level = ("High"   if not is_valid else
                      "Medium" if line_type in ("voip", "special_services") else "Safe")

        log.info(f"[NumVerify] {clean} → valid={is_valid} type={line_type} risk={risk_level}")
        return {
            "status": "ok", "source": "numverify", "phone": intl_fmt,
            "is_valid": is_valid, "country": country, "carrier": carrier,
            "line_type": line_type, "location": data.get("location"),
            "risk_level": risk_level, "flags": flags,
        }

    except Exception as e:
        log.warning(f"[NumVerify] {phone} failed: {e}")
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════════
# 5. Chainabuse — Crypto Scam Reports (multi-endpoint fallback)
# ═══════════════════════════════════════════════════════════════

async def chainabuse_check(address: str) -> dict:
    """
    Chainabuse (successor to BitcoinAbuse) — crowdsourced crypto scam reports.
    Tries multiple API endpoint formats with fallback:
      1. GraphQL at /graphql
      2. REST v1 at /v1/reports
      3. REST v0 at /v0/reports
    """
    if not CHAINABUSE_KEY:
        return {"status": "skipped", "note": "Set CHAINABUSE_KEY in .env (chainabuse.com)"}
    if not address:
        return {"status": "skipped", "note": "No address provided"}

    headers = {
        "Authorization": f"Bearer {CHAINABUSE_KEY}",
        "Content-Type":  "application/json",
        "User-Agent":    "Aegis-QR-Scanner/5.2",
    }

    # ── Attempt 1: GraphQL ───────────────────────────────────
    gql_query = """
    query SearchReports($address: String!) {
      reports(address: $address) {
        totalCount
        edges {
          node {
            id
            category
            description
            createdAt
          }
        }
      }
    }
    """
    gql_payload = {"query": gql_query, "variables": {"address": address}}

    endpoints = [
        ("graphql_v1", "POST", "https://api.chainabuse.com/graphql",       None,             gql_payload),
        ("graphql_v2", "POST", "https://www.chainabuse.com/api/graphql",   None,             gql_payload),
        ("rest_v1",    "GET",  "https://api.chainabuse.com/v1/reports",    {"address": address}, None),
        ("rest_v0",    "GET",  "https://api.chainabuse.com/v0/reports",    {"address": address}, None),
    ]

    last_status = None
    async with httpx.AsyncClient() as client:
        for (name, method, url, params, json_body) in endpoints:
            try:
                if method == "POST":
                    resp = await client.post(url, headers=headers, json=json_body, timeout=TIMEOUT)
                else:
                    resp = await client.get(url, headers=headers, params=params, timeout=TIMEOUT)

                last_status = resp.status_code

                if resp.status_code == 401:
                    return {"status": "auth_error", "note": "Chainabuse key invalid or expired"}
                if resp.status_code == 429:
                    return {"status": "rate_limited"}
                if resp.status_code == 404:
                    log.debug(f"[Chainabuse] {name} → 404, trying next endpoint")
                    continue   # Try next endpoint
                if resp.status_code != 200:
                    log.debug(f"[Chainabuse] {name} → {resp.status_code}")
                    continue

                # Parse response ──────────────────────────────
                body = resp.json()

                # GraphQL response shape
                if "data" in body:
                    reports_obj = (body.get("data", {}).get("reports") or {})
                    # Handle different GraphQL schema versions
                    total   = (reports_obj.get("totalCount") or
                                reports_obj.get("total") or 0)
                    edges   = (reports_obj.get("edges") or [])
                    reports = [e.get("node", e) for e in edges]
                elif "errors" in body:
                    errs = [e.get("message", "") for e in body["errors"]]
                    log.warning(f"[Chainabuse] GraphQL errors: {errs}")
                    continue

                # REST response shape
                elif isinstance(body, list):
                    reports = body
                    total   = len(body)
                elif "results" in body:
                    reports = body["results"]
                    total   = body.get("count", len(reports))
                else:
                    reports = []
                    total   = 0

                if total == 0 and not reports:
                    log.info(f"[Chainabuse] {address[:20]}... → no reports (via {name})")
                    return {
                        "status": "ok", "source": f"chainabuse/{name}",
                        "total": 0, "is_flagged": False,
                        "categories": [], "risk_level": "Safe", "flags": [],
                    }

                categories = list({r.get("category", "unknown")
                                   for r in reports if r.get("category")})
                recent = [
                    {"id": r.get("id"), "category": r.get("category"),
                     "description": (r.get("description") or "")[:200],
                     "date": r.get("createdAt") or r.get("created_at")}
                    for r in reports[:5]
                ]

                flags = [f"Chainabuse: {total} scam report(s) — {', '.join(categories)}"]
                risk_level = "Critical" if total >= 3 else "High"

                log.info(f"[Chainabuse] {address[:20]}... → total={total} "
                         f"categories={categories} via={name}")
                return {
                    "status": "ok", "source": f"chainabuse/{name}",
                    "total": total, "is_flagged": True,
                    "categories": categories, "recent_reports": recent,
                    "risk_level": risk_level, "flags": flags,
                }

            except httpx.TimeoutException:
                log.warning(f"[Chainabuse] {name} timed out")
                continue
            except Exception as e:
                log.warning(f"[Chainabuse] {name} error: {e}")
                continue

    # All endpoints failed
    log.warning(f"[Chainabuse] All endpoints failed. Last HTTP status: {last_status}")
    return {
        "status":    "api_error",
        "note":      f"All Chainabuse endpoints returned errors (last HTTP {last_status}). "
                     f"Check CHAINABUSE_KEY and https://www.chainabuse.com/api",
        "attempted": [e[0] for e in endpoints],
    }


# ═══════════════════════════════════════════════════════════════
# 6. Blockchain.com — BTC Transaction History (Free, No Key)
# ═══════════════════════════════════════════════════════════════

async def blockchain_com_check(address: str) -> dict:
    """Fetch Bitcoin transaction history from Blockchain.com public API."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://blockchain.info/rawaddr/{address}",
                params={"limit": 5},
                headers={"User-Agent": "Aegis-QR-Scanner/5.2"},
                timeout=TIMEOUT,
            )

        if resp.status_code == 404:
            return {"status": "not_found", "transaction_count": 0,
                    "note": "Address not yet on blockchain"}
        if resp.status_code != 200:
            return {"status": "api_error", "http_code": resp.status_code}

        data = resp.json()
        return {
            "status":             "ok",
            "total_received_btc": round(data.get("total_received", 0) / 1e8, 8),
            "total_sent_btc":     round(data.get("total_sent",     0) / 1e8, 8),
            "balance_btc":        round(data.get("final_balance",  0) / 1e8, 8),
            "transaction_count":  data.get("n_tx", 0),
        }

    except httpx.TimeoutException:
        return {"status": "timeout", "note": "Blockchain.com timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════════
# 7. Crypto Address — Combined Check
# ═══════════════════════════════════════════════════════════════

async def crypto_address_check(address: str, coin: str = "bitcoin") -> dict:
    """Chainabuse + Blockchain.com + address format validation."""
    coin   = coin.lower()
    result = {
        "status":          "ok",
        "source":          "crypto_intelligence",
        "address":         address,
        "coin":            coin,
        "is_flagged":      False,
        "abuse_reports":   0,
        "blockchain_data": {},
        "risk_level":      "Safe",
        "flags":           [],
        "explorer_urls":   _get_explorer_urls(address, coin),
    }

    # Format validation
    validation = _validate_crypto_address(address, coin)
    result["address_format_valid"] = validation["valid"]
    if not validation["valid"]:
        result["flags"].append(f"CRYPTO: {validation['reason']}")

    # Run Chainabuse + Blockchain.com concurrently
    ca_coro = chainabuse_check(address)
    bc_coro = blockchain_com_check(address) if coin == "bitcoin" else _skipped("Not Bitcoin")

    ca_result, bc_result = await asyncio.gather(ca_coro, bc_coro, return_exceptions=True)

    # Process Chainabuse
    if isinstance(ca_result, dict):
        result["chainabuse"] = ca_result
        if ca_result.get("is_flagged"):
            result["is_flagged"]    = True
            result["abuse_reports"] = ca_result.get("total", 0)
            result["flags"].extend(ca_result.get("flags", []))
    else:
        result["chainabuse"] = {"status": "error", "error": str(ca_result)}

    # Process Blockchain.com — always store even if no transactions
    if isinstance(bc_result, dict):
        result["blockchain_data"] = bc_result
        bc_status = bc_result.get("status", "")
        if bc_status == "ok":
            tx       = bc_result.get("transaction_count", 0)
            received = bc_result.get("total_received_btc", 0.0)
            if tx > 0:
                result["flags"].append(
                    f"Blockchain.com: {tx} tx(s) found, "
                    f"{received:.6f} BTC received historically"
                )
            else:
                result["flags"].append(
                    "Blockchain.com: Wallet has NO transaction history — "
                    "may be freshly generated for this scam"
                )
        elif bc_status == "not_found":
            result["flags"].append(
                "Blockchain.com: Address not on blockchain yet (zero transactions)"
            )

    # Final risk
    result["risk_level"] = ("Critical" if result["is_flagged"] else
                             "High"    if not validation["valid"] else "Safe")
    result["warning"] = (
        "⚠️ Crypto transactions are IRREVERSIBLE. "
        "Verify this address independently before sending funds."
    )

    log.info(f"[Crypto] {coin}:{address[:20]}... "
             f"flagged={result['is_flagged']} risk={result['risk_level']}")
    return result


def _validate_crypto_address(address: str, coin: str) -> dict:
    if not address:
        return {"valid": False, "reason": "Empty wallet address"}
    patterns = {
        "bitcoin":  [r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", r"^bc1[a-z0-9]{39,59}$"],
        "ethereum": [r"^0x[a-fA-F0-9]{40}$"],
        "litecoin": [r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$", r"^ltc1[a-z0-9]{39,59}$"],
        "monero":   [r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$"],
    }
    coin_patterns = patterns.get(coin, [])
    if not coin_patterns:
        return {"valid": True, "reason": f"No pattern for {coin}"}
    for pattern in coin_patterns:
        if re.match(pattern, address):
            return {"valid": True, "reason": "Valid format"}
    return {"valid": False,
            "reason": f"Does not match {coin} address patterns — possible substitution attack"}


def _get_explorer_urls(address: str, coin: str) -> dict:
    explorers = {
        "bitcoin":  {"blockchain.com": f"https://www.blockchain.com/explorer/addresses/btc/{address}",
                     "blockchair":     f"https://blockchair.com/bitcoin/address/{address}",
                     "chainabuse":     f"https://www.chainabuse.com/address/{address}"},
        "ethereum": {"etherscan":  f"https://etherscan.io/address/{address}",
                     "blockchair": f"https://blockchair.com/ethereum/address/{address}",
                     "chainabuse": f"https://www.chainabuse.com/address/{address}"},
        "litecoin": {"blockchair": f"https://blockchair.com/litecoin/address/{address}",
                     "chainabuse": f"https://www.chainabuse.com/address/{address}"},
        "monero":   {"xmrchain":   f"https://xmrchain.net/search?value={address}",
                     "chainabuse": f"https://www.chainabuse.com/address/{address}"},
    }
    return explorers.get(coin, {})


# ═══════════════════════════════════════════════════════════════
# 8. Orchestrated Enrichment (called from main.py)
# ═══════════════════════════════════════════════════════════════

async def enrich_url(url: str) -> dict:
    """
    URL enrichment — Google Safe Browsing + AbuseIPDB (if IP-based).
    Note: URLHaus is intentionally EXCLUDED here because the Link Analyzer
    already runs URLHaus internally and includes it in url_deep_scans[].urlhaus.
    Calling it here caused 401 errors and duplicated data.
    """
    gsb_coro = gsb_check_url(url)
    ip       = _extract_ip_from_url(url)
    adb_coro = abuseipdb_check(ip) if ip else _skipped("Not an IP-based URL")

    gsb, adb = await asyncio.gather(gsb_coro, adb_coro, return_exceptions=True)

    def _safe(r): return r if isinstance(r, dict) else {"status": "error", "error": str(r)}
    gsb = _safe(gsb)
    adb = _safe(adb)

    return {
        "google_safe_browsing":  gsb,
        "abuseipdb":             adb,
        "enrichment_risk_level": _max_risk([gsb.get("risk_level", "Safe"),
                                            adb.get("risk_level", "Safe")]),
        "all_enrichment_flags":  _collect_flags(gsb, adb),
        "note": "URLHaus result available in url_deep_scans[].urlhaus (provided by Link Analyzer)",
    }


async def enrich_email(email: str) -> dict:
    """Email enrichment — EmailRep.io (replaces HIBP). Free, no key needed."""
    erep = await emailrep_check(email)
    return {
        "emailrep":              erep,
        "enrichment_risk_level": erep.get("risk_level", "Safe"),
        "all_enrichment_flags":  erep.get("flags", []),
    }


async def enrich_phone(phone: str) -> dict:
    """Phone enrichment — NumVerify (existing key from Phase 1)."""
    nv = await numverify_check(phone)
    return {
        "numverify":             nv,
        "enrichment_risk_level": nv.get("risk_level", "Safe"),
        "all_enrichment_flags":  nv.get("flags", []),
    }


async def enrich_crypto(address: str, coin: str) -> dict:
    """Crypto enrichment — Chainabuse + Blockchain.com + format validation."""
    result = await crypto_address_check(address, coin)
    return {
        "crypto_check":          result,
        "enrichment_risk_level": result.get("risk_level", "Safe"),
        "all_enrichment_flags":  result.get("flags", []),
    }


async def enrich_vcard(parsed_vcard: dict) -> dict:
    """vCard enrichment — all URLs, emails, phones checked concurrently."""
    urls   = parsed_vcard.get("urls",   [])
    phones = parsed_vcard.get("phones", [])
    emails = parsed_vcard.get("emails", [])

    url_t   = [enrich_url(u)   for u in urls   if u]
    phone_t = [enrich_phone(p) for p in phones if p]
    email_t = [enrich_email(e) for e in emails if e]

    all_tasks = url_t + phone_t + email_t
    if not all_tasks:
        return {"status": "no_enrichable_fields", "enrichment_risk_level": "Safe",
                "all_enrichment_flags": []}

    all_results = await asyncio.gather(*all_tasks, return_exceptions=True)
    nu, np = len(url_t), len(phone_t)

    url_r   = [r if isinstance(r, dict) else {"status": "error"} for r in all_results[:nu]]
    phone_r = [r if isinstance(r, dict) else {"status": "error"} for r in all_results[nu:nu+np]]
    email_r = [r if isinstance(r, dict) else {"status": "error"} for r in all_results[nu+np:]]

    all_risks, all_flags = [], []
    for r in url_r + phone_r + email_r:
        if isinstance(r, dict):
            all_risks.append(r.get("enrichment_risk_level", "Safe"))
            all_flags.extend(r.get("all_enrichment_flags", []))

    return {
        "url_enrichments":       url_r,
        "phone_enrichments":     phone_r,
        "email_enrichments":     email_r,
        "enrichment_risk_level": _max_risk(all_risks),
        "all_enrichment_flags":  all_flags,
    }
