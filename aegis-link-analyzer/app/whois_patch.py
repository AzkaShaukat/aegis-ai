"""
whois_patch.py
Patch to apply to whois_check.py

The WHOIS error flags currently include the entire VeriSign legal notice
(200+ lines of boilerplate). This shows up in all_flags and the scan response.

Apply this fix inside run_whois_check() wherever WHOIS failure flags are built.
Replace any flag-building that includes raw WHOIS exception/response text with
the _clean_whois_error() function below.
"""


def _clean_whois_error(raw_error: str, domain: str) -> str:
    """
    Extracts only the meaningful part of a WHOIS error message.
    Strips away VeriSign/IANA legal boilerplate that appears in raw WHOIS responses.
    
    Before: "WHOIS lookup failed (No match for "EXAMPLE.COM".\n>>> Last update of whois 
             database: 2026-02-28T06:43:20Z <<<\n\nNOTICE: The expiration date displayed 
             in this record is the date the registrar's sponsorship... [200 more lines]"
    
    After: "Domain not found in WHOIS registry — unregistered or recently deleted"
    """
    raw = str(raw_error).strip()
    
    # Pattern 1: "No match for DOMAIN" → domain does not exist in registry
    if "No match for" in raw or "NOT FOUND" in raw.upper() or "no entries found" in raw.lower():
        return f"Domain '{domain}' not found in WHOIS registry — unregistered or recently deleted"
    
    # Pattern 2: "WHOIS lookup failed" with massive boilerplate
    if "NOTICE:" in raw or "VeriSign" in raw or "TERMS OF USE" in raw:
        # Extract just the first meaningful line
        first_line = raw.split("\n")[0].strip()
        # Remove the leading boilerplate if present
        for prefix in ["WHOIS lookup failed (", "WHOIS error: "]:
            if first_line.startswith(prefix):
                first_line = first_line[len(prefix):].rstrip(")")
        if len(first_line) > 120:
            first_line = first_line[:120] + "..."
        return f"WHOIS data unavailable — {first_line}"
    
    # Pattern 3: Connection timeout or network error
    if "timeout" in raw.lower() or "timed out" in raw.lower():
        return "WHOIS lookup timed out — registry may be rate-limiting requests"
    
    # Pattern 4: Rate limited
    if "rate limit" in raw.lower() or "too many" in raw.lower():
        return "WHOIS lookup rate-limited — try again in a few minutes"
    
    # Default: truncate to 150 chars
    if len(raw) > 150:
        return raw[:150].rstrip() + "..."
    return raw
