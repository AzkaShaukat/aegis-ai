"""
Aegis AI — Full-Stack Credential & Identity Risk Analyzer
Version 4.0.0 | FastAPI | Async | Redis-cached
"""
import hashlib, json, logging, time, uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

# Tier 1
from app.analyzers.email        import analyze_email
from app.analyzers.password     import analyze_password
from app.analyzers.username     import analyze_username
# Tier 2
from app.analyzers.card         import analyze_card
from app.analyzers.iban         import analyze_iban
from app.analyzers.crypto       import analyze_crypto
from app.analyzers.social_media import analyze_social_media
# Tier 3
from app.analyzers.national_id  import analyze_national_id
from app.analyzers.passport     import analyze_passport
from app.analyzers.phone        import analyze_phone
# Tier 4
from app.analyzers.api_key      import analyze_api_key
# Tier 5
from app.analyzers.phone_advanced import analyze_phone_advanced
# Infrastructure
from app.config      import settings
from app.redis_client import cache_get, cache_set, redis_status

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
                    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger(__name__)

# ══ Request Models ════════════════════════════════════════════════════════════
class CredentialIn(BaseModel):
    value:    str = Field(..., min_length=1, max_length=512)
    email:    str = Field("", max_length=320)
    username: str = Field("", max_length=128)

class CardIn(BaseModel):
    number:       str = Field(..., min_length=12, max_length=23)
    expiry_month: str = Field("", max_length=2)
    expiry_year:  str = Field("", max_length=4)
    cvv:          str = Field("", max_length=4)

class IbanIn(BaseModel):
    iban:  str = Field(..., min_length=5, max_length=34)
    swift: str = Field("", max_length=11)

class SocialIn(BaseModel):
    username: str = Field("", max_length=128)
    email:    str = Field("", max_length=320)
    phone:    str = Field("", max_length=20)
    platform: str = Field("", max_length=32)

class NationalIdIn(BaseModel):
    value:   str = Field(..., min_length=5, max_length=20)
    id_type: str = Field("auto")

class PassportIn(BaseModel):
    mrz_line1:       str = Field("", max_length=44)
    mrz_line2:       str = Field("", max_length=44)
    mrz_line3:       str = Field("", max_length=30)
    raw_mrz:         str = Field("", max_length=200)
    doc_number:      str = Field("", max_length=20)
    issuing_country: str = Field("", max_length=10)

class PhoneIn(BaseModel):
    value: str = Field(..., min_length=3, max_length=25)

class PhoneAdvancedIn(BaseModel):
    value:     str = Field(..., min_length=3, max_length=25)
    sms_body:  str = Field("", max_length=2000)
    carrier:   str = Field("", max_length=50)
    line_type: str = Field("", max_length=20)

class ApiKeyIn(BaseModel):
    value: str = Field(..., min_length=4, max_length=4096)

class BulkItem(BaseModel):
    type:  str  = Field(...)
    value: str  = Field(..., min_length=1, max_length=512)
    extra: dict = Field(default_factory=dict)

class BulkIn(BaseModel):
    items: list[BulkItem] = Field(..., min_length=1, max_length=50)

class ScanIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)


# ══ Lifespan ══════════════════════════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Aegis v4.0.0 — Tiers 1–5 ready on :8003")
    yield
    logger.info("Aegis shutting down")

# ══ App ═══════════════════════════════════════════════════════════════════════
app = FastAPI(
    title="Aegis AI — Credential & Identity Risk Analyzer",
    description=(
        "## Full-Stack Credential Risk Analysis — Tiers 1–5\n\n"
        "**Tier 1** Email · Password · Username\n\n"
        "**Tier 2** Card · IBAN · Crypto · Social Media\n\n"
        "**Tier 3** CNIC/SSN/Aadhaar · Passport MRZ · Phone\n\n"
        "**Tier 4** API Keys & Tokens (AWS, GitHub, Stripe, OpenAI, 40+ services)\n\n"
        "**Tier 5** OTP/SIM-swap · Smishing · 2FA Rating · IPQS Fraud Score\n\n"
        "**Production** Rate limiting · Correlation IDs · Bulk · Scanner · Metrics · GDPR"
    ),
    version="4.0.0",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"],
                   expose_headers=["X-Request-ID", "X-Rate-Limit-Remaining", "X-Response-Time-Ms"])


# ══ Middleware ════════════════════════════════════════════════════════════════
@app.middleware("http")
async def request_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
    t0 = time.perf_counter()

    # Redis rate limiting
    if settings.RATE_LIMIT_PER_MIN > 0 and request.url.path not in ("/health", "/metrics"):
        client_ip = (request.client.host if request.client else "unknown")
        rate_key = f"ratelimit:{client_ip}:{int(time.time()//60)}"
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            count = await r.incr(rate_key)
            if count == 1: await r.expire(rate_key, 60)
            await r.aclose()
            if count > settings.RATE_LIMIT_PER_MIN:
                return JSONResponse(status_code=429, headers={"X-Request-ID": req_id},
                    content={"error": "Rate limit exceeded",
                             "limit_per_min": settings.RATE_LIMIT_PER_MIN,
                             "retry_after_seconds": 60 - int(time.time() % 60)})
        except Exception:
            pass

    # Optional bearer-key auth
    if settings.AEGIS_API_KEY:
        skip = {"/health", "/metrics", "/docs", "/redoc", "/openapi.json"}
        if request.url.path not in skip:
            provided = request.headers.get("X-API-Key", "")
            if not provided:
                return JSONResponse(status_code=401, headers={"X-Request-ID": req_id},
                    content={"error": "X-API-Key header required"})
            if provided != settings.AEGIS_API_KEY:
                return JSONResponse(status_code=403, headers={"X-Request-ID": req_id},
                    content={"error": "Invalid API key"})

    response = await call_next(request)
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Response-Time-Ms"] = str(elapsed)
    return response


# ══ Helpers ═══════════════════════════════════════════════════════════════════
def _timed(r: dict, t0: float) -> dict:
    r["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1); return r

async def _webhook(result: dict):
    if not settings.WEBHOOK_URL: return
    score = result.get("overall_risk_score", 0)
    if score < settings.WEBHOOK_MIN_RISK: return
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(settings.WEBHOOK_URL, json={
                "event": "high_risk_credential",
                "risk_score": score,
                "risk_level": result.get("overall_risk_level"),
                "credential_type": result.get("credential_type"),
                "flags": result.get("all_flags", [])[:5],
                "timestamp": int(time.time()),
            })
    except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "healthy", "version": "4.0.0",
        "redis": await redis_status(),
        "tiers": {
            "tier1": {"name": "Identity Credentials",
                      "endpoints": ["/analyze/email","/analyze/password","/analyze/username"]},
            "tier2": {"name": "Financial Credentials",
                      "endpoints": ["/analyze/card","/analyze/iban","/analyze/crypto","/analyze/social"]},
            "tier3": {"name": "Identity Documents",
                      "endpoints": ["/analyze/national-id","/analyze/passport","/analyze/phone"]},
            "tier4": {"name": "API Keys & Tokens",
                      "endpoints": ["/analyze/api-key"]},
            "tier5": {"name": "Advanced Phone Security",
                      "endpoints": ["/analyze/phone/advanced"]},
        },
        "apis_configured": {
            "hibp":         bool(settings.HIBP_API_KEY),
            "dehashed":     bool(settings.DEHASHED_API_KEY),
            "hunter":       bool(settings.HUNTER_API_KEY),
            "whoisxml":     bool(settings.WHOISXML_API_KEY),
            "numverify":    bool(settings.NUMVERIFY_API_KEY),
            "abstract_api": bool(settings.ABSTRACT_API_KEY),
            "ipqs":         bool(settings.IPQS_API_KEY),
            "leakcheck":    bool(settings.LEAKCHECK_API_KEY),
        },
        "features": {
            "rate_limiting": settings.RATE_LIMIT_PER_MIN > 0,
            "api_key_auth":  bool(settings.AEGIS_API_KEY),
            "webhook_alerts":bool(settings.WEBHOOK_URL),
            "bulk_analysis": True,
            "text_scanner":  True,
            "metrics":       True,
            "gdpr_purge":    True,
        },
        "timestamp": int(time.time()),
    }


@app.get("/metrics", tags=["System"], response_class=PlainTextResponse)
async def metrics():
    """Prometheus-compatible text format. Add to prometheus.yml as scrape target."""
    configured_apis = sum([bool(settings.HIBP_API_KEY), bool(settings.DEHASHED_API_KEY),
        bool(settings.HUNTER_API_KEY), bool(settings.WHOISXML_API_KEY),
        bool(settings.NUMVERIFY_API_KEY), bool(settings.ABSTRACT_API_KEY),
        bool(settings.IPQS_API_KEY), bool(settings.LEAKCHECK_API_KEY)])
    return "\n".join([
        '# HELP aegis_info Aegis service info',
        '# TYPE aegis_info gauge',
        'aegis_info{version="4.0.0",tiers="5"} 1',
        '# HELP aegis_apis_configured External APIs configured',
        '# TYPE aegis_apis_configured gauge',
        f'aegis_apis_configured {configured_apis}',
        '# HELP aegis_rate_limit Requests per minute limit (0=disabled)',
        '# TYPE aegis_rate_limit gauge',
        f'aegis_rate_limit {settings.RATE_LIMIT_PER_MIN}',
    ])


@app.get("/cache/stats", tags=["System"])
async def cache_stats():
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        mem = await r.info("memory"); ks = await r.info("keyspace")
        await r.aclose()
        return {"status": "connected", "used_memory": mem.get("used_memory_human"),
                "keyspace": ks}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.delete("/cache/purge", tags=["System"])
async def cache_purge(confirm: str = ""):
    """GDPR right-to-erasure: flush all cached credential analysis results."""
    if confirm.lower() != "yes":
        raise HTTPException(400, "Pass ?confirm=yes to flush the cache")
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await r.flushdb(); await r.aclose()
        return {"status": "ok", "message": "All cached analysis data flushed",
                "gdpr_note": "Redis cache cleared — no analysis results retained in memory"}
    except Exception as e:
        raise HTTPException(500, f"Cache flush failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/detect", tags=["Utilities"])
async def detect_credential_type(body: CredentialIn):
    """Auto-identify the most likely credential type without full analysis."""
    import re
    v = body.value.strip()
    suggestions = []
    rules = [
        ("email",       "High",   re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
        ("phone",       "High",   re.compile(r"^\+?[0-9\s\-\(\)]{7,20}$")),
        ("cnic",        "High",   re.compile(r"^\d{5}-?\d{7}-?\d$")),
        ("ssn",         "High",   re.compile(r"^\d{3}-?\d{2}-?\d{4}$")),
        ("aadhaar",     "High",   re.compile(r"^\d{12}$")),
        ("iban",        "High",   re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")),
        ("bitcoin",     "High",   re.compile(r"^(bc1|[13])[A-Za-z0-9]{24,62}$")),
        ("ethereum",    "High",   re.compile(r"^0x[0-9a-fA-F]{40}$")),
        ("jwt",         "High",   re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")),
        ("aws_key",     "High",   re.compile(r"^AKIA[0-9A-Z]{16}$")),
        ("github_pat",  "High",   re.compile(r"^gh[pors]_[A-Za-z0-9]{36}$")),
        ("stripe_key",  "High",   re.compile(r"^(sk|pk|rk)_(live|test)_[A-Za-z0-9]{24,}")),
        ("credit_card", "High",   re.compile(r"^[\d\s\-]{13,19}$")),
        ("passport_mrz","Medium", re.compile(r"^P<[A-Z]{3}")),
        ("api_key",     "Low",    re.compile(r"^[A-Za-z0-9_\-]{20,}$")),
        ("password",    "Low",    re.compile(r"^.{6,}$")),
    ]
    for name, conf, pat in rules:
        if pat.match(v):
            suggestions.append({"type": name, "confidence": conf})
    if not suggestions:
        suggestions.append({"type": "unknown", "confidence": "None"})
    return {"input_length": len(v), "suggestions": suggestions[:5],
            "primary_suggestion": suggestions[0]["type"],
            "note": "Use /analyze/{type} for full analysis"}


@app.post("/scan", tags=["Utilities"])
async def scan_text(body: ScanIn):
    """Scan free-form text (logs, code, config files) for embedded credentials."""
    import re
    text = body.text
    findings = []
    PATTERNS = [
        ("AWS Access Key",    "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("GitHub PAT",        "high",     re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
        ("GitHub Fine-Grained","high",    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
        ("Stripe Live Key",   "critical", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
        ("Stripe Test Key",   "low",      re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b")),
        ("OpenAI Key",        "high",     re.compile(r"\bsk-[A-Za-z0-9]{48}\b")),
        ("Anthropic Key",     "high",     re.compile(r"\bsk-ant-api[0-9]+-[A-Za-z0-9_\-]{90,}\b")),
        ("SendGrid Key",      "high",     re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
        ("Slack Bot Token",   "high",     re.compile(r"\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b")),
        ("JWT Token",         "medium",   re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
        ("GCP API Key",       "high",     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
        ("Telegram Bot",      "medium",   re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
        ("DigitalOcean Token","high",     re.compile(r"\bdop_v1_[a-f0-9]{64}\b")),
        ("GitLab Token",      "high",     re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
        ("Discord Bot Token", "high",     re.compile(r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}\b")),
        ("Email Address",     "info",     re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")),
        ("Pakistani CNIC",    "high",     re.compile(r"\b\d{5}-\d{7}-\d\b")),
        ("US SSN",            "critical", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
        ("IBAN",              "high",     re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
        ("Visa/MC Card",      "critical", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b")),
        ("Bitcoin Address",   "medium",   re.compile(r"\b(bc1|[13])[A-Za-z0-9]{24,62}\b")),
        ("Ethereum Address",  "medium",   re.compile(r"\b0x[0-9a-fA-F]{40}\b")),
        ("MongoDB URI",       "critical", re.compile(r"mongodb(\+srv)?://[^\s\"'<>]+")),
        ("PostgreSQL URI",    "critical", re.compile(r"postgres(ql)?://[^\s\"'<>]+")),
        ("MySQL URI",         "critical", re.compile(r"mysql://[^\s\"'<>]+")),
        ("Private Key",       "critical", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
    ]
    for label, severity, pattern in PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(0)
            masked = raw[:4] + "*"*max(0, len(raw)-8) + raw[-4:] if len(raw) > 8 else "****"
            findings.append({"type": label, "severity": severity, "position": m.start(),
                              "length": len(raw), "masked_value": masked,
                              "line_number": text[:m.start()].count("\n") + 1})
    sord = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    findings.sort(key=lambda x: sord.get(x["severity"], 5))
    crit = sum(1 for f in findings if f["severity"]=="critical")
    high = sum(1 for f in findings if f["severity"]=="high")
    return {
        "total_findings": len(findings), "critical": crit, "high": high,
        "findings": findings[:100],
        "risk_level": "Critical" if crit else "High" if high else "Medium" if findings else "Clean",
        "recommendation": (
            "Rotate all detected secrets immediately. Use git-secrets or GitGuardian pre-commit hooks."
            if (crit+high) > 0 else "No high-severity credentials found."
        ),
    }


@app.post("/analyze/bulk", tags=["Utilities"])
async def bulk_analyze(body: BulkIn):
    """Analyze up to 50 credentials in a single request."""
    import asyncio
    async def _one(item: BulkItem) -> dict:
        t0 = time.perf_counter()
        try:
            t = item.type.lower().replace("-","_")
            if   t == "email":       r = await analyze_email(item.value)
            elif t == "password":    r = await analyze_password(item.value)
            elif t == "username":    r = await analyze_username(item.value)
            elif t in ("phone","phone_number"): r = await analyze_phone(item.value)
            elif t in ("api_key","token","secret"): r = await analyze_api_key(item.value)
            elif t == "card":
                ex = item.extra
                r = await analyze_card(item.value, ex.get("expiry_month",""),
                                       ex.get("expiry_year",""), ex.get("cvv",""))
            elif t == "iban":    r = await analyze_iban(item.value, item.extra.get("swift",""))
            elif t in ("crypto","wallet"): r = await analyze_crypto(item.value)
            elif t in ("national_id","cnic","ssn","aadhaar"):
                r = await analyze_national_id(item.value, t if t!="national_id" else "auto")
            else:
                r = {"error": f"Unknown type '{item.type}'",
                     "supported": ["email","password","username","phone","api_key",
                                   "card","iban","crypto","national_id"]}
            r["elapsed_ms"] = round((time.perf_counter()-t0)*1000,1)
            return {"input_type": item.type, "result": r}
        except Exception as e:
            return {"input_type": item.type, "error": str(e)[:200]}

    results = await asyncio.gather(*[_one(item) for item in body.items])
    scores = [r["result"].get("overall_risk_score",0) for r in results if "result" in r]
    return {
        "total": len(results), "results": list(results),
        "summary": {
            "max_risk_score":  max(scores) if scores else 0,
            "avg_risk_score":  round(sum(scores)/len(scores),1) if scores else 0,
            "critical_count":  sum(1 for s in scores if s>=76),
            "high_count":      sum(1 for s in scores if 56<=s<76),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# TIER 1 — Identity Credentials
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/analyze/email",    tags=["Tier 1 — Email"])
async def route_email(body: CredentialIn):
    t0=time.perf_counter(); r=await analyze_email(body.value)
    await _webhook(r); return _timed(r,t0)

@app.post("/analyze/password", tags=["Tier 1 — Password"])
async def route_password(body: CredentialIn):
    t0=time.perf_counter(); r=await analyze_password(body.value,body.email,body.username)
    return _timed(r,t0)

@app.post("/analyze/username", tags=["Tier 1 — Username"])
async def route_username(body: CredentialIn):
    t0=time.perf_counter(); r=await analyze_username(body.value)
    return _timed(r,t0)

@app.get("/analyze/email/{email:path}",   tags=["Tier 1 — Email"])
async def get_email(email: str): return await analyze_email(email)

@app.get("/analyze/username/{username}",  tags=["Tier 1 — Username"])
async def get_username(username: str): return await analyze_username(username)


# ══════════════════════════════════════════════════════════════════════════════
# TIER 2 — Financial Credentials
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/analyze/card",   tags=["Tier 2 — Card"])
async def route_card(body: CardIn):
    t0=time.perf_counter()
    r=await analyze_card(body.number,body.expiry_month,body.expiry_year,body.cvv)
    return _timed(r,t0)

@app.post("/analyze/iban",   tags=["Tier 2 — IBAN"])
async def route_iban(body: IbanIn):
    t0=time.perf_counter(); r=await analyze_iban(body.iban,body.swift); return _timed(r,t0)

@app.post("/analyze/crypto", tags=["Tier 2 — Crypto"])
async def route_crypto(body: CredentialIn):
    t0=time.perf_counter(); r=await analyze_crypto(body.value); return _timed(r,t0)

@app.post("/analyze/social", tags=["Tier 2 — Social Media"])
async def route_social(body: SocialIn):
    t0=time.perf_counter()
    r=await analyze_social_media(username=body.username,email=body.email,
                                  phone=body.phone,platform=body.platform)
    return _timed(r,t0)

@app.get("/analyze/crypto/{address}", tags=["Tier 2 — Crypto"])
async def get_crypto(address: str): return await analyze_crypto(address)


# ══════════════════════════════════════════════════════════════════════════════
# TIER 3 — Identity Documents
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/analyze/national-id", tags=["Tier 3 — National ID"])
async def route_national_id(body: NationalIdIn):
    t0=time.perf_counter(); r=await analyze_national_id(body.value, body.id_type)
    await _webhook(r); return _timed(r,t0)

@app.post("/analyze/passport", tags=["Tier 3 — Passport"])
async def route_passport(body: PassportIn):
    t0=time.perf_counter()
    r=await analyze_passport(mrz_line1=body.mrz_line1, mrz_line2=body.mrz_line2,
        mrz_line3=body.mrz_line3, raw_mrz=body.raw_mrz,
        doc_number=body.doc_number, issuing_country=body.issuing_country)
    await _webhook(r); return _timed(r,t0)

@app.post("/analyze/phone", tags=["Tier 3 — Phone"])
async def route_phone(body: PhoneIn):
    t0=time.perf_counter(); r=await analyze_phone(body.value); return _timed(r,t0)

@app.get("/analyze/phone/{phone:path}", tags=["Tier 3 — Phone"])
async def get_phone(phone: str): return await analyze_phone(phone)


# ══════════════════════════════════════════════════════════════════════════════
# TIER 4 — API Keys & Tokens
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/analyze/api-key", tags=["Tier 4 — API Keys"],
          summary="Service detection · entropy · scope · JWT decode · GitGuardian-style")
async def route_api_key(body: ApiKeyIn):
    t0=time.perf_counter(); r=await analyze_api_key(body.value)
    await _webhook(r); return _timed(r,t0)

@app.get("/analyze/api-key/{key:path}", tags=["Tier 4 — API Keys"])
async def get_api_key(key: str): return await analyze_api_key(key)


# ══════════════════════════════════════════════════════════════════════════════
# TIER 5 — Advanced Phone Security
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/analyze/phone/advanced", tags=["Tier 5 — Advanced Phone"],
          summary="OTP bypass · SIM swap · Smishing · 2FA rating · IPQS fraud score")
async def route_phone_advanced(body: PhoneAdvancedIn):
    t0=time.perf_counter()
    r=await analyze_phone_advanced(phone=body.value, sms_body=body.sms_body,
                                    carrier=body.carrier, line_type=body.line_type)
    return _timed(r,t0)
