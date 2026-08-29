"""Central configuration — reads from .env automatically."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Tier 1 APIs ───────────────────────────────────────────────────────────
    HIBP_API_KEY:         str = ""   # haveibeenpwned.com — $3.50/mo
    DEHASHED_EMAIL:       str = ""   # dehashed.com — free account
    DEHASHED_API_KEY:     str = ""
    HUNTER_API_KEY:       str = ""   # hunter.io — email validation, free tier
    WHOISXML_API_KEY:     str = ""   # whoisxmlapi.com — domain age, free tier

    # ── Tier 2/3 APIs ─────────────────────────────────────────────────────────
    NUMVERIFY_API_KEY:    str = ""   # apilayer.net/numverify — 100/month free

    # ── Tier 3 Phone APIs ─────────────────────────────────────────────────────
    ABSTRACT_API_KEY:     str = ""   # abstractapi.com/phone — 100/month free
    VERIPHONE_API_KEY:    str = ""   # veriphone.io — 1000/month free, best carrier data

    # ── Tier 4 Exceptional API ────────────────────────────────────────────────
    # IPQualityScore — BEST phone fraud API (5000 req/month FREE)
    # https://www.ipqualityscore.com/user/register
    # Returns: fraud_score, VOIP, prepaid, active, risky, recent_abuse, carrier, line_type
    IPQS_API_KEY:         str = ""

    # LeakCheck — credential exposure API (free 10/day)
    # https://leakcheck.io/register
    LEAKCHECK_API_KEY:    str = ""

    # ── Microservice Config ───────────────────────────────────────────────────
    REDIS_URL:            str = "redis://redis_t1:6379/0"
    LOG_LEVEL:            str = "INFO"
    HTTP_TIMEOUT:         float = 12.0

    # Rate limiting — requests per minute per IP (0 = disabled)
    RATE_LIMIT_PER_MIN:   int = 60
    # Aegis API key for protecting this microservice (empty = no auth required)
    AEGIS_API_KEY:        str = ""
    # Webhook URL for critical-risk alerts (empty = disabled)
    WEBHOOK_URL:          str = ""
    WEBHOOK_MIN_RISK:     int = 76   # Only fire webhook for risk >= this score

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
