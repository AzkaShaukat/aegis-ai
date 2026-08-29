"""
schemas.py
Aegis Link Analyzer

Pydantic request/response models for all API endpoints.
URL validation automatically prepends https:// if no scheme is provided,
so users can submit bare domains like "google.com" or "www.google.com".
"""

from pydantic import BaseModel, field_validator
from typing import Dict, List, Optional, Any




# ─────────────────────────────────────────────────────────────────────────────
# REQUESTS
# ─────────────────────────────────────────────────────────────────────────────

class LinkRequest(BaseModel):
    url: str

    @field_validator("url", mode="before")
    @classmethod
    def normalize_url(cls, v: str) -> str:
        v = str(v).strip()
        if not v:
            raise ValueError("URL cannot be empty.")
        if not v.startswith("http://") and not v.startswith("https://"):
            v = "https://" + v
        return v

    model_config = {"json_schema_extra": {"example": {"url": "https://example.com"}}}


class BulkScanRequest(BaseModel):
    urls: List[str]

    @field_validator("urls", mode="before")
    @classmethod
    def normalize_urls(cls, v: list) -> list:
        result = []
        for url in v:
            url = str(url).strip()
            if url and not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url
            if url:
                result.append(url)
        if len(result) == 0:
            raise ValueError("At least 1 URL is required.")
        if len(result) > 10:
            raise ValueError("Maximum 10 URLs per bulk scan request.")
        return result

    model_config = {
        "json_schema_extra": {
            "example": {
                "urls": [
                    "https://google.com",
                    "https://github.com",
                    "http://suspicious-example.tk"
                ]
            }
        }
    }


class FeedbackRequest(BaseModel):
    scan_id: str
    url: str
    original_risk: str
    corrected_risk: str
    feedback_type: str
    user_note: Optional[str] = None
    confidence_score: Optional[float] = None
    total_flags: Optional[int] = None
    false_flags: Optional[List[str]] = []

    model_config = {
        "json_schema_extra": {
            "example": {
                "scan_id": "u-abc123...",
                "url": "https://example.com",
                "original_risk": "High Risk",
                "corrected_risk": "Safe",
                "feedback_type": "false_positive",
                "user_note": "This is a legitimate internal tool",
            }
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LAYER SUB-MODELS
# ─────────────────────────────────────────────────────────────────────────────

class HeuristicsResult(BaseModel):
    flags: List[str] = []
    flag_count: int = 0
    heuristic_score: float = 0.0
    entropy: float = 0.0
    checks_count: int = 0
    is_suspicious: bool = False


class WhoisResult(BaseModel):
    domain: Optional[str] = None
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    country: Optional[str] = None
    flags: List[str] = []
    whois_score: float = 0.0
    is_suspicious: bool = False


class DNSResult(BaseModel):
    hostname: Optional[str] = None
    flags: List[str] = []
    dns_score: float = 0.0
    details: Dict[str, Any] = {}
    is_suspicious: bool = False


class SSLResult(BaseModel):
    hostname: Optional[str] = None
    flags: List[str] = []
    ssl_score: float = 0.0
    details: Dict[str, Any] = {}
    is_suspicious: bool = False


class RedirectResult(BaseModel):
    original_url: Optional[str] = None
    final_url: Optional[str] = None
    hop_count: int = 0
    hops: List[Dict[str, Any]] = []
    shorteners_found: List[str] = []
    destination_changed: bool = False
    is_www_normalization: bool = False
    final_domain: Optional[str] = None
    flags: List[str] = []
    redirect_score: float = 0.0
    is_suspicious: bool = False


class URLhausResult(BaseModel):
    found: bool = False
    status: Optional[str] = None
    threat: Optional[str] = None
    tags: List[str] = []
    date_added: Optional[str] = None
    reporter: Optional[str] = None
    urlhaus_url: Optional[str] = None
    flags: List[str] = []
    urlhaus_score: float = 0.0
    is_suspicious: bool = False


class OpenPhishResult(BaseModel):
    found: bool = False
    match_type: Optional[str] = None
    matched_entry: Optional[str] = None
    feed_size: int = 0
    source: str = "openphish"
    flags: List[str] = []
    phishtank_score: float = 0.0
    is_suspicious: bool = False


class GSBResult(BaseModel):
    found: bool = False
    threats: List[Dict[str, Any]] = []
    flags: List[str] = []
    gsb_score: float = 0.0
    is_suspicious: bool = False
    api_available: bool = False


class MLPredictionResult(BaseModel):
    available: bool = False
    prediction: Optional[int] = None
    ml_risk_level: Optional[str] = None
    phishing_probability: Optional[float] = None
    safe_probability: Optional[float] = None
    top_features: List[Dict[str, Any]] = []
    model_type: Optional[str] = None
    model_version: Optional[str] = None
    trained_on: Optional[str] = None
    training_accuracy: Optional[float] = None
    features_used: Optional[int] = None
    error: Optional[str] = None


class ScoreBreakdown(BaseModel):
    heuristics: float = 0.0
    whois: float = 0.0
    dns: float = 0.0
    ssl: float = 0.0
    redirects: float = 0.0
    virustotal: float = 0.0
    urlhaus: float = 0.0
    phishtank: float = 0.0
    gsb: float = 0.0
    combined_final: float = 0.0
    critical_signals_triggered: int = 0
    critical_sources: List[str] = []


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCAN RESULT
# ─────────────────────────────────────────────────────────────────────────────

class ScanResult(BaseModel):
    url: str
    risk_level: str
    confidence_score: float
    message: str
    scan_date: str
    scan_id: Optional[str] = None

    detection_counts: Dict[str, int] = {}
    scanners_count: int = 0
    virustotal_report: Optional[str] = None
    report_url: Optional[str] = None
    screenshot_url: Optional[str] = None

    score_breakdown: Optional[ScoreBreakdown] = None
    ml_prediction: Optional[MLPredictionResult] = None

    heuristics: Optional[HeuristicsResult] = None
    whois: Optional[WhoisResult] = None
    dns: Optional[DNSResult] = None
    ssl: Optional[SSLResult] = None
    redirects: Optional[RedirectResult] = None

    urlhaus: Optional[URLhausResult] = None
    phishtank: Optional[OpenPhishResult] = None
    gsb: Optional[GSBResult] = None

    all_flags: List[str] = []
    total_flags: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# BULK SCAN
# ─────────────────────────────────────────────────────────────────────────────

class BulkScanResult(BaseModel):
    url: str
    status: str
    risk_level: Optional[str] = None
    confidence_score: Optional[float] = None
    message: Optional[str] = None
    total_flags: Optional[int] = None
    score_breakdown: Optional[ScoreBreakdown] = None
    error: Optional[str] = None


class BulkScanResponse(BaseModel):
    total_urls: int
    completed: int
    failed: int
    results: List[BulkScanResult]
    scan_duration_seconds: Optional[float] = None
    highest_risk_url: Optional[str] = None
    highest_risk_level: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC SCAN
# ─────────────────────────────────────────────────────────────────────────────

class AsyncScanResponse(BaseModel):
    job_id: str
    url: str
    status: str
    message: str
    poll_url: str
    created_at: str


class ScanJobStatus(BaseModel):
    job_id: str
    url: str
    status: str
    progress_message: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    elapsed_seconds: Optional[int] = None
    result: Optional[ScanResult] = None
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# FEEDBACK
# ─────────────────────────────────────────────────────────────────────────────

class FeedbackResponse(BaseModel):
    feedback_id: int
    status: str
    message: str
    submitted_at: str


class FeedbackStats(BaseModel):
    total_feedback: int
    breakdown_by_type: Dict[str, int] = {}
    false_positives: int = 0
    false_negatives: int = 0
    recent_feedback: List[Dict[str, Any]] = []
    training_ready: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# METRICS
# ─────────────────────────────────────────────────────────────────────────────

class ScanMetrics(BaseModel):
    summary: Dict[str, Any] = {}
    risk_distribution: Dict[str, Any] = {}
    threat_feed_hits: Dict[str, int] = {}
    ml_predictions: Dict[str, int] = {}
    daily_scans_last_7_days: Dict[str, int] = {}
    service_start: Optional[str] = None
    last_updated: Optional[str] = None
