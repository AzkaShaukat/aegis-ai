"""Aegis AI — All Pydantic request/response models (all 4 blocks unified)."""
from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────
class RiskLevel(str, Enum):
    CLEAN    = "clean"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class FraudType(str, Enum):
    IMPERSONATOR   = "impersonator"
    CATFISH        = "catfish"
    BOT            = "bot"
    SCAMMER        = "scammer"
    POLITICAL_BOT  = "political_bot"
    ROMANCE_SCAM   = "romance_scam"
    CRYPTO_SCAM    = "crypto_scam"
    ACCOUNT_SELLER = "account_seller"
    COORDINATED    = "coordinated_inauthentic"
    LEGITIMATE     = "legitimate"
    UNKNOWN        = "unknown"


def score_to_risk(s: int) -> RiskLevel:
    if s >= 70:   return RiskLevel.CRITICAL
    elif s >= 50: return RiskLevel.HIGH
    elif s >= 30: return RiskLevel.MEDIUM
    elif s >= 10: return RiskLevel.LOW
    return RiskLevel.CLEAN


# ── Base ──────────────────────────────────────────────────────────────────────
class BlockResult(BaseModel):
    suspicion_score: int       = 0
    risk_level:      RiskLevel = RiskLevel.CLEAN
    flags:           List[str] = []
    checks:          Dict[str, Any] = {}

    def finalize(self) -> "BlockResult":
        self.suspicion_score = min(self.suspicion_score, 100)
        self.risk_level = score_to_risk(self.suspicion_score)
        return self


# ══════════════════════════════════════════════════════════════════════════════
# BLOCK 1 — Identity & Profile Foundation
# ══════════════════════════════════════════════════════════════════════════════
class UsernameResult(BlockResult):
    username:             str
    entropy_score:        Optional[float] = None
    random_pattern:       bool = False
    leet_impersonation:   bool = False
    excessive_digits:     bool = False
    impersonates_brand:   Optional[str] = None
    platforms_found:      List[str] = []
    username_age_days:    Optional[int] = None


class PhotoResult(BlockResult):
    url:                  Optional[str] = None
    is_default_avatar:    bool = False
    face_detected:        Optional[bool] = None
    multiple_faces:       Optional[bool] = None
    is_ai_generated:      Optional[bool] = None
    ai_confidence:        Optional[int]  = None
    is_stock_photo:       Optional[bool] = None
    reverse_search_hits:  int  = 0
    phash:                Optional[str] = None


class AccountResult(BlockResult):
    account_age_days:     Optional[int]   = None
    followers:            Optional[int]   = None
    following:            Optional[int]   = None
    ff_ratio:             Optional[float] = None
    posts_count:          Optional[int]   = None
    posts_per_day:        Optional[float] = None
    bio_empty:            bool = False
    default_pic:          bool = False
    location_set:         bool = False
    link_set:             bool = False
    verified:             bool = False
    new_account_signal:   bool = False
    high_ff_ratio_signal: bool = False


class PhoneResult(BlockResult):
    phone:                Optional[str] = None
    valid:                bool = False
    carrier:              Optional[str] = None
    line_type:            Optional[str] = None
    country:              Optional[str] = None
    is_voip:              bool = False
    is_disposable:        bool = False
    ipqs_fraud_score:     Optional[int] = None
    recent_abuse:         bool = False


class EmailResult(BlockResult):
    email:                Optional[str] = None
    valid_format:         bool = False
    valid_mx:             bool = False
    is_disposable:        bool = False
    is_role_account:      bool = False
    is_free_provider:     bool = False
    domain_age_days:      Optional[int] = None
    ipqs_fraud_score:     Optional[int] = None
    leaked:               bool = False


# ══════════════════════════════════════════════════════════════════════════════
# BLOCK 2 — Content & Language Intelligence
# ══════════════════════════════════════════════════════════════════════════════
class BioResult(BlockResult):
    bio_length:           int  = 0
    scam_category_hits:   Dict[str, int] = {}
    has_suspicious_links: bool = False
    has_phone_in_bio:     bool = False
    emoji_density:        float = 0
    excessive_caps:       bool = False
    has_crypto_wallet:    bool = False
    pk_scam_hits:         Dict[str, int] = {}
    ollama_scam_score:    Optional[int]  = None
    ai_generated_bio:     Optional[bool] = None


class PostsResult(BlockResult):
    post_count:           int  = 0
    interval_cv:          Optional[float] = None
    bot_posting_pattern:  bool = False
    no_sleep_hours:       bool = False
    copy_paste_score:     Optional[float] = None
    hashtag_count:        int  = 0
    template_hits:        int  = 0
    repost_ratio:         Optional[float] = None
    scheduler_detected:   bool = False
    scheduler_apps:       List[str] = []
    engagement_bait:      bool = False
    ollama_scam_score:    Optional[int] = None


class LinkResult(BaseModel):
    url:                  str
    is_malicious:         Optional[bool] = None
    is_shortener:         bool = False
    final_url:            Optional[str]  = None
    domain_age_days:      Optional[int]  = None
    is_https:             bool = False
    is_lookalike:         bool = False
    lookalike_brand:      Optional[str]  = None
    is_phishing_path:     bool = False
    is_high_risk_service: bool = False
    vt_malicious:         int  = 0
    score:                int  = 0


class LinksResult(BlockResult):
    links_analyzed:       int = 0
    link_details:         List[LinkResult] = []
    malicious_count:      int = 0
    shortener_count:      int = 0
    lookalike_count:      int = 0


class LanguageResult(BlockResult):
    detected_scripts:     List[str] = []
    claimed_location:     Optional[str] = None
    script_mismatch:      bool = False
    multilang_farm:       bool = False
    inferred_timezone:    Optional[str] = None
    timezone_mismatch:    bool = False
    exif_country:         Optional[str] = None
    exif_mismatch:        bool = False
    per_post_languages:   List[str] = []


# ══════════════════════════════════════════════════════════════════════════════
# BLOCK 3 — Network & Social Intelligence
# ══════════════════════════════════════════════════════════════════════════════
class EngagementResult(BlockResult):
    engagement_rate:      Optional[float] = None
    purchased_followers:  bool = False
    bot_follower_pct:     Optional[float] = None
    spike_detected:       bool = False
    spike_day:            Optional[str]   = None
    spike_gain:           Optional[int]   = None
    ghost_follower_signal: bool = False
    follow_cycling:       bool = False
    mutual_ratio:         Optional[float] = None


class CrossPlatformResult(BlockResult):
    username:             str = ""
    platforms_found:      List[str] = []
    platforms_checked:    int = 0
    dark_web_mention:     bool = False
    dark_web_results:     List[str] = []
    sherlock_count:       int = 0
    bio_authority_claim:  bool = False
    socialblade_anomaly:  bool = False


class OsintResult(BlockResult):
    leakcheck_found:      bool = False
    leakcheck_count:      int  = 0
    hudsonrock_found:     bool = False
    breachdirectory_found: bool = False
    breachdirectory_count: int  = 0
    hibp_found:           bool = False
    hibp_breaches:        List[str] = []
    shodan_found:         bool = False
    shodan_vulns:         int  = 0
    greynoise_malicious:  bool = False
    greynoise_noise:      bool = False
    botometer_bot:        bool = False
    botometer_cap:        Optional[float] = None
    breach_summary:       str  = ""
    total_breach_sources: int  = 0
    queried_email:        Optional[str] = None
    queried_username:     Optional[str] = None
    queried_ip:           Optional[str] = None


class BehaviorResult(BlockResult):
    response_automated:   bool = False
    response_cv:          Optional[float] = None
    follow_cycling:       bool = False
    cib_detected:         bool = False
    cib_clusters:         int  = 0
    echo_chamber:         bool = False
    mention_density:      Optional[float] = None
    coordinated_hashtags: bool = False
    hashtag_jaccard:      Optional[float] = None
    scheduler_detected:   bool = False
    burst_detected:       bool = False
    action_rate_anomaly:  bool = False
    actions_per_hour:     Optional[float] = None


# ══════════════════════════════════════════════════════════════════════════════
# BLOCK 4 — AI/ML Holistic Scoring
# ══════════════════════════════════════════════════════════════════════════════
class OllamaHolisticResult(BaseModel):
    available:     bool
    model:         str  = ""
    scam_score:    Optional[int]  = None
    fraud_type:    Optional[str]  = None
    confidence:    Optional[str]  = None
    red_flags:     List[str] = []
    reasoning:     Optional[str]  = None
    recommended_action: Optional[str] = None
    latency_ms:    int  = 0
    error:         Optional[str]  = None


class LlavaResult(BaseModel):
    available:          bool
    model:              str  = ""
    is_ai_generated:    Optional[bool] = None
    ai_confidence:      Optional[int]  = None
    face_detected:      Optional[bool] = None
    multiple_faces:     Optional[bool] = None
    is_stock_photo:     Optional[bool] = None
    is_cartoon_avatar:  Optional[bool] = None
    red_flags:          List[str] = []
    description:        Optional[str]  = None
    reasoning:          Optional[str]  = None
    latency_ms:         int  = 0
    error:              Optional[str]  = None


class SklearnResult(BaseModel):
    available:          bool
    model_version:      str  = ""
    fraud_probability:  Optional[float] = None
    predicted_class:    Optional[str]   = None
    feature_count:      int  = 0
    top_features:       List[Dict[str, Any]] = []
    latency_ms:         int  = 0
    error:              Optional[str]   = None
    note:               Optional[str]   = None


class StylometryResult(BaseModel):
    available:              bool
    avg_word_length:        Optional[float] = None
    avg_sentence_length:    Optional[float] = None
    vocabulary_richness:    Optional[float] = None
    flesch_reading_ease:    Optional[float] = None
    gunning_fog:            Optional[float] = None
    punctuation_density:    Optional[float] = None
    capitalization_rate:    Optional[float] = None
    text_uniformity_score:  Optional[float] = None
    repetition_score:       Optional[float] = None
    stylometry_bot_score:   Optional[int]   = None
    flags:                  List[str] = []
    error:                  Optional[str]   = None


# ══════════════════════════════════════════════════════════════════════════════
# FULL PROFILE REQUEST — Single unified input
# ══════════════════════════════════════════════════════════════════════════════
class PostSample(BaseModel):
    text:         Optional[str]  = None
    timestamp:    Optional[str]  = None
    likes:        Optional[int]  = None
    comments:     Optional[int]  = None
    shares:       Optional[int]  = None
    source_app:   Optional[str]  = None
    is_repost:    bool = False
    hashtags:     List[str] = []


class FollowerSample(BaseModel):
    default_avatar:       bool = False
    no_bio:               bool = False
    no_posts:             bool = False
    created_recently:     bool = False
    high_following_ratio: bool = False
    random_username:      bool = False
    zero_followers:       bool = False


class FollowEvent(BaseModel):
    date:   str
    action: str  # "follow" | "unfollow"
    count:  int = 0


class MentionEdge(BaseModel):
    from_user: str
    to_user:   str
    count:     int = 1


class CoordAction(BaseModel):
    timestamp:   str
    username:    str
    action_type: str


class ProfileRequest(BaseModel):
    """Master input — provide as many fields as available."""
    # Identity
    username:             Optional[str]  = None
    display_name:         Optional[str]  = None
    bio:                  Optional[str]  = None
    email:                Optional[str]  = None
    phone:                Optional[str]  = None
    ip:                   Optional[str]  = None
    domain:               Optional[str]  = None
    claimed_platform:     Optional[str]  = None
    claimed_location:     Optional[str]  = None
    claimed_timezone:     Optional[str]  = None
    is_verified:          bool = False

    # Account meta
    account_created:      Optional[str]  = None   # ISO date
    account_age_days:     Optional[int]  = None
    followers:            Optional[int]  = None
    following:            Optional[int]  = None
    posts_count:          Optional[int]  = None

    # Content
    profile_pic_url:      Optional[str]  = None
    profile_pic_base64:   Optional[str]  = None   # for LLaVA
    profile_pic_mime:     str = "image/jpeg"
    posts:                Optional[List[PostSample]] = None
    extra_links:          Optional[List[str]] = None

    # Engagement / Network
    follower_sample:      Optional[List[FollowerSample]] = None
    follower_history:     Optional[List[Dict[str, Any]]] = None
    post_samples_eng:     Optional[List[Dict[str, Any]]] = None  # {likes,comments,shares}

    # Behavioral
    response_times_sec:   Optional[List[float]] = None
    follow_history:       Optional[List[FollowEvent]] = None
    interactions:         Optional[List[Dict[str, Any]]] = None
    coordinated_actions:  Optional[List[CoordAction]] = None
    mention_graph:        Optional[List[MentionEdge]] = None

    # EXIF GPS
    exif_gps_lat:         Optional[float] = None
    exif_gps_lon:         Optional[float] = None

    # Analysis options
    run_ollama:           bool = True
    run_vision:           bool = True
    run_sklearn:          bool = True
    run_osint:            bool = True
    run_crossplatform:    bool = True


# ══════════════════════════════════════════════════════════════════════════════
# FULL PROFILE RESPONSE
# ══════════════════════════════════════════════════════════════════════════════
class FinalVerdict(BaseModel):
    # Block component scores
    block1_score:         Optional[int] = None
    block2_score:         Optional[int] = None
    block3_score:         Optional[int] = None
    block4_ollama_score:  Optional[int] = None
    block4_vision_score:  Optional[int] = None
    block4_sklearn_score: Optional[int] = None
    block4_stylo_score:   Optional[int] = None
    # Aggregated
    final_score:          int       = 0
    risk_level:           RiskLevel = RiskLevel.CLEAN
    fraud_type:           FraudType = FraudType.UNKNOWN
    fraud_type_label:     str       = "UNKNOWN"
    confidence:           str       = "low"
    # Evidence
    top_flags:            List[str] = []
    all_flags:            List[str] = []
    # Human-readable
    summary:              str       = ""
    recommendation:       str       = ""
    # Meta
    analysis_ms:          int       = 0
    blocks_run:           List[str] = []


class FullProfileResult(BaseModel):
    username:             Optional[str] = None
    claimed_platform:     Optional[str] = None
    # Per-block detail
    identity:             Optional[Dict[str, Any]] = None   # Block 1
    content:              Optional[Dict[str, Any]] = None   # Block 2
    network:              Optional[Dict[str, Any]] = None   # Block 3
    ai_ml:                Optional[Dict[str, Any]] = None   # Block 4
    # Final verdict
    verdict:              FinalVerdict


# ══════════════════════════════════════════════════════════════════════════════
# ML TRAINING
# ══════════════════════════════════════════════════════════════════════════════
class TrainSample(BaseModel):
    label:             int   # 1 = fake, 0 = real
    followers:         Optional[int]   = None
    following:         Optional[int]   = None
    account_age_days:  Optional[int]   = None
    bio_length:        Optional[int]   = None
    bio_scam_score:    Optional[int]   = None
    engagement_rate:   Optional[float] = None
    platforms_found:   Optional[int]   = None
    breach_count:      Optional[int]   = None
    block1_score:      Optional[int]   = None
    block2_score:      Optional[int]   = None
    block3_score:      Optional[int]   = None
    has_phone_in_bio:  bool = False
    is_verified:       bool = False
    uses_scheduler:    bool = False
    copy_paste_score:  Optional[float] = None
    posts_count:       Optional[int]   = None


class TrainRequest(BaseModel):
    samples: List[TrainSample] = Field(..., min_length=10)


class TrainResult(BaseModel):
    success:       bool
    samples_used:  int
    accuracy:      Optional[float] = None
    f1_score:      Optional[float] = None
    feature_count: int = 0
    model_path:    str = ""
    message:       str = ""


class HealthResponse(BaseModel):
    status:   str
    version:  str
    redis:    str
    features: Dict[str, Any]
