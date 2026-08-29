"""Pydantic schemas for all Phase 1 + Phase 2 endpoints."""
from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    CLEAN    = "Clean"
    LOW      = "Low Risk"
    MEDIUM   = "Medium Risk"
    HIGH     = "High Risk"
    CRITICAL = "Critical"


class Pipeline(str, Enum):
    IMAGE = "image_ensemble"
    VIDEO = "video_ensemble"


class ModelAgreement(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


class InputQualityStatus(str, Enum):
    GOOD     = "good"
    DEGRADED = "degraded"
    POOR     = "poor"


# ── Request models ────────────────────────────────────────────────────────────

class ImageURLRequest(BaseModel):
    url: str = Field(..., description="Publicly accessible URL of a face image")
    source_hint: Optional[str] = Field(None, description="'whatsapp'|'telegram'|'download'|'original'")


class BatchImageRequest(BaseModel):
    images_base64: list[str] = Field(..., description="List of base64-encoded images (max 10)", max_length=10)
    source_hint: Optional[str] = None


# ── Sub-models ────────────────────────────────────────────────────────────────

class PerModelScores(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_1_name: str
    model_1_p_fake: float = Field(..., ge=0.0, le=1.0)
    model_2_name: str
    model_2_p_fake: float = Field(..., ge=0.0, le=1.0)
    model_3_name: str
    model_3_p_fake: float = Field(..., ge=0.0, le=1.0)


class EnsembleWeights(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_1_weight: float
    model_2_weight: float
    model_3_weight: float
    source: str


class FaceInfo(BaseModel):
    faces_detected: int
    primary_face_size_px: Optional[int] = None
    face_detection_confidence: Optional[float] = None
    multiple_faces: bool = False


class InputQuality(BaseModel):
    status: InputQualityStatus
    blur_score: Optional[float] = None
    resolution_ok: bool = True
    face_visibility_ok: bool = True
    warnings: list[str] = Field(default_factory=list)


class VideoInfo(BaseModel):
    duration_seconds: float
    fps_extracted: int
    total_frames_extracted: int
    sequences_analyzed: int
    face_detection_rate: float


class TimelineEntry(BaseModel):
    second: int
    p_fake: float


# ── Main analysis result ──────────────────────────────────────────────────────

class DeepfakeAnalysisResult(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    scan_id: str
    scan_date: str
    pipeline_used: Pipeline
    overall_risk_score: int = Field(..., ge=0, le=100)
    overall_risk_level: RiskLevel
    ensemble_probability: float = Field(..., ge=0.0, le=1.0)
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0,
        description="Distance from 0.5 boundary × 200. 0=uncertain, 100=certain.")
    scan_date: str
    pipeline_used: Pipeline
    overall_risk_score: int = Field(..., ge=0, le=100)
    overall_risk_level: RiskLevel
    ensemble_probability: float = Field(..., ge=0.0, le=1.0)
    verdict: str
    message: str
    confidence_note: str
    per_model_scores: PerModelScores
    ensemble_weights: EnsembleWeights
    model_agreement: ModelAgreement
    face_info: FaceInfo
    input_quality: InputQuality
    video_info: Optional[VideoInfo] = None
    timeline: Optional[list[TimelineEntry]] = None
    gradcam_heatmap: Optional[str] = None  # base64 JPEG (Phase 2 /explain endpoint)
    all_flags: list[str] = Field(default_factory=list)
    total_flags: int = 0
    elapsed_ms: float
    cached: bool = False
    model_version: str = "2.0.0"
    privacy: dict = Field(default_factory=lambda: {"note": "Input media is not stored. Analysis runs in-memory."})


# ── Batch result ──────────────────────────────────────────────────────────────

class BatchImageResult(BaseModel):
    total_images: int
    completed: int
    failed: int
    results: list[dict]
    batch_risk: str
    highest_risk_score: int
    elapsed_ms: float


# ── Async job schemas ─────────────────────────────────────────────────────────

class AsyncJobResponse(BaseModel):
    job_id: str
    status: str
    message: str
    poll_url: str
    created_at: float


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress_message: str
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    elapsed_seconds: Optional[float] = None
    result: Optional[DeepfakeAnalysisResult] = None
    error: Optional[str] = None


# ── System schemas ────────────────────────────────────────────────────────────

class ModelStatus(BaseModel):
    loaded: bool
    path: str
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    image_pipeline: dict
    video_pipeline: dict
    device: str
    gpu_available: bool
    redis_available: bool
    timestamp: str


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    scan_id: Optional[str] = None


# ── Feedback schemas ──────────────────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    scan_id: str
    original_verdict: str
    corrected_verdict: str = Field(..., description="'real' or 'fake'")
    notes: Optional[str] = None


class FeedbackResponse(BaseModel):
    feedback_id: str
    status: str
    message: str
