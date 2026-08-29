"""
Quality gate. Hard fail when no face detected — no centre-crop workaround.
QR codes, logos, charts → detector returns [] → UNAVAILABLE response.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

import cv2
import numpy as np

from app.config import get_settings
from app.utils.face_detector import DetectedFace, get_face_detector

settings = get_settings()


@dataclass
class QualityGateResult:
    passed: bool
    status: str
    blur_score: float
    resolution_ok: bool
    face_detected: bool
    face_size_px: int
    visibility: float = 1.0
    warnings: list = field(default_factory=list)
    errors: list   = field(default_factory=list)


def _blur(gray: np.ndarray) -> float:
    return float(cv2.Laplacian(gray, cv2.CV_64F).var())


def run_quality_gate(image_bgr: np.ndarray):
    if image_bgr is None or image_bgr.size == 0:
        return QualityGateResult(passed=False, status="poor", blur_score=0.0,
            resolution_ok=False, face_detected=False, face_size_px=0,
            errors=["Empty or unreadable image."]), None

    detector  = get_face_detector()
    warnings  = []
    errors    = []
    faces     = detector.detect(image_bgr)

    if not faces:
        return QualityGateResult(
            passed=False, status="poor", blur_score=0.0,
            resolution_ok=False, face_detected=False, face_size_px=0,
            errors=["No face detected. Please send a clear photo showing a human face. "
                    "QR codes, logos, and non-face images are not supported."],
        ), None

    primary       = faces[0]
    face_crop_bgr = primary.crop(image_bgr, padding=0.20)
    face_size_px  = min(primary.w, primary.h)
    resolution_ok = face_size_px >= settings.MIN_FACE_SIZE_PX

    if face_size_px < 30:
        errors.append(f"Face region too small ({face_size_px}px). Send a larger photo.")
    elif not resolution_ok:
        warnings.append(f"Face small ({face_size_px}px, recommended ≥{settings.MIN_FACE_SIZE_PX}px).")

    blur_score = 0.0
    if face_crop_bgr is not None and face_crop_bgr.size > 0:
        blur_score = _blur(cv2.cvtColor(face_crop_bgr, cv2.COLOR_BGR2GRAY))
    if blur_score < settings.MIN_BLUR_SCORE:
        warnings.append(f"Blurry image (score {blur_score:.1f}). Frequency analysis accuracy reduced.")

    if len(faces) > 1:
        warnings.append(f"{len(faces)} faces detected — each analyzed individually. "
                        "Final verdict = highest-risk face.")

    has_error = len(errors) > 0
    status = "poor" if has_error else ("degraded" if warnings else "good")

    return QualityGateResult(
        passed=not has_error, status=status, blur_score=blur_score,
        resolution_ok=resolution_ok, face_detected=True,
        face_size_px=face_size_px, warnings=warnings, errors=errors,
    ), face_crop_bgr
