#!/usr/bin/env python3
"""
Aegis AI — Patch Script
Run once from the project root to apply all fixes, then rebuild Docker.

Usage:
    cd "D:\\Aegis AI\\deepfake-api"
    python patch.py
    docker-compose down
    docker-compose up --build
"""
import os, sys, textwrap, shutil
from pathlib import Path

ROOT = Path(__file__).parent
errors = []


def write(rel_path: str, content: str):
    path = ROOT / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
    print(f"  ✅ Written: {rel_path}")


def patch(rel_path: str, old: str, new: str):
    path = ROOT / rel_path
    if not path.exists():
        errors.append(f"MISSING: {rel_path}")
        return
    content = path.read_text(encoding="utf-8")
    if old not in content:
        errors.append(f"PATTERN NOT FOUND in {rel_path} — may already be patched")
        return
    path.write_text(content.replace(old, new), encoding="utf-8")
    print(f"  ✅ Patched: {rel_path}")


print("\n" + "="*60)
print("  Aegis AI Patch Script")
print("="*60)

# ─────────────────────────────────────────────────────────────
# 1. config.py — fix all settings in one shot
# ─────────────────────────────────────────────────────────────
print("\n[1/6] Rewriting config.py ...")
write("app/config.py", """
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Image pipeline
    IMAGE_EFFICIENTNET_PATH: str = "app/models/efficientnet_best.pth"
    IMAGE_VIT_PATH: str          = "app/models/vit_best.pth"
    IMAGE_FREQCNN_PATH: str      = "app/models/freqcnn_best.pth"
    IMAGE_ENSEMBLE_CONFIG: str   = "app/models/ensemble_config.json"

    # Video pipeline
    VIDEO_SPATIAL_PATH: str    = "app/models/spatial_best.pth"
    VIDEO_TEMPORAL_PATH: str   = "app/models/temporal_best.pth"
    VIDEO_FREQ_SRM_PATH: str   = "app/models/freq_srm_best.pth"
    VIDEO_ENSEMBLE_CONFIG: str = "app/models/ensemble_video_config.json"

    DEVICE: str = "auto"

    # Image processing
    IMAGE_SIZE: int     = 224
    IMAGENET_MEAN: list = [0.485, 0.456, 0.406]
    IMAGENET_STD: list  = [0.229, 0.224, 0.225]

    # Quality gate
    MIN_FACE_SIZE_PX: int      = 60
    MIN_BLUR_SCORE: float      = 20.0
    MIN_FACE_VISIBILITY: float = 0.30

    # Video — unlimited, 1 fps for speed
    VIDEO_FPS_EXTRACT: int      = 1
    SEQUENCE_LENGTH: int        = 16
    MAX_VIDEO_SIZE_MB: int      = 99999   # effectively unlimited
    MAX_VIDEO_DURATION_SEC: int = 3600
    MAX_IMAGE_SIZE_MB: int      = 50      # 50 MB per image

    # API
    API_KEY: str          = ""
    PORT: int             = 8004
    LOG_LEVEL: str        = "INFO"
    HTTP_TIMEOUT: float   = 30.0
    RATE_LIMIT_ENABLED: bool = True

    # Redis
    REDIS_URL: str         = "redis://aegis_deepfake_redis:6379/0"
    CACHE_TTL_SECONDS: int = 3600
    JOB_TTL_SECONDS: int   = 3600

    # Ensemble weights
    IMAGE_DEFAULT_WEIGHTS: list = [0.50, 0.45, 0.05]
    VIDEO_DEFAULT_WEIGHTS: list = [0.45, 0.20, 0.35]

    # Risk thresholds
    RISK_CLEAN_MAX: int  = 15
    RISK_LOW_MAX: int    = 35
    RISK_MEDIUM_MAX: int = 55
    RISK_HIGH_MAX: int   = 75

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
""")

# ─────────────────────────────────────────────────────────────
# 2. ensemble.py — fix confidence_pct (must be >= ensemble)
# ─────────────────────────────────────────────────────────────
print("\n[2/6] Fixing confidence_pct in ensemble.py ...")

NEW_CONFIDENCE = '''def confidence_pct(p_fake: float) -> float:
    """
    Confidence is ALWAYS >= the dominant-side probability.

    If ensemble=83% FAKE  → conviction=83% → confidence >= 83%  (returns ~87%)
    If ensemble=67% FAKE  → conviction=67% → confidence >= 67%  (returns ~75%)
    If ensemble= 8% FAKE  → conviction=92% → confidence >= 92%  (returns ~94%)
    If ensemble=45% FAKE  → conviction=55% → confidence >= 55%  (returns ~63%)

    Formula: conf = conviction + (1 - conviction) * 0.25
    Hard floor: conf >= conviction  (guaranteed by math, enforced explicitly)
    """
    eps = 1e-7
    p = max(eps, min(1.0 - eps, float(p_fake)))
    conviction = max(p, 1.0 - p)                   # 0.5 → 1.0
    conf = conviction + (1.0 - conviction) * 0.25   # always > conviction
    conf = max(conf, conviction + 0.005)             # hard floor
    return round(min(conf, 1.0) * 100, 1)
'''

ensemble_path = ROOT / "app/models/ensemble.py"
if ensemble_path.exists():
    content = ensemble_path.read_text(encoding="utf-8")
    import re
    # Replace any existing confidence_pct function
    pattern = r'def confidence_pct\(p_fake.*?(?=\ndef |\nclass |\Z)'
    if re.search(pattern, content, re.DOTALL):
        content = re.sub(pattern, NEW_CONFIDENCE + "\n\n", content, flags=re.DOTALL)
        ensemble_path.write_text(content, encoding="utf-8")
        print("  ✅ Patched: app/models/ensemble.py (confidence_pct)")
    else:
        errors.append("Could not find confidence_pct in ensemble.py")
else:
    errors.append("MISSING: app/models/ensemble.py")

# ─────────────────────────────────────────────────────────────
# 3. face_detector.py — no centre-crop fallback, cap at 4 faces
# ─────────────────────────────────────────────────────────────
print("\n[3/6] Rewriting face_detector.py ...")
write("app/utils/face_detector.py", """
\"\"\"
Face detection.
- Primary cascade only (haarcascade_frontalface_default)
- minNeighbors=4, minSize=60px — balanced, not too strict
- Cap at 4 faces — more than 4 = almost certainly false positives
- NMS IoU=0.30 — aggressive merge of overlapping boxes
- NO centre-crop fallback — non-face images return [] → UNAVAILABLE
  (QR codes, logos, charts correctly get 'No face detected')
\"\"\"
from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Optional

import cv2
import numpy as np

logger = logging.getLogger(__name__)

_HAAR_PRIMARY = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
_HAAR_ALT2    = cv2.data.haarcascades + "haarcascade_frontalface_alt2.xml"

try:
    import dlib as _dlib
    _DLIB_DETECTOR = _dlib.get_frontal_face_detector()
    DLIB_AVAILABLE = True
except ImportError:
    _DLIB_DETECTOR = None
    DLIB_AVAILABLE = False


@dataclass
class DetectedFace:
    x: int
    y: int
    w: int
    h: int
    confidence: float
    method: str

    @property
    def area(self) -> int:
        return self.w * self.h

    def crop(self, image: np.ndarray, padding: float = 0.20) -> np.ndarray:
        h_img, w_img = image.shape[:2]
        pad_x = int(self.w * padding)
        pad_y = int(self.h * padding)
        x1 = max(0, self.x - pad_x)
        y1 = max(0, self.y - pad_y)
        x2 = min(w_img, self.x + self.w + pad_x)
        y2 = min(h_img, self.y + self.h + pad_y)
        return image[y1:y2, x1:x2]


class FaceDetector:
    def __init__(self):
        self._primary = None
        self._alt2 = None
        try:
            c = cv2.CascadeClassifier(_HAAR_PRIMARY)
            if not c.empty():
                self._primary = c
        except Exception:
            pass
        try:
            c = cv2.CascadeClassifier(_HAAR_ALT2)
            if not c.empty():
                self._alt2 = c
        except Exception:
            pass

    def _nms(self, faces: list, iou: float = 0.30) -> list:
        if len(faces) <= 1:
            return faces
        kept = []
        for cand in sorted(faces, key=lambda f: f.area, reverse=True):
            overlap = False
            for k in kept:
                ix1 = max(cand.x, k.x)
                iy1 = max(cand.y, k.y)
                ix2 = min(cand.x + cand.w, k.x + k.w)
                iy2 = min(cand.y + cand.h, k.y + k.h)
                inter = max(0, ix2 - ix1) * max(0, iy2 - iy1)
                union = cand.area + k.area - inter
                if union > 0 and inter / union > iou:
                    overlap = True
                    break
            if not overlap:
                kept.append(cand)
        return kept

    def _run_cascade(self, cascade, gray: np.ndarray) -> list:
        try:
            dets = cascade.detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=4,
                minSize=(60, 60), flags=cv2.CASCADE_SCALE_IMAGE,
            )
            if len(dets) > 0:
                return [DetectedFace(x=int(x), y=int(y), w=int(w), h=int(h),
                                     confidence=0.80, method="haar")
                        for (x, y, w, h) in dets]
        except Exception as e:
            logger.debug(f"Cascade error: {e}")
        return []

    def detect(self, image_bgr: np.ndarray) -> list:
        \"\"\"Returns list sorted by area. Returns [] if no face — no fallback.\"\"\"
        if image_bgr is None or image_bgr.size == 0:
            return []
        gray    = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2GRAY)
        gray_eq = cv2.equalizeHist(gray)
        candidates = []
        if self._primary is not None:
            found = self._run_cascade(self._primary, gray_eq) or self._run_cascade(self._primary, gray)
            candidates.extend(found)
        if not candidates and self._alt2 is not None:
            found = self._run_cascade(self._alt2, gray_eq) or self._run_cascade(self._alt2, gray)
            candidates.extend(found)
        if not candidates and DLIB_AVAILABLE and _DLIB_DETECTOR is not None:
            try:
                rgb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
                dets, scores, _ = _DLIB_DETECTOR.run(rgb, 1)
                for rect, score in zip(dets, scores):
                    if score >= 0:
                        candidates.append(DetectedFace(
                            x=max(0, rect.left()), y=max(0, rect.top()),
                            w=max(1, rect.width()), h=max(1, rect.height()),
                            confidence=min(1.0, float(score+1)/3.0), method="dlib",
                        ))
            except Exception as e:
                logger.debug(f"dlib error: {e}")
        candidates = self._nms(candidates)
        candidates.sort(key=lambda f: f.area, reverse=True)
        return candidates[:4]   # cap at 4

    def detect_and_crop_primary(self, image_bgr, target_size=224, padding=0.20):
        faces = self.detect(image_bgr)
        if not faces:
            return None, None
        crop = faces[0].crop(image_bgr, padding=padding)
        if crop is None or crop.size == 0:
            return None, None
        return cv2.cvtColor(cv2.resize(crop, (target_size, target_size)), cv2.COLOR_BGR2RGB), faces[0]

    def detect_all_faces(self, image_bgr, target_size=224, padding=0.20):
        results = []
        for face in self.detect(image_bgr):
            crop = face.crop(image_bgr, padding=padding)
            if crop is None or crop.size == 0:
                continue
            results.append((cv2.cvtColor(cv2.resize(crop, (target_size, target_size)), cv2.COLOR_BGR2RGB), face))
        return results


_detector = None

def get_face_detector() -> FaceDetector:
    global _detector
    if _detector is None:
        _detector = FaceDetector()
    return _detector
""")

# ─────────────────────────────────────────────────────────────
# 4. quality_gate.py — hard fail when no face, no centre-crop
# ─────────────────────────────────────────────────────────────
print("\n[4/6] Rewriting quality_gate.py ...")
write("app/utils/quality_gate.py", """
\"\"\"
Quality gate. Hard fail when no face detected — no centre-crop workaround.
QR codes, logos, charts → detector returns [] → UNAVAILABLE response.
\"\"\"
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
""")

# ─────────────────────────────────────────────────────────────
# 5. Dockerfile — 4 workers + long keepalive for large uploads
# ─────────────────────────────────────────────────────────────
print("\n[5/6] Rewriting Dockerfile ...")
write("Dockerfile", """
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \\
    libglib2.0-0 libsm6 libxext6 libxrender-dev libgl1-mesa-glx curl \\
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data
EXPOSE 8004
# --workers 4      = 4 parallel processes, so one long video scan doesn't block others
# --timeout-keep-alive 600  = keep connection alive 10 min (prevents Failed to fetch on large uploads)
CMD ["uvicorn", "app.main:app", \\
     "--host", "0.0.0.0", \\
     "--port", "8004", \\
     "--workers", "4", \\
     "--timeout-keep-alive", "600", \\
     "--log-level", "info"]
""")

# ─────────────────────────────────────────────────────────────
# 6. docker-compose.yml — fix CORS, unlimited video, Redis port
# ─────────────────────────────────────────────────────────────
print("\n[6/6] Rewriting docker-compose.yml ...")
write("docker-compose.yml", """
version: \"3.9\"

services:
  redis:
    image: redis:7-alpine
    container_name: aegis_deepfake_redis
    ports:
      - \"6380:6379\"
    volumes:
      - redis_data:/data
    command: redis-server --save 60 1 --loglevel warning
    restart: unless-stopped
    networks:
      - aegis_net
    healthcheck:
      test: [\"CMD\", \"redis-cli\", \"ping\"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s

  deepfake-api:
    build: .
    container_name: aegis_deepfake_api
    ports:
      - \"8004:8004\"
    volumes:
      - ./app/models:/app/app/models:ro
      - ./data:/app/data
    env_file:
      - .env
    environment:
      - PYTHONUNBUFFERED=1
      - REDIS_URL=redis://aegis_deepfake_redis:6379/0
      - MAX_VIDEO_SIZE_MB=99999
    depends_on:
      redis:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - aegis_net

volumes:
  redis_data:

networks:
  aegis_net:
    driver: bridge
    name: aegis_network
""")

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
print("\n" + "="*60)
if errors:
    print("  ⚠️  Completed with warnings:")
    for e in errors:
        print(f"     - {e}")
else:
    print("  ✅  All patches applied successfully!")

print("""
  Current limits:
    Image size : 50 MB  (MAX_IMAGE_SIZE_MB in config.py)
    Video size : UNLIMITED (MAX_VIDEO_SIZE_MB=99999)
    Video FPS  : 1 fps  (VIDEO_FPS_EXTRACT in config.py)

  Next steps:
    docker-compose down
    docker-compose up --build

  Then verify:
    curl http://localhost:8004/health
""")
