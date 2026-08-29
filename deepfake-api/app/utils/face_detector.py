"""
Face detection.
- Primary cascade only (haarcascade_frontalface_default)
- minNeighbors=4, minSize=60px — balanced, not too strict
- Cap at 4 faces — more than 4 = almost certainly false positives
- NMS IoU=0.30 — aggressive merge of overlapping boxes
- NO centre-crop fallback — non-face images return [] → UNAVAILABLE
  (QR codes, logos, charts correctly get 'No face detected')
"""
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
        """Returns list sorted by area. Returns [] if no face — no fallback."""
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
