"""
Unit tests for face detection false-positive suppression.
Tests: skin filter, aspect ratio, NMS, mobile-photo-like backgrounds.
"""
import cv2
import numpy as np
import pytest
from unittest.mock import patch, MagicMock

from app.utils.face_detector import FaceDetector, DetectedFace, _skin_fraction, _is_face_shaped


class TestSkinFilter:
    def test_real_skin_tone_passes(self):
        # South Asian skin tone (BGR: B=110, G=140, R=190)
        img = np.full((100, 100, 3), [110, 140, 190], dtype=np.uint8)
        assert _skin_fraction(img) >= 0.12

    def test_qr_code_black_rejected(self):
        img = np.zeros((100, 100, 3), dtype=np.uint8)
        assert _skin_fraction(img) < 0.12

    def test_qr_code_white_rejected(self):
        img = np.full((100, 100, 3), 255, dtype=np.uint8)
        assert _skin_fraction(img) < 0.12

    def test_blue_background_rejected(self):
        img = np.full((100, 100, 3), [200, 50, 50], dtype=np.uint8)
        assert _skin_fraction(img) < 0.12

    def test_tile_gray_rejected(self):
        img = np.full((100, 100, 3), 128, dtype=np.uint8)
        assert _skin_fraction(img) < 0.12

    def test_darker_skin_tone_passes(self):
        img = np.full((100, 100, 3), [80, 110, 160], dtype=np.uint8)
        assert _skin_fraction(img) >= 0.12

    def test_empty_image_returns_zero(self):
        assert _skin_fraction(None) == 0.0
        assert _skin_fraction(np.zeros((0, 0, 3), dtype=np.uint8)) == 0.0


class TestAspectRatio:
    def test_square_face_passes(self):
        assert _is_face_shaped(100, 100) is True

    def test_slightly_tall_passes(self):
        assert _is_face_shaped(80, 100) is True

    def test_very_wide_rejected(self):
        assert _is_face_shaped(300, 100) is False

    def test_very_tall_rejected(self):
        assert _is_face_shaped(50, 200) is False


class TestNMS:
    def _make_face(self, x, y, w, h, conf=0.9):
        return DetectedFace(x=x, y=y, w=w, h=h, confidence=conf, method="test")

    def test_non_overlapping_kept(self):
        det = FaceDetector()
        faces = [
            self._make_face(0,   0, 100, 100, 0.9),
            self._make_face(200, 0, 100, 100, 0.8),
        ]
        result = det._nms(faces)
        assert len(result) == 2

    def test_overlapping_deduped(self):
        det = FaceDetector()
        faces = [
            self._make_face(0, 0, 100, 100, 0.9),
            self._make_face(5, 5, 100, 100, 0.7),  # IoU > 0.35
        ]
        result = det._nms(faces)
        assert len(result) == 1
        assert result[0].confidence == 0.9

    def test_single_face_unchanged(self):
        det = FaceDetector()
        faces = [self._make_face(0, 0, 100, 100)]
        assert len(det._nms(faces)) == 1

    def test_empty_list(self):
        det = FaceDetector()
        assert det._nms([]) == []


class TestMobilePhotoFalsePositives:
    """Verify that background tiles/text don't get detected as faces."""

    def _make_tiled_background(self, size=400):
        """Create image with repeating tile pattern (common mobile photo background)."""
        img = np.ones((size, size, 3), dtype=np.uint8) * 180
        for i in range(0, size, 30):
            cv2.line(img, (i, 0), (i, size), (140, 140, 140), 1)
            cv2.line(img, (0, i), (size, i), (140, 140, 140), 1)
        return img

    def test_tiled_background_rejected(self):
        det = FaceDetector()
        tile_img = self._make_tiled_background()
        # Validate function should reject all detections from tile pattern
        # Simulate a candidate detection on a tile region
        candidates = [(50, 50, 80, 80, 0.7, "haar")]
        result = det._validate(tile_img, candidates)
        assert len(result) == 0  # tile has no skin pixels

    def test_face_region_accepted(self):
        det = FaceDetector()
        img = np.full((400, 400, 3), [110, 140, 190], dtype=np.uint8)  # skin tone
        candidates = [(50, 50, 150, 150, 0.8, "test")]
        result = det._validate(img, candidates)
        assert len(result) == 1

    def test_tiny_region_rejected(self):
        """Detection smaller than 3% of image area should be rejected."""
        det = FaceDetector()
        img = np.full((400, 400, 3), [110, 140, 190], dtype=np.uint8)
        # 20x20 = 400 pixels, image = 160000 pixels, fraction = 0.25% < 3%
        candidates = [(50, 50, 20, 20, 0.9, "test")]
        result = det._validate(img, candidates)
        assert len(result) == 0
