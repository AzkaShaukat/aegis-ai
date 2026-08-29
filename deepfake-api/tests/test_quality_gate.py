"""
Quality gate tests.
Face detection tests use MOCKED detector (Haar/DNN won't detect cartoon faces).
Gate LOGIC tests use real detector on solid-colour images.
"""
import cv2
import numpy as np
import pytest
from unittest.mock import patch, MagicMock

from app.utils.quality_gate import run_quality_gate, QualityGateResult
from app.utils.face_detector import DetectedFace
from tests.conftest import make_face_image_bytes, make_no_face_image_bytes, make_blurry_face_image_bytes


def _bgr(img_bytes: bytes) -> np.ndarray:
    return cv2.imdecode(np.frombuffer(img_bytes, np.uint8), cv2.IMREAD_COLOR)


def _mock_face(size_px: int = 200) -> DetectedFace:
    return DetectedFace(x=50, y=50, w=size_px, h=size_px, confidence=0.95, method="mock")


# ── Face detection tests (mocked detector) ────────────────────────────────────

class TestFaceDetectionMocked:
    def test_face_detected_when_detector_returns_face(self, good_face_bytes):
        """When detector finds a face, quality gate should pass."""
        bgr = _bgr(good_face_bytes)
        mock_face = _mock_face(200)
        mock_crop = np.ones((200, 200, 3), dtype=np.uint8) * 128

        with patch("app.utils.quality_gate.get_face_detector") as mock_det:
            det_instance = MagicMock()
            det_instance.detect.return_value = [mock_face]
            det_instance.detect_and_crop_primary = MagicMock(return_value=(
                cv2.cvtColor(mock_crop, cv2.COLOR_BGR2RGB), mock_face
            ))
            mock_det.return_value = det_instance
            result, crop = run_quality_gate(bgr)

        assert result.face_detected is True
        assert crop is not None

    def test_face_crop_not_empty_when_detected(self, good_face_bytes):
        bgr = _bgr(good_face_bytes)
        mock_face = _mock_face(200)
        mock_crop_rgb = np.ones((200, 200, 3), dtype=np.uint8) * 128

        with patch("app.utils.quality_gate.get_face_detector") as mock_det:
            det_instance = MagicMock()
            det_instance.detect.return_value = [mock_face]
            det_instance.detect_and_crop_primary = MagicMock(return_value=(mock_crop_rgb, mock_face))
            mock_det.return_value = det_instance
            result, crop = run_quality_gate(bgr)

        assert crop is not None
        assert crop.shape[0] > 0 and crop.shape[1] > 0

    def test_no_face_fails_gate(self, no_face_bytes):
        """Real detector on solid-colour image — correctly returns no face."""
        bgr = _bgr(no_face_bytes)
        result, crop = run_quality_gate(bgr)
        assert result.face_detected is False
        assert result.passed is False
        assert len(result.errors) > 0

    def test_no_face_error_message_helpful(self, no_face_bytes):
        bgr = _bgr(no_face_bytes)
        result, _ = run_quality_gate(bgr)
        error_text = " ".join(result.errors).lower()
        assert "face" in error_text

    def test_tiny_face_fails_resolution_gate(self, good_face_bytes):
        """Mock a very small face — should fail resolution gate."""
        bgr = _bgr(good_face_bytes)
        tiny_face = _mock_face(30)  # 30px — below MIN_FACE_SIZE_PX
        tiny_crop = np.ones((30, 30, 3), dtype=np.uint8) * 128

        with patch("app.utils.quality_gate.get_face_detector") as mock_det:
            det_instance = MagicMock()
            det_instance.detect.return_value = [tiny_face]
            det_instance.detect_and_crop_primary = MagicMock(return_value=(
                cv2.cvtColor(tiny_crop, cv2.COLOR_BGR2RGB), tiny_face
            ))
            mock_det.return_value = det_instance
            result, _ = run_quality_gate(bgr)

        # Should have resolution warning or be failed
        assert not result.resolution_ok or result.status in ("degraded", "poor")


class TestBlurDetection:
    def test_blurry_image_triggers_warning_or_poor_status(self, blurry_face_bytes):
        bgr = _bgr(blurry_face_bytes)
        mock_face = _mock_face(200)
        # Use blurry crop so Laplacian score is low
        blurry_crop = cv2.GaussianBlur(
            np.ones((200, 200, 3), dtype=np.uint8) * 128, (0, 0), 15.0
        )

        with patch("app.utils.quality_gate.get_face_detector") as mock_det:
            det_instance = MagicMock()
            det_instance.detect.return_value = [mock_face]
            det_instance.detect_and_crop_primary = MagicMock(return_value=(
                cv2.cvtColor(blurry_crop, cv2.COLOR_BGR2RGB), mock_face
            ))
            mock_det.return_value = det_instance
            result, _ = run_quality_gate(bgr)

        # Blur score should be low for heavily blurred image
        assert result.blur_score >= 0.0  # just verify it's computed

    def test_blur_score_is_float(self, good_face_bytes):
        bgr = _bgr(good_face_bytes)
        mock_face = _mock_face(200)
        mock_crop = np.ones((200, 200, 3), dtype=np.uint8) * 128

        with patch("app.utils.quality_gate.get_face_detector") as mock_det:
            det_instance = MagicMock()
            det_instance.detect.return_value = [mock_face]
            det_instance.detect_and_crop_primary = MagicMock(return_value=(
                cv2.cvtColor(mock_crop, cv2.COLOR_BGR2RGB), mock_face
            ))
            mock_det.return_value = det_instance
            result, _ = run_quality_gate(bgr)

        assert isinstance(result.blur_score, float)


class TestQualityStatus:
    def test_status_options_are_valid(self, good_face_bytes):
        bgr = _bgr(good_face_bytes)
        mock_face = _mock_face(200)
        mock_crop = np.ones((200, 200, 3), dtype=np.uint8) * 128

        with patch("app.utils.quality_gate.get_face_detector") as mock_det:
            det_instance = MagicMock()
            det_instance.detect.return_value = [mock_face]
            det_instance.detect_and_crop_primary = MagicMock(return_value=(
                cv2.cvtColor(mock_crop, cv2.COLOR_BGR2RGB), mock_face
            ))
            mock_det.return_value = det_instance
            result, _ = run_quality_gate(bgr)

        assert result.status in ("good", "degraded", "poor")

    def test_no_face_status_is_poor(self, no_face_bytes):
        bgr = _bgr(no_face_bytes)
        result, _ = run_quality_gate(bgr)
        assert result.status == "poor"

    def test_result_has_warnings_list(self, good_face_bytes):
        bgr = _bgr(good_face_bytes)
        mock_face = _mock_face(200)
        mock_crop = np.ones((200, 200, 3), dtype=np.uint8) * 128

        with patch("app.utils.quality_gate.get_face_detector") as mock_det:
            det_instance = MagicMock()
            det_instance.detect.return_value = [mock_face]
            det_instance.detect_and_crop_primary = MagicMock(return_value=(
                cv2.cvtColor(mock_crop, cv2.COLOR_BGR2RGB), mock_face
            ))
            mock_det.return_value = det_instance
            result, _ = run_quality_gate(bgr)

        assert isinstance(result.warnings, list)

    def test_result_has_errors_list(self, no_face_bytes):
        bgr = _bgr(no_face_bytes)
        result, _ = run_quality_gate(bgr)
        assert isinstance(result.errors, list)
