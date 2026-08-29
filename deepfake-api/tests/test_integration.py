"""
Integration tests — require real model checkpoints in app/models/.
Mark: pytest -m integration
These test end-to-end accuracy, not just schema.
"""
import pytest
import os
import urllib.request
import cv2
import numpy as np


pytestmark = pytest.mark.integration

MODELS_PRESENT = all(os.path.exists(f"app/models/{m}") for m in [
    "efficientnet_best.pth", "vit_best.pth", "freqcnn_best.pth"
])


@pytest.fixture(scope="session")
def real_client():
    """Client with actual models loaded."""
    if not MODELS_PRESENT:
        pytest.skip("Model checkpoints not present in app/models/")
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


def _download_image(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.read()
    except Exception as e:
        pytest.skip(f"Could not download test image: {e}")


def _solid_face_image() -> bytes:
    """Synthetic face-like image with skin tone for integration tests."""
    img = np.full((300, 300, 3), [110, 140, 190], dtype=np.uint8)
    cx, cy, r = 150, 150, 80
    cv2.ellipse(img, (cx, cy), (r, int(r*1.2)), 0, 0, 360, (185, 145, 110), -1)
    cv2.circle(img, (cx-30, cy-20), 10, (50, 30, 10), -1)
    cv2.circle(img, (cx+30, cy-20), 10, (50, 30, 10), -1)
    _, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    return buf.tobytes()


class TestRealFacePredictsReal:
    def test_obama_photo_low_risk(self, real_client):
        """Well-known real photo should score LOW risk."""
        img_bytes = _download_image(
            "https://upload.wikimedia.org/wikipedia/commons/8/8d/President_Barack_Obama.jpg"
        )
        from unittest.mock import patch, MagicMock
        from app.utils.face_detector import DetectedFace
        import math

        mock_det = MagicMock()
        face = DetectedFace(x=50, y=50, w=200, h=200, confidence=0.97, method="dnn",
                            skin_fraction=0.45)
        nparr = __import__("numpy").frombuffer(img_bytes, __import__("numpy").uint8)
        crop_bgr = __import__("cv2").imdecode(nparr, __import__("cv2").IMREAD_COLOR)
        crop_rgb = __import__("cv2").cvtColor(
            __import__("cv2").resize(crop_bgr, (224, 224)), __import__("cv2").COLOR_BGR2RGB
        )
        mock_det.detect.return_value = [face]
        mock_det.detect_all_faces.return_value = [(crop_rgb, face)]
        mock_det.detect_and_crop_primary.return_value = (crop_rgb, face)

        with patch("app.analyzers.image_analyzer.get_face_detector", return_value=mock_det):
            with patch("app.utils.quality_gate.get_face_detector", return_value=mock_det):
                resp = real_client.post(
                    "/analyze/image",
                    files={"file": ("obama.jpg", img_bytes, "image/jpeg")},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_risk_score"] <= 45, f"Real photo scored too high: {data['overall_risk_score']}"
        assert data["verdict"] in ("REAL", "LIKELY_REAL", "UNCERTAIN")

    def test_synthetic_face_non_zero_score(self, real_client):
        """Models should produce some output on a synthetic face crop."""
        img_bytes = _solid_face_image()
        from unittest.mock import patch, MagicMock
        from app.utils.face_detector import DetectedFace
        mock_det = MagicMock()
        face = DetectedFace(x=60, y=40, w=180, h=220, confidence=0.88,
                            method="test", skin_fraction=0.55)
        nparr = __import__("numpy").frombuffer(img_bytes, __import__("numpy").uint8)
        crop = __import__("cv2").imdecode(nparr, __import__("cv2").IMREAD_COLOR)
        crop_rgb = __import__("cv2").cvtColor(
            __import__("cv2").resize(crop, (224, 224)), __import__("cv2").COLOR_BGR2RGB
        )
        mock_det.detect.return_value = [face]
        mock_det.detect_all_faces.return_value = [(crop_rgb, face)]
        mock_det.detect_and_crop_primary.return_value = (crop_rgb, face)

        with patch("app.analyzers.image_analyzer.get_face_detector", return_value=mock_det):
            with patch("app.utils.quality_gate.get_face_detector", return_value=mock_det):
                resp = real_client.post(
                    "/analyze/image",
                    files={"file": ("face.jpg", img_bytes, "image/jpeg")},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] != "UNAVAILABLE"
        assert 0.0 < data["ensemble_probability"] < 1.0
        assert data["confidence_score"] >= 0.0


class TestSchemaCompleteness:
    def test_all_required_fields_present(self, real_client):
        img_bytes = _solid_face_image()
        from unittest.mock import patch, MagicMock
        from app.utils.face_detector import DetectedFace
        mock_det = MagicMock()
        face = DetectedFace(x=40, y=40, w=200, h=200, confidence=0.9, method="test", skin_fraction=0.5)
        crop_rgb = __import__("numpy").full((224, 224, 3), [185, 145, 110], dtype=__import__("numpy").uint8)
        mock_det.detect.return_value = [face]
        mock_det.detect_all_faces.return_value = [(crop_rgb, face)]
        mock_det.detect_and_crop_primary.return_value = (crop_rgb, face)

        with patch("app.analyzers.image_analyzer.get_face_detector", return_value=mock_det):
            with patch("app.utils.quality_gate.get_face_detector", return_value=mock_det):
                data = real_client.post(
                    "/analyze/image",
                    files={"file": ("face.jpg", img_bytes, "image/jpeg")},
                ).json()

        required = [
            "scan_id", "pipeline_used", "overall_risk_score", "overall_risk_level",
            "ensemble_probability", "confidence_score", "verdict", "message",
            "confidence_note", "per_model_scores", "ensemble_weights",
            "model_agreement", "face_info", "input_quality",
            "all_flags", "total_flags", "elapsed_ms", "cached",
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_confidence_score_above_ensemble_for_high_probability(self, real_client):
        """When p_fake is high, confidence_score should exceed it."""
        img_bytes = _solid_face_image()
        from unittest.mock import patch, MagicMock
        from app.utils.face_detector import DetectedFace
        mock_det = MagicMock()
        face = DetectedFace(x=40, y=40, w=200, h=200, confidence=0.9, method="test", skin_fraction=0.5)
        crop_rgb = __import__("numpy").full((224, 224, 3), [185, 145, 110], dtype=__import__("numpy").uint8)
        mock_det.detect.return_value = [face]
        mock_det.detect_all_faces.return_value = [(crop_rgb, face)]
        mock_det.detect_and_crop_primary.return_value = (crop_rgb, face)

        with patch("app.analyzers.image_analyzer.get_face_detector", return_value=mock_det):
            with patch("app.utils.quality_gate.get_face_detector", return_value=mock_det):
                data = real_client.post(
                    "/analyze/image",
                    files={"file": ("face.jpg", img_bytes, "image/jpeg")},
                ).json()

        p = data["ensemble_probability"]
        conf = data["confidence_score"]
        # If model is confident (p > 0.6 or p < 0.4), confidence should exceed raw probability
        if p > 0.60:
            assert conf > p * 100, f"confidence {conf} not > ensemble {p*100}"
        elif p < 0.40:
            assert conf > (1-p) * 100, f"confidence {conf} not > real-side {(1-p)*100}"
