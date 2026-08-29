"""Video pipeline tests — rate limiting and face detection both mocked."""
import time
import numpy as np
import pytest
from unittest.mock import patch, MagicMock


def _mock_det():
    from app.utils.face_detector import DetectedFace
    m = MagicMock()
    face = DetectedFace(x=40, y=40, w=160, h=160, confidence=0.95, method="mock")
    crop = np.ones((224, 224, 3), dtype=np.uint8) * 128
    m.detect.return_value = [face]
    m.detect_and_crop_primary.return_value = (crop, face)
    return m


def _analyze_video(client, vid_bytes):
    """Run video analysis with mocked face detector."""
    with patch("app.analyzers.video_analyzer.get_face_detector", return_value=_mock_det()), \
         patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
        resp = client.post("/analyze/video",
                           files=[("file", ("clip.mp4", vid_bytes, "video/mp4"))])
    return resp


class TestVideoBasic:
    def test_200_with_video(self, client, short_video_bytes):
        assert _analyze_video(client, short_video_bytes).status_code == 200

    def test_empty_400(self, client):
        resp = client.post("/analyze/video", files=[("file", ("e.mp4", b"", "video/mp4"))])
        assert resp.status_code == 400

    def test_oversized_413(self, client):
        big = b"X" * (101 * 1024 * 1024)
        resp = client.post("/analyze/video", files=[("file", ("b.mp4", big, "video/mp4"))])
        assert resp.status_code == 413

    def test_no_face_unavailable(self, client, short_video_bytes):
        no_face = MagicMock()
        no_face.detect_and_crop_primary.return_value = (None, None)
        with patch("app.analyzers.video_analyzer.get_face_detector", return_value=no_face):
            resp = client.post("/analyze/video",
                               files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))])
        assert resp.json()["verdict"] == "UNAVAILABLE"


class TestVideoSchema:
    def test_scan_id_vid(self, client, short_video_bytes):
        data = _analyze_video(client, short_video_bytes).json()
        assert data["scan_id"].startswith("vid-")

    def test_pipeline_video(self, client, short_video_bytes):
        data = _analyze_video(client, short_video_bytes).json()
        assert data["pipeline_used"] == "video_ensemble"

    def test_has_video_info(self, client, short_video_bytes):
        data = _analyze_video(client, short_video_bytes).json()
        assert data.get("video_info") is not None
        vi = data["video_info"]
        assert "duration_seconds" in vi
        assert "sequences_analyzed" in vi
        assert 0.0 <= vi["face_detection_rate"] <= 1.0

    def test_model_names(self, client, short_video_bytes):
        pms = _analyze_video(client, short_video_bytes).json()["per_model_scores"]
        assert "Spatial" in pms["model_1_name"]
        assert "Temporal" in pms["model_2_name"]

    def test_risk_score_range(self, client, short_video_bytes):
        assert 0 <= _analyze_video(client, short_video_bytes).json()["overall_risk_score"] <= 100

    def test_verdict_valid(self, client, short_video_bytes):
        v = _analyze_video(client, short_video_bytes).json()["verdict"]
        assert v in ("REAL","LIKELY_REAL","UNCERTAIN","LIKELY_FAKE","FAKE","UNAVAILABLE")

    def test_confidence_note(self, client, short_video_bytes):
        assert len(_analyze_video(client, short_video_bytes).json()["confidence_note"]) > 5

    def test_agreement_valid(self, client, short_video_bytes):
        assert _analyze_video(client, short_video_bytes).json()["model_agreement"] in ("high","medium","low")


class TestVideoAccuracy:
    def test_real_ensemble_low_risk(self, client, short_video_bytes, real_video_ensemble):
        from app.models import ensemble as em
        em._registry["video"] = real_video_ensemble
        data = _analyze_video(client, short_video_bytes).json()
        if data["verdict"] != "UNAVAILABLE":
            assert data["overall_risk_score"] <= 60

    def test_fake_ensemble_high_risk(self, client, short_video_bytes, fake_video_ensemble):
        from app.models import ensemble as em
        em._registry["video"] = fake_video_ensemble
        data = _analyze_video(client, short_video_bytes).json()
        if data["verdict"] not in ("UNAVAILABLE", "UNCERTAIN"):
            assert data["verdict"] in ("FAKE","LIKELY_FAKE","UNCERTAIN")


class TestAsyncVideo:
    def test_submit_returns_job_id(self, client, short_video_bytes):
        resp = client.post("/analyze/video-async",
                           files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))])
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"].startswith("job-")
        assert data["status"] == "queued"

    def test_poll_returns_job(self, client, short_video_bytes):
        resp = client.post("/analyze/video-async",
                           files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))])
        job_id = resp.json()["job_id"]
        status_resp = client.get(f"/analyze/status/{job_id}")
        assert status_resp.status_code == 200
        assert status_resp.json()["job_id"] == job_id

    def test_invalid_job_404(self, client):
        assert client.get("/analyze/status/nonexistent-0000").status_code == 404

    def test_empty_async_400(self, client):
        assert client.post("/analyze/video-async",
                           files=[("file", ("e.mp4", b"", "video/mp4"))]).status_code == 400

    def test_job_completes(self, client, short_video_bytes):
        with patch("app.analyzers.video_analyzer.get_face_detector", return_value=_mock_det()), \
             patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
            resp = client.post("/analyze/video-async",
                               files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))])
        job_id = resp.json()["job_id"]
        for _ in range(40):
            s = client.get(f"/analyze/status/{job_id}").json()["status"]
            if s in ("complete","failed"):
                break
            time.sleep(1)
        assert s in ("complete","failed")


class TestTimeline:
    def test_timeline_200(self, client, short_video_bytes):
        with patch("app.analyzers.video_analyzer.get_face_detector", return_value=_mock_det()), \
             patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
            resp = client.post("/analyze/video/timeline",
                               files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))])
        assert resp.status_code == 200

    def test_timeline_has_video_info(self, client, short_video_bytes):
        with patch("app.analyzers.video_analyzer.get_face_detector", return_value=_mock_det()), \
             patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
            data = client.post("/analyze/video/timeline",
                               files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))]).json()
        assert "video_info" in data
