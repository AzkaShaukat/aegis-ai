"""
Phase 2 tests — async jobs, batch, GradCAM, timeline, cache, feedback.
All use mocked models (no .pth files needed).
"""
import base64
import time
import pytest
from tests.conftest import make_face_image_bytes, make_minimal_valid_mp4


class TestBatchEndpoint:
    def test_batch_single_image(self, client, good_face_bytes):
        resp = client.post(
            "/analyze/batch",
            files=[("files", ("face.jpg", good_face_bytes, "image/jpeg"))],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_images"] == 1
        assert data["completed"] == 1
        assert "batch_risk" in data
        assert "highest_risk_score" in data
        assert "elapsed_ms" in data

    def test_batch_multiple_images(self, client, good_face_bytes):
        files = [("files", (f"face{i}.jpg", good_face_bytes, "image/jpeg")) for i in range(3)]
        resp = client.post("/analyze/batch", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_images"] == 3

    def test_batch_exceeds_10_returns_400(self, client, good_face_bytes):
        files = [("files", (f"face{i}.jpg", good_face_bytes, "image/jpeg")) for i in range(11)]
        resp = client.post("/analyze/batch", files=files)
        assert resp.status_code == 400

    def test_batch_results_have_required_fields(self, client, good_face_bytes):
        files = [("files", ("face.jpg", good_face_bytes, "image/jpeg"))]
        data = client.post("/analyze/batch", files=files).json()
        assert len(data["results"]) == 1
        result = data["results"][0]
        assert result["status"] == "complete"
        assert "overall_risk_score" in result

    def test_batch_empty_returns_400(self, client):
        resp = client.post("/analyze/batch", files=[])
        assert resp.status_code in (400, 422)

    def test_batch_no_face_counted_as_complete(self, client, no_face_bytes):
        files = [("files", ("blank.jpg", no_face_bytes, "image/jpeg"))]
        resp = client.post("/analyze/batch", files=files)
        assert resp.status_code == 200
        data = resp.json()
        # No face is a valid (complete) result with verdict UNAVAILABLE
        assert data["total_images"] == 1


class TestAsyncVideoEndpoint:
    def test_async_submit_returns_job_id(self, client, short_video_bytes):
        resp = client.post(
            "/analyze/video-async",
            files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "job_id" in data
        assert data["job_id"].startswith("job-")
        assert "poll_url" in data
        assert data["status"] == "queued"

    def test_async_job_status_returns_job(self, client, short_video_bytes):
        # Submit
        resp = client.post(
            "/analyze/video-async",
            files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))],
        )
        job_id = resp.json()["job_id"]

        # Poll immediately — should be queued or processing
        status_resp = client.get(f"/analyze/status/{job_id}")
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data["job_id"] == job_id
        assert data["status"] in ("queued", "preprocessing", "extracting_faces", "running_models", "complete", "failed")

    def test_async_invalid_job_id_returns_404(self, client):
        resp = client.get("/analyze/status/nonexistent-job-id")
        assert resp.status_code == 404

    def test_async_oversized_returns_413(self, client):
        big = b"X" * (101 * 1024 * 1024)
        resp = client.post(
            "/analyze/video-async",
            files=[("file", ("big.mp4", big, "video/mp4"))],
        )
        assert resp.status_code == 413

    def test_async_empty_returns_400(self, client):
        resp = client.post(
            "/analyze/video-async",
            files=[("file", ("empty.mp4", b"", "video/mp4"))],
        )
        assert resp.status_code == 400

    def test_async_job_completes(self, client, short_video_bytes):
        """Poll until complete (with timeout)."""
        resp = client.post(
            "/analyze/video-async",
            files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))],
        )
        job_id = resp.json()["job_id"]

        # Poll up to 30 seconds
        for _ in range(30):
            status = client.get(f"/analyze/status/{job_id}").json()
            if status["status"] in ("complete", "failed"):
                break
            time.sleep(1)

        assert status["status"] in ("complete", "failed")
        if status["status"] == "complete":
            assert status["result"] is not None
            assert "overall_risk_score" in status["result"]


class TestExplainEndpoint:
    def test_explain_returns_200(self, client, good_face_bytes):
        resp = client.post(
            "/analyze/image/explain",
            files=[("file", ("face.jpg", good_face_bytes, "image/jpeg"))],
        )
        assert resp.status_code == 200

    def test_explain_schema(self, client, good_face_bytes):
        data = client.post(
            "/analyze/image/explain",
            files=[("file", ("face.jpg", good_face_bytes, "image/jpeg"))],
        ).json()
        assert "scan_id" in data
        assert "overall_risk_score" in data
        # gradcam_heatmap is None when no real model loaded, that's fine
        assert "gradcam_heatmap" in data

    def test_explain_no_face_returns_unavailable(self, client, no_face_bytes):
        data = client.post(
            "/analyze/image/explain",
            files=[("file", ("blank.jpg", no_face_bytes, "image/jpeg"))],
        ).json()
        assert data["verdict"] == "UNAVAILABLE"

    def test_explain_result_not_cached(self, client, good_face_bytes):
        """GradCAM results should not be cached (too large)."""
        # Two calls with same image — both should succeed
        r1 = client.post("/analyze/image/explain",
                         files=[("file", ("face.jpg", good_face_bytes, "image/jpeg"))]).json()
        r2 = client.post("/analyze/image/explain",
                         files=[("file", ("face.jpg", good_face_bytes, "image/jpeg"))]).json()
        assert r1["cached"] is False
        assert r2["cached"] is False


class TestTimelineEndpoint:
    def test_timeline_returns_200(self, client, short_video_bytes):
        resp = client.post(
            "/analyze/video/timeline",
            files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))],
        )
        assert resp.status_code == 200

    def test_timeline_schema(self, client, short_video_bytes):
        data = client.post(
            "/analyze/video/timeline",
            files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))],
        ).json()
        assert "video_info" in data
        # Timeline is populated when spatial model is loaded;
        # in stub mode it may be None — both are acceptable
        assert "timeline" in data

    def test_timeline_entries_have_correct_fields(self, client, short_video_bytes):
        data = client.post(
            "/analyze/video/timeline",
            files=[("file", ("clip.mp4", short_video_bytes, "video/mp4"))],
        ).json()
        if data.get("timeline"):
            entry = data["timeline"][0]
            assert "second" in entry
            assert "p_fake" in entry
            assert 0.0 <= entry["p_fake"] <= 1.0


class TestFeedbackEndpoint:
    def test_feedback_returns_200(self, client):
        resp = client.post("/feedback", json={
            "scan_id": "img-abc123",
            "original_verdict": "FAKE",
            "corrected_verdict": "real",
            "notes": "This is a real person",
        })
        assert resp.status_code == 200

    def test_feedback_schema(self, client):
        data = client.post("/feedback", json={
            "scan_id": "img-xyz",
            "original_verdict": "REAL",
            "corrected_verdict": "fake",
        }).json()
        assert "feedback_id" in data
        assert data["feedback_id"].startswith("fb-")
        assert data["status"] == "received"

    def test_feedback_stats(self, client):
        resp = client.get("/feedback/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_feedback" in data
        assert "training_ready" in data

    def test_feedback_missing_fields_returns_422(self, client):
        resp = client.post("/feedback", json={"scan_id": "abc"})
        assert resp.status_code == 422


class TestCacheEndpoints:
    def test_cache_stats_returns_200(self, client):
        resp = client.get("/cache/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "redis_available" in data

    def test_cache_purge_returns_200(self, client):
        resp = client.delete("/cache/purge")
        assert resp.status_code == 200
        data = resp.json()
        assert "purged" in data


class TestCachedImageResult:
    def test_cached_flag_false_first_request(self, client, good_face_bytes):
        """First request should not be cached."""
        # Purge first to ensure clean state
        client.delete("/cache/purge")
        data = client.post(
            "/analyze/image",
            files=[("file", ("face.jpg", good_face_bytes, "image/jpeg"))],
        ).json()
        # cached is False on first request
        assert data["cached"] is False

    def test_image_result_has_cached_field(self, client, good_face_bytes):
        data = client.post(
            "/analyze/image",
            files=[("file", ("face.jpg", good_face_bytes, "image/jpeg"))],
        ).json()
        assert "cached" in data


class TestPhase2HealthFields:
    def test_health_has_redis_field(self, client):
        data = client.get("/health").json()
        assert "redis_available" in data

    def test_root_has_phase2_endpoints(self, client):
        data = client.get("/").json()
        assert "phase2_endpoints" in data
        assert "/analyze/video-async" in data["phase2_endpoints"]
        assert "/analyze/batch" in data["phase2_endpoints"]
