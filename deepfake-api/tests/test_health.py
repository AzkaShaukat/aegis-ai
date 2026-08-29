"""Tests for GET /health and GET / endpoints."""


def test_health_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_health_schema(client):
    data = client.get("/health").json()
    for field in ("status", "image_pipeline", "video_pipeline", "device",
                  "gpu_available", "redis_available", "timestamp"):
        assert field in data, f"Missing: {field}"


def test_health_status_values(client):
    data = client.get("/health").json()
    assert data["status"] in ("healthy", "degraded", "unavailable")


def test_health_with_mocked_models(client):
    """With mocked models (all_loaded=True via statuses.loaded=True), degraded or healthy."""
    data = client.get("/health").json()
    # Mocked models have statuses.loaded=True but model instances are real mocks
    # all_loaded checks model instances != None — they are MagicMock so not None
    assert data["status"] in ("healthy", "degraded")


def test_health_no_models_not_healthy(unloaded_client):
    """With unloaded ensemble (all model instances are None), status should be degraded."""
    data = unloaded_client.get("/health").json()
    # all_loaded = False (None models), so status = degraded
    assert data["status"] in ("degraded", "unavailable")
    assert data["status"] != "healthy"


def test_health_pipeline_keys_present(client):
    data = client.get("/health").json()
    assert len(data["image_pipeline"]) > 0
    assert len(data["video_pipeline"]) > 0


def test_health_timestamp_iso(client):
    import re
    data = client.get("/health").json()
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", data["timestamp"])


def test_root_returns_200(client):
    assert client.get("/").status_code == 200


def test_root_has_phase_endpoints(client):
    data = client.get("/").json()
    assert "phase1_endpoints" in data
    assert "phase2_endpoints" in data
    assert "/analyze/image" in data["phase1_endpoints"]
    assert "/analyze/video-async" in data["phase2_endpoints"]


def test_root_has_version(client):
    assert "version" in client.get("/").json()
