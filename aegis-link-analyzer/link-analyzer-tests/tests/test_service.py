"""
test_service.py — Service Health & Connectivity Tests
======================================================
Tests for: /, /health, /docs, /metrics, /metrics/prometheus
"""

import pytest
from conftest import BASE_URL, get, TIMEOUT
import httpx


class TestRoot:
    def test_root_returns_200(self):
        r = get("/")
        assert r.status_code == 200

    def test_root_has_service_name(self):
        data = get("/").json()
        assert "service" in data
        assert "link" in data["service"].lower() or "aegis" in data["service"].lower()

    def test_root_has_version(self):
        data = get("/").json()
        assert "version" in data

    def test_root_has_status_running(self):
        data = get("/").json()
        assert data.get("status") == "running"

    def test_root_has_docs_link(self):
        data = get("/").json()
        assert "docs" in data
        assert "/docs" in data["docs"]


class TestHealth:
    def test_health_returns_200(self):
        r = get("/health")
        assert r.status_code == 200

    def test_health_has_status_healthy(self):
        data = get("/health").json()
        assert data.get("status") == "healthy"

    def test_health_has_ml_model_field(self):
        data = get("/health").json()
        assert "ml_model" in data
        assert data["ml_model"] in ("loaded", "unavailable")

    def test_health_has_timestamp(self):
        data = get("/health").json()
        assert "timestamp" in data
        assert len(data["timestamp"]) > 10

    def test_docs_accessible(self):
        r = get("/docs")
        assert r.status_code == 200

    def test_openapi_json_accessible(self):
        r = get("/openapi.json")
        assert r.status_code == 200
        data = r.json()
        assert "paths" in data
        assert "/scan" in data["paths"]


class TestMetrics:
    def test_metrics_json_returns_200(self):
        r = get("/metrics")
        assert r.status_code == 200

    def test_metrics_json_has_summary(self):
        data = get("/metrics").json()
        assert "summary" in data

    def test_metrics_json_has_risk_distribution(self):
        data = get("/metrics").json()
        assert "risk_distribution" in data

    def test_metrics_json_has_threat_feed_hits(self):
        data = get("/metrics").json()
        assert "threat_feed_hits" in data

    def test_metrics_json_has_ml_predictions(self):
        data = get("/metrics").json()
        assert "ml_predictions" in data

    def test_metrics_prometheus_returns_200(self):
        r = get("/metrics/prometheus")
        assert r.status_code == 200

    def test_metrics_prometheus_content_type(self):
        r = get("/metrics/prometheus")
        ct = r.headers.get("content-type", "")
        assert "text/plain" in ct

    def test_metrics_prometheus_has_aegis_prefix(self):
        r = get("/metrics/prometheus")
        assert "aegis_" in r.text

    def test_metrics_increments_after_scan(self):
        from conftest import scan
        before = get("/metrics").json().get("summary", {}).get("total_scans", 0)
        scan("https://google.com")
        after = get("/metrics").json().get("summary", {}).get("total_scans", 0)
        assert after >= before
