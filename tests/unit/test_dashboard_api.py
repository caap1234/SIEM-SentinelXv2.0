import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "test-api-key"}


def test_soc_dashboard_summary_endpoint():
    res = client.get("/api/v1/dashboard/summary", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "events_received" in data
    assert "events_processed" in data
    assert "events_indexed" in data
    assert "alerts_active" in data
    assert "system_health" in data
    assert data["system_health"]["api"] == "healthy"
    assert data["tenant_id"] == "default"


def test_soc_dashboard_activity_endpoint():
    res = client.get("/api/v1/dashboard/activity", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "series" in data
    assert len(data["series"]) == 24
    assert "events" in data["series"][0]


def test_soc_dashboard_recent_alerts_endpoint():
    res = client.get("/api/v1/dashboard/alerts/recent", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data


def test_soc_dashboard_agents_status_endpoint():
    res = client.get("/api/v1/dashboard/agents/status", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "agents" in data
    assert isinstance(data["agents"], list)


def test_soc_dashboard_unauthenticated_returns_401():
    res = client.get("/api/v1/dashboard/summary")
    assert res.status_code == 401
