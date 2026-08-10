import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "test-api-key"}


def test_hunting_search_endpoint():
    res = client.get("/api/v1/hunting/search?q=exim", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert "total" in data
    assert data["tenant_id"] == "default"


def test_hunting_event_detail_endpoint():
    res = client.get("/api/v1/hunting/event/evt-mock-001", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["_id"] == "evt-mock-001"
    assert "sentinelx" in data


def test_hunting_unauthenticated_returns_401():
    res = client.get("/api/v1/hunting/search")
    assert res.status_code == 401
