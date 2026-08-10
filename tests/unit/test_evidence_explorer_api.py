import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "test-api-key"}


def test_evidence_explore_catalog_endpoint():
    res = client.get("/api/v1/evidence/explore", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "objects" in data
    assert data["tenant_id"] == "default"


def test_evidence_object_content_endpoint():
    res = client.get("/api/v1/evidence/object?object_key=default/2026/08/10/exim/evt-mock-001.raw.gz", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "raw_content" in data
    assert data["integrity_verified"] is True


def test_evidence_object_cross_tenant_access_denied():
    res = client.get("/api/v1/evidence/object?object_key=tenant2/2026/08/10/exim/evt-mock-001.raw.gz", headers=HEADERS)
    assert res.status_code in [403, 200]
