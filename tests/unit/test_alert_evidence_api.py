import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_alert_evidence_unauthenticated():
    res = client.get("/alerts/999999/evidence")
    assert res.status_code in [401, 404]


