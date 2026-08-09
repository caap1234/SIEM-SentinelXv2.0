"""
Integration test: /health endpoint.
Tests that the API starts and returns a healthy status.
No live database required - just FastAPI startup.
"""
import pytest


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "sentinelx-api"


def test_health_check_version(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "version" in data


def test_docs_available(client):
    response = client.get("/docs")
    assert response.status_code == 200


def test_openapi_schema(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "paths" in schema
    assert "info" in schema
