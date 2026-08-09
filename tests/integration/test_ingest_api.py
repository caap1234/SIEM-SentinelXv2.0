"""
Integration tests for Ingest API v1 (/api/v1/ingest).
NATS JetStream is mocked via unittest.mock so tests run without a live broker.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.schemas.normalized_event import NormalizedEvent, TenantMeta, SourceMeta, EventMeta
from app.services.nats_service import NatsUnavailableError, NatsServiceError

BASE_URL = "/api/v1/ingest"
HEADERS = {"X-API-Key": "test-api-key"}


def make_event_payload(**kwargs) -> dict:
    ev = NormalizedEvent(
        tenant=TenantMeta(id=kwargs.get("tenant_id", "tenant-test")),
        source=SourceMeta(ip=kwargs.get("ip", "198.51.100.1")),
    )
    return ev.model_dump(by_alias=True, mode="json")


# ─────────────────────────────────────────────────────────────────────────────
# 1. AUTH TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_ingest_single_no_api_key_returns_401(client):
    payload = make_event_payload()
    response = client.post(f"{BASE_URL}/event", json=payload)
    assert response.status_code == 401


def test_ingest_batch_no_api_key_returns_401(client):
    response = client.post(f"{BASE_URL}/batch", json=[make_event_payload()])
    assert response.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 2. SINGLE EVENT INGEST - NATS AVAILABLE
# ─────────────────────────────────────────────────────────────────────────────

def test_ingest_single_event_success(client):
    mock_ack = MagicMock()
    mock_ack.stream = "SENTINELX_EVENTS_NORMALIZED"
    mock_ack.sequence = 42

    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 42),
    ):
        payload = make_event_payload(tenant_id="tenant-hosting")
        response = client.post(f"{BASE_URL}/event", json=payload, headers=HEADERS)

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert data["tenant_id"] == "tenant-hosting"
    assert data["stream"] == "SENTINELX_EVENTS_NORMALIZED"
    assert data["sequence"] == 42
    assert "event_id" in data
    assert "timestamp_utc" in data


def test_ingest_single_event_contains_event_id(client):
    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 1),
    ):
        payload = make_event_payload()
        response = client.post(f"{BASE_URL}/event", json=payload, headers=HEADERS)

    data = response.json()
    assert isinstance(data["event_id"], str)
    assert len(data["event_id"]) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 3. SINGLE EVENT INGEST - NATS OFFLINE / DEGRADED
# ─────────────────────────────────────────────────────────────────────────────

def test_ingest_single_event_nats_offline_returns_503(client):
    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        side_effect=NatsUnavailableError("NATS offline"),
    ):
        payload = make_event_payload()
        response = client.post(f"{BASE_URL}/event", json=payload, headers=HEADERS)

    assert response.status_code == 503
    assert "nats" in response.json()["detail"].lower()


def test_ingest_single_event_nats_error_returns_500(client):
    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        side_effect=NatsServiceError("Broker timeout"),
    ):
        payload = make_event_payload()
        response = client.post(f"{BASE_URL}/event", json=payload, headers=HEADERS)

    assert response.status_code == 500


# ─────────────────────────────────────────────────────────────────────────────
# 4. BATCH INGEST
# ─────────────────────────────────────────────────────────────────────────────

def test_ingest_batch_success(client):
    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 100),
    ):
        payloads = [make_event_payload() for _ in range(5)]
        response = client.post(f"{BASE_URL}/batch", json=payloads, headers=HEADERS)

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert data["total"] == 5
    assert data["accepted_count"] == 5
    assert data["failed_count"] == 0
    assert len(data["items"]) == 5


def test_ingest_empty_batch_returns_400(client):
    response = client.post(f"{BASE_URL}/batch", json=[], headers=HEADERS)
    assert response.status_code == 400


def test_ingest_batch_too_large_returns_429(client):
    # MAX_BATCH_EVENTS is 5000; send 5001
    import os
    os.environ["INGEST_MAX_BATCH_EVENTS"] = "3"
    
    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 1),
    ):
        payloads = [make_event_payload() for _ in range(4)]
        response = client.post(f"{BASE_URL}/batch", json=payloads, headers=HEADERS)

    # Reset
    os.environ["INGEST_MAX_BATCH_EVENTS"] = "5000"
    assert response.status_code == 429


def test_ingest_batch_nats_offline_returns_503(client):
    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        side_effect=NatsUnavailableError("NATS offline"),
    ):
        payloads = [make_event_payload() for _ in range(2)]
        response = client.post(f"{BASE_URL}/batch", json=payloads, headers=HEADERS)

    assert response.status_code == 503


# ─────────────────────────────────────────────────────────────────────────────
# 5. PYDANTIC SCHEMA VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def test_ingest_invalid_event_schema_returns_422(client):
    # source.port = 99999 is invalid (>65535)
    payload = make_event_payload()
    payload["source"]["port"] = 99999

    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 1),
    ):
        response = client.post(f"{BASE_URL}/event", json=payload, headers=HEADERS)

    assert response.status_code == 422


def test_ingest_invalid_http_status_code_returns_422(client):
    payload = make_event_payload()
    payload["http"] = {"status_code": 50}  # < 100, invalid

    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 1),
    ):
        response = client.post(f"{BASE_URL}/event", json=payload, headers=HEADERS)

    assert response.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# 6. IDEMPOTENCY - same event_id produces same response
# ─────────────────────────────────────────────────────────────────────────────

def test_ingest_same_event_id_idempotent(client):
    fixed_id = "00000000-0000-0000-0000-000000000001"
    payload = make_event_payload()
    payload["event"]["id"] = fixed_id

    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 1),
    ):
        r1 = client.post(f"{BASE_URL}/event", json=payload, headers=HEADERS)
        r2 = client.post(f"{BASE_URL}/event", json=payload, headers=HEADERS)

    assert r1.status_code == 202
    assert r2.status_code == 202
    assert r1.json()["event_id"] == fixed_id
    assert r2.json()["event_id"] == fixed_id
