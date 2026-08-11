import pytest
from unittest.mock import AsyncMock, patch

from app.core.nats_config import STREAM_NORMALIZED, SUBJECT_NORMALIZED_HOSTING
from app.schemas.normalized_event import NormalizedEvent, EventMeta, TenantMeta, SourceMeta
from app.services.nats_service import NatsService, NatsUnavailableError, NatsServiceError


@pytest.mark.asyncio
async def test_nats_service_offline_raises_unavailable_error():
    service = NatsService(url="nats://localhost:59999")
    event = NormalizedEvent(
        tenant=TenantMeta(id="tenant-1"),
        source=SourceMeta(ip="1.1.1.1"),
    )

    with pytest.raises(NatsUnavailableError):
        await service.publish_normalized_event(event)


@pytest.mark.asyncio
async def test_nats_service_publish_event_success():
    service = NatsService()
    service._connected = True
    
    mock_js = AsyncMock()
    mock_ack = AsyncMock()
    mock_ack.stream = STREAM_NORMALIZED
    mock_ack.seq = 100
    mock_ack.sequence = 100
    mock_js.publish.return_value = mock_ack
    service.js = mock_js

    event = NormalizedEvent(
        tenant=TenantMeta(id="tenant-acme"),
        event=EventMeta(id="evt-12345"),
        source=SourceMeta(ip="198.51.100.1"),
    )

    success, stream, seq = await service.publish_normalized_event(event)

    assert success is True
    assert stream == STREAM_NORMALIZED
    assert seq == 100
    mock_js.publish.assert_called_once()
    call_args = mock_js.publish.call_args
    assert call_args.kwargs["headers"]["Nats-Msg-Id"] == "evt-12345"


@pytest.mark.asyncio
async def test_nats_service_publish_dlq():
    service = NatsService()
    service._connected = True
    
    mock_js = AsyncMock()
    service.js = mock_js

    res = await service.publish_dlq({"raw": "bad line"}, reason="parse_failed")
    assert res is True
    mock_js.publish.assert_called_once()
