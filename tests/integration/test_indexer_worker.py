import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.workers.opensearch_indexer_worker import OpenSearchIndexerWorker
from app.schemas.normalized_event import NormalizedEvent, TenantMeta, SourceMeta, EventMeta
from app.core.opensearch_client import OpenSearchUnavailableError


def make_mock_nats_message(event_id: str = "evt-001", valid_json: bool = True) -> MagicMock:
    msg = MagicMock()
    msg.ack = AsyncMock()
    if valid_json:
        ev = NormalizedEvent(
            tenant=TenantMeta(id="tenant-test"),
            event=EventMeta(id=event_id),
            source=SourceMeta(ip="198.51.100.5"),
        )
        msg.data = json.dumps(ev.to_opensearch_doc(), default=str).encode("utf-8")
    else:
        msg.data = b"INVALID_RAW_NON_JSON"
    return msg


@pytest.mark.asyncio
async def test_indexer_worker_process_batch_success():
    worker = OpenSearchIndexerWorker()

    msg1 = make_mock_nats_message("evt-001")
    msg2 = make_mock_nats_message("evt-002")
    messages = [msg1, msg2]

    with patch.object(
        worker.opensearch_client,
        "bulk_index_events",
        return_value=(2, []),
    ):
        indexed, dlq, retries = await worker.process_batch(messages)

    assert indexed == 2
    assert dlq == 0
    assert retries == 0
    msg1.ack.assert_called_once()
    msg2.ack.assert_called_once()


@pytest.mark.asyncio
async def test_indexer_worker_corrupt_message_sent_to_dlq():
    worker = OpenSearchIndexerWorker()

    corrupt_msg = make_mock_nats_message(valid_json=False)
    messages = [corrupt_msg]

    with patch.object(worker.nats_service, "publish_dlq", new_callable=AsyncMock) as mock_dlq:
        indexed, dlq, retries = await worker.process_batch(messages)

    assert indexed == 0
    assert dlq == 1
    assert retries == 0
    mock_dlq.assert_called_once()
    corrupt_msg.ack.assert_called_once()


@pytest.mark.asyncio
async def test_indexer_worker_opensearch_offline_no_ack():
    worker = OpenSearchIndexerWorker()

    msg1 = make_mock_nats_message("evt-001")
    messages = [msg1]

    with patch.object(
        worker.opensearch_client,
        "bulk_index_events",
        side_effect=OpenSearchUnavailableError("Cluster offline"),
    ):
        indexed, dlq, retries = await worker.process_batch(messages)

    assert indexed == 0
    assert dlq == 0
    assert retries == 1
    # ACK MUST NOT be called when OpenSearch is offline, allowing JetStream redelivery
    msg1.ack.assert_not_called()


@pytest.mark.asyncio
async def test_indexer_worker_mapping_failure_sent_to_dlq():
    worker = OpenSearchIndexerWorker()

    msg1 = make_mock_nats_message("evt-fail")
    messages = [msg1]

    # OpenSearch returns a mapping error for evt-fail
    failed_items = [
        {
            "create": {
                "_id": "evt-fail",
                "status": 400,
                "error": {"type": "mapper_parsing_exception", "reason": "failed to parse field"},
            }
        }
    ]

    with patch.object(
        worker.opensearch_client,
        "bulk_index_events",
        return_value=(0, failed_items),
    ), patch.object(
        worker.nats_service,
        "publish_dlq",
        new_callable=AsyncMock,
    ) as mock_dlq:
        indexed, dlq, retries = await worker.process_batch(messages)

    assert indexed == 0
    assert dlq == 1
    assert retries == 0
    mock_dlq.assert_called_once()
    msg1.ack.assert_called_once()
