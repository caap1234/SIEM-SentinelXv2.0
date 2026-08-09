import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.workers.minio_evidence_worker import MinioEvidenceWorker
from app.schemas.normalized_event import NormalizedEvent, TenantMeta, SourceMeta, EventMeta
from app.services.evidence_service import MinioUnavailableError, EvidenceServiceError


def make_mock_nats_message(event_id: str = "evt-001", valid_json: bool = True) -> MagicMock:
    msg = MagicMock()
    msg.ack = AsyncMock()
    if valid_json:
        ev = NormalizedEvent(
            tenant=TenantMeta(id="tenant-test"),
            event=EventMeta(id=event_id, original="LOG EVIDENCIA ORIGINAL"),
            source=SourceMeta(ip="198.51.100.5"),
        )
        msg.data = json.dumps(ev.to_opensearch_doc(), default=str).encode("utf-8")
    else:
        msg.data = b"INVALID_RAW_NON_JSON"
    return msg


@pytest.mark.asyncio
async def test_minio_worker_process_batch_success():
    worker = MinioEvidenceWorker()

    msg1 = make_mock_nats_message("evt-001")
    msg2 = make_mock_nats_message("evt-002")
    messages = [msg1, msg2]

    with patch.object(
        worker.evidence_service,
        "upload_evidence",
        return_value=("tenant-test/2026/08/09/generic/evt-001.json.gz", "mocksha256", "sentinelx-evidence"),
    ):
        uploaded, dlq, retries = await worker.process_batch(messages)

    assert uploaded == 2
    assert dlq == 0
    assert retries == 0
    msg1.ack.assert_called_once()
    msg2.ack.assert_called_once()


@pytest.mark.asyncio
async def test_minio_worker_minio_offline_no_ack():
    worker = MinioEvidenceWorker()

    msg1 = make_mock_nats_message("evt-001")
    messages = [msg1]

    with patch.object(
        worker.evidence_service,
        "upload_evidence",
        side_effect=MinioUnavailableError("MinIO connection refused"),
    ):
        uploaded, dlq, retries = await worker.process_batch(messages)

    assert uploaded == 0
    assert dlq == 0
    assert retries == 1
    # ACK MUST NOT be called when MinIO is offline, ensuring NATS JetStream retries later
    msg1.ack.assert_not_called()


@pytest.mark.asyncio
async def test_minio_worker_corrupt_message_sent_to_dlq():
    worker = MinioEvidenceWorker()

    corrupt_msg = make_mock_nats_message(valid_json=False)
    messages = [corrupt_msg]

    with patch.object(worker.nats_service, "publish_dlq", new_callable=AsyncMock) as mock_dlq:
        uploaded, dlq, retries = await worker.process_batch(messages)

    assert uploaded == 0
    assert dlq == 1
    assert retries == 0
    mock_dlq.assert_called_once()
    corrupt_msg.ack.assert_called_once()
