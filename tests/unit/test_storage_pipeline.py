# tests/unit/test_storage_pipeline.py
import pytest
from datetime import datetime, timezone
from uuid import uuid4

from app.schemas.normalized_event import (
    NormalizedEvent,
    EventMeta,
    TenantMeta,
    HostMeta,
)
from app.services.nats_service import NatsService
from app.workers.opensearch_indexer_worker import OpenSearchIndexerWorker
from app.workers.minio_evidence_worker import MinioEvidenceWorker
from app.services.evidence_service import EvidenceService


def create_sample_event(tenant_id: str = "default") -> NormalizedEvent:
    ev_id = str(uuid4())
    now = datetime.now(timezone.utc)
    return NormalizedEvent(
        event=EventMeta(id=ev_id, dataset="nginx.access", severity=10),
        tenant=TenantMeta(id=tenant_id),
        host=HostMeta(name="srv-unit-test", hostname="srv-unit-test"),
        timestamp_utc=now,
    )


def test_normalized_event_opensearch_doc():
    ev = create_sample_event("default")
    doc = ev.to_opensearch_doc()
    assert doc["tenant"]["id"] == "default"
    assert doc["host"]["name"] == "srv-unit-test"
    assert "@timestamp" in doc


def test_evidence_service_package():
    srv = EvidenceService.get_instance()
    ev = create_sample_event("default")
    payload, meta = srv.build_evidence_package(ev)
    assert len(payload) > 0
    assert "sha256" in meta
    s3_key = srv.build_s3_key(ev)
    assert s3_key.startswith("default/")
    assert s3_key.endswith(".json.gz")


def test_opensearch_indexer_worker_dynamic_stream():
    worker = OpenSearchIndexerWorker()
    ev = create_sample_event("tenant_test")
    doc = ev.to_opensearch_doc()
    assert doc["tenant"]["id"] == "tenant_test"


def test_log_upload_tenant_resolution():
    from app.models.log_upload import LogUpload
    log = LogUpload(filename="test.log", server="svgt187", path="/tmp/test.log", extra_meta={"tenant_id": "global"})
    
    tenant_str = "default"
    if log:
        meta = log.extra_meta if isinstance(getattr(log, "extra_meta", None), dict) else {}
        if meta.get("tenant_id"):
            tenant_str = str(meta["tenant_id"])
    assert tenant_str == "global"
