import gzip
import hashlib
import json
from io import BytesIO
import pytest

from app.schemas.normalized_event import NormalizedEvent, EventMeta, TenantMeta, SourceMeta, HostMeta
from app.services.evidence_service import EvidenceService, MinioUnavailableError


def test_build_s3_key_format():
    ev = NormalizedEvent(
        tenant=TenantMeta(id="tenant-acme"),
        event=EventMeta(id="evt-9999", dataset="apache.access"),
    )
    s3_key = EvidenceService.build_s3_key(ev)
    assert s3_key.startswith("tenant-acme/")
    assert "apache_access" in s3_key
    assert s3_key.endswith("evt-9999.json.gz")


def test_build_evidence_package_gzip_and_sha256():
    ev = NormalizedEvent(
        tenant=TenantMeta(id="tenant-hosting"),
        event=EventMeta(id="evt-5555", original="LÍNEA DE EVIDENCIA CRUDA DE PRUEBA"),
        source=SourceMeta(ip="198.51.100.44"),
        host=HostMeta(hostname="srv-cpanel-01"),
    )

    compressed_bytes, metadata = EvidenceService.build_evidence_package(ev)

    assert isinstance(compressed_bytes, bytes)
    assert len(compressed_bytes) > 0
    assert metadata["event_id"] == "evt-5555"
    assert metadata["tenant_id"] == "tenant-hosting"
    assert metadata["hostname"] == "srv-cpanel-01"
    assert "sha256" in metadata

    # Decompress and verify SHA-256
    with gzip.GzipFile(fileobj=BytesIO(compressed_bytes), mode="rb") as gz:
        uncompressed_data = gz.read()

    calc_hash = hashlib.sha256(uncompressed_data).hexdigest()
    assert calc_hash == metadata["sha256"]

    # Verify JSON content inside
    doc = json.loads(uncompressed_data.decode("utf-8"))
    assert doc["event"]["original"] == "LÍNEA DE EVIDENCIA CRUDA DE PRUEBA"


def test_evidence_service_offline_raises_error():
    service = EvidenceService(endpoint="http://localhost:59999")
    ev = NormalizedEvent(tenant=TenantMeta(id="t1"))

    with pytest.raises(MinioUnavailableError):
        service.upload_evidence(ev)
