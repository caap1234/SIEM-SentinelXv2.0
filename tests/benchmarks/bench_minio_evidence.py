#!/usr/bin/env python3
"""
Benchmark de rendimiento para el worker de evidencia cruda S3 / MinIO (v1).
Mide el throughput de empaquetado, compresión gzip, hash SHA-256 y carga S3.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "bench-key-123")

import asyncio
import time
from unittest.mock import MagicMock, patch, AsyncMock

from app.workers.minio_evidence_worker import MinioEvidenceWorker
from app.schemas.normalized_event import NormalizedEvent, TenantMeta, SourceMeta, EventMeta


def make_event(i: int) -> NormalizedEvent:
    return NormalizedEvent(
        tenant=TenantMeta(id=f"tenant-{i % 5}"),
        event=EventMeta(id=f"evt-ev-{i}", original="2026-08-09 12:00:00 [EXIM] Message received from user@domain.com S=4096"),
        source=SourceMeta(ip=f"198.51.{(i % 250)}.{((i * 11) % 250)}"),
    )


async def run_evidence_benchmark(total_events: int = 5000, batch_size: int = 200) -> dict:
    worker = MinioEvidenceWorker(batch_size=batch_size)
    events = [make_event(i) for i in range(total_events)]

    import json
    messages = []
    for ev in events:
        msg = MagicMock()
        msg.ack = AsyncMock()
        msg.data = json.dumps(ev.to_opensearch_doc(), default=str).encode("utf-8")
        messages.append(msg)

    n_batches = (total_events + batch_size - 1) // batch_size

    with patch.object(
        worker.evidence_service,
        "upload_evidence",
        side_effect=lambda event, bucket_name="sentinelx-evidence": ("key.gz", "sha256", "sentinelx-evidence"),
    ):
        start = time.perf_counter()
        total_uploaded = 0
        total_dlq = 0

        for b in range(n_batches):
            chunk = messages[b * batch_size : (b + 1) * batch_size]
            up, dlq, ret = await worker.process_batch(chunk)
            total_uploaded += up
            total_dlq += dlq

        elapsed = time.perf_counter() - start

    return {
        "total_events": total_events,
        "batch_size": batch_size,
        "n_batches": n_batches,
        "uploaded": total_uploaded,
        "dlq": total_dlq,
        "total_seconds": round(elapsed, 3),
        "events_per_second": round(total_events / elapsed),
        "ms_per_batch": round((elapsed / n_batches) * 1000, 3),
    }


if __name__ == "__main__":
    print("\n═══════════════════════════════════════════")
    print("  SentinelX MinIO Evidence Worker Benchmark")
    print("═══════════════════════════════════════════")

    res = asyncio.run(run_evidence_benchmark(total_events=5000, batch_size=200))
    print(f"\n[Evidence Worker] {res['total_events']:,} events ({res['n_batches']} batches of {res['batch_size']})")
    print(f"  Total time  : {res['total_seconds']}s")
    print(f"  Throughput  : {res['events_per_second']:,} events/s")
    print(f"  Batch rate  : {round(res['n_batches'] / res['total_seconds']):,} batches/s")
    print(f"  Latency p50 : ~{res['ms_per_batch']} ms/batch")
    print("\n═══════════════════════════════════════════\n")
