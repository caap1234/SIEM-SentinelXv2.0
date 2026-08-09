#!/usr/bin/env python3
"""
Benchmark de rendimiento para el worker de indexación de OpenSearch (v1).
Mide el throughput de indexación masiva (eventos/s) usando mocks de OpenSearch.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "bench-key-123")

import asyncio
import time
from unittest.mock import MagicMock, patch, AsyncMock

from app.workers.opensearch_indexer_worker import OpenSearchIndexerWorker
from app.schemas.normalized_event import NormalizedEvent, TenantMeta, SourceMeta, EventMeta


def make_event(i: int) -> NormalizedEvent:
    return NormalizedEvent(
        tenant=TenantMeta(id="bench-tenant"),
        event=EventMeta(id=f"evt-bench-{i}"),
        source=SourceMeta(ip=f"198.51.{(i % 250)}.{((i * 7) % 250)}"),
    )


async def run_indexer_benchmark(total_events: int = 10000, batch_size: int = 500) -> dict:
    worker = OpenSearchIndexerWorker(batch_size=batch_size)
    events = [make_event(i) for i in range(total_events)]

    # Mock NATS messages
    messages = []
    import json
    for ev in events:
        msg = MagicMock()
        msg.ack = AsyncMock()
        msg.data = json.dumps(ev.to_opensearch_doc(), default=str).encode("utf-8")
        messages.append(msg)

    n_batches = (total_events + batch_size - 1) // batch_size

    with patch.object(
        worker.opensearch_client,
        "bulk_index_events",
        side_effect=lambda events, target_stream="sentinelx-events-hosting-default": (len(events), []),
    ):
        start = time.perf_counter()
        total_indexed = 0
        total_dlq = 0

        for b in range(n_batches):
            chunk = messages[b * batch_size : (b + 1) * batch_size]
            idx, dlq, ret = await worker.process_batch(chunk)
            total_indexed += idx
            total_dlq += dlq

        elapsed = time.perf_counter() - start

    return {
        "total_events": total_events,
        "batch_size": batch_size,
        "n_batches": n_batches,
        "indexed": total_indexed,
        "dlq": total_dlq,
        "total_seconds": round(elapsed, 3),
        "events_per_second": round(total_events / elapsed),
        "ms_per_batch": round((elapsed / n_batches) * 1000, 3),
    }


if __name__ == "__main__":
    print("\n═══════════════════════════════════════════")
    print("  SentinelX OpenSearch Indexer Benchmark")
    print("═══════════════════════════════════════════")

    res = asyncio.run(run_indexer_benchmark(total_events=10000, batch_size=500))
    print(f"\n[Bulk Indexer] {res['total_events']:,} events ({res['n_batches']} batches of {res['batch_size']})")
    print(f"  Total time  : {res['total_seconds']}s")
    print(f"  Throughput  : {res['events_per_second']:,} events/s")
    print(f"  Batch rate  : {round(res['n_batches'] / res['total_seconds']):,} batches/s")
    print(f"  Latency p50 : ~{res['ms_per_batch']} ms/batch")
    print("\n═══════════════════════════════════════════\n")
