#!/usr/bin/env python3
"""
Benchmark de rendimiento para la API de Ingesta de SentinelX SIEM v1.
Mide throughput de eventos/s usando el mock de NATS (sin broker real).
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "bench-key-123")

from unittest.mock import AsyncMock, patch
import time

from fastapi.testclient import TestClient
from app.main import app
from app.schemas.normalized_event import NormalizedEvent, TenantMeta, SourceMeta, EventMeta


def make_payload(ip: str = "198.51.100.1") -> dict:
    ev = NormalizedEvent(
        tenant=TenantMeta(id="bench-tenant"),
        source=SourceMeta(ip=ip),
    )
    return ev.model_dump(by_alias=True, mode="json")


def run_single_event_benchmark(n: int = 1000) -> dict:
    client = TestClient(app, raise_server_exceptions=False)
    payload = make_payload()
    headers = {"X-API-Key": "bench-key"}

    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 1),
    ):
        start = time.perf_counter()
        for _ in range(n):
            r = client.post("/api/v1/ingest/event", json=payload, headers=headers)
            assert r.status_code == 202, f"Unexpected: {r.status_code}"
        elapsed = time.perf_counter() - start

    return {
        "mode": "single_event",
        "n_requests": n,
        "total_seconds": round(elapsed, 3),
        "events_per_second": round(n / elapsed),
        "ms_per_event": round((elapsed / n) * 1000, 3),
    }


def run_batch_benchmark(n_batches: int = 100, batch_size: int = 50) -> dict:
    client = TestClient(app, raise_server_exceptions=False)
    batch = [make_payload(f"198.51.{i % 255}.{(i * 3) % 255}") for i in range(batch_size)]
    headers = {"X-API-Key": "bench-key"}

    with patch(
        "app.services.nats_service.NatsService.publish_normalized_event",
        new_callable=AsyncMock,
        return_value=(True, "SENTINELX_EVENTS_NORMALIZED", 1),
    ):
        start = time.perf_counter()
        for _ in range(n_batches):
            r = client.post("/api/v1/ingest/batch", json=batch, headers=headers)
            assert r.status_code == 202, f"Unexpected: {r.status_code}"
        elapsed = time.perf_counter() - start

    total_events = n_batches * batch_size
    return {
        "mode": "batch",
        "n_batches": n_batches,
        "batch_size": batch_size,
        "total_events": total_events,
        "total_seconds": round(elapsed, 3),
        "events_per_second": round(total_events / elapsed),
        "batches_per_second": round(n_batches / elapsed),
        "ms_per_batch": round((elapsed / n_batches) * 1000, 3),
    }


if __name__ == "__main__":
    print("\n═══════════════════════════════════════════")
    print("  SentinelX Ingest API Benchmark (v1)")
    print("═══════════════════════════════════════════")

    r1 = run_single_event_benchmark(n=500)
    print(f"\n[Single Event] {r1['n_requests']} events")
    print(f"  Total time  : {r1['total_seconds']}s")
    print(f"  Throughput  : {r1['events_per_second']:,} events/s")
    print(f"  Latency p50 : ~{r1['ms_per_event']} ms/event")

    r2 = run_batch_benchmark(n_batches=100, batch_size=50)
    print(f"\n[Batch {r2['batch_size']} events/req] {r2['n_batches']} batches = {r2['total_events']:,} events")
    print(f"  Total time  : {r2['total_seconds']}s")
    print(f"  Throughput  : {r2['events_per_second']:,} events/s")
    print(f"  Batch rate  : {r2['batches_per_second']:,} batches/s")
    print(f"  Latency p50 : ~{r2['ms_per_batch']} ms/batch")
    print("\n═══════════════════════════════════════════\n")
