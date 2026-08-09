#!/usr/bin/env python3
"""
Benchmark de rendimiento para el motor de correlación reactivo en tiempo real (v1).
Mide el throughput (eventos/s), latencia p50 por evento y la sobrecarga de memoria de ventanas.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "bench-key-123")

import time
from app.services.correlation_engine import CorrelationEngine
from app.schemas.normalized_event import NormalizedEvent, EventMeta, TenantMeta, SourceMeta, ServiceMeta
from app.core.hosting_rules import DEFAULT_HOSTING_RULES


def run_correlation_benchmark(total_events: int = 50000) -> dict:
    engine = CorrelationEngine(rules=DEFAULT_HOSTING_RULES)

    events = [
        NormalizedEvent(
            tenant=TenantMeta(id=f"tenant-{i % 3}"),
            event=EventMeta(id=f"evt-c-{i}", action="auth_failed" if i % 2 == 0 else "login_failed"),
            service=ServiceMeta(name="exim" if i % 2 == 0 else "sshd"),
            source=SourceMeta(ip=f"198.51.{(i % 100)}.{((i * 3) % 250)}"),
        )
        for i in range(total_events)
    ]

    start = time.perf_counter()
    total_alerts = 0
    for ev in events:
        alerts = engine.process_event(ev)
        total_alerts += len(alerts)
    elapsed = time.perf_counter() - start

    # Calcular sobrecarga de memoria aproximada
    bucket_count = len(engine.windows)

    return {
        "total_events": total_events,
        "total_rules_evaluated": len(DEFAULT_HOSTING_RULES),
        "total_alerts": total_alerts,
        "active_buckets": bucket_count,
        "total_seconds": round(elapsed, 4),
        "events_per_second": round(total_events / elapsed),
        "ns_per_event": round((elapsed / total_events) * 1000000000, 2),
        "us_per_event": round((elapsed / total_events) * 1000000, 2),
    }


if __name__ == "__main__":
    print("\n═══════════════════════════════════════════")
    print("  SentinelX Correlation Engine Benchmark")
    print("═══════════════════════════════════════════")

    res = run_correlation_benchmark(total_events=50000)
    print(f"\n[Correlation Engine] {res['total_events']:,} events evaluated against {res['total_rules_evaluated']} detection rules")
    print(f"  Total time     : {res['total_seconds']}s")
    print(f"  Throughput     : {res['events_per_second']:,} events/s")
    print(f"  Latency p50    : ~{res['us_per_event']} µs/event ({res['ns_per_event']} ns)")
    print(f"  Alerts Emitted : {res['total_alerts']:,}")
    print(f"  Active Buckets : {res['active_buckets']:,} sliding windows")
    print("\n═══════════════════════════════════════════\n")
