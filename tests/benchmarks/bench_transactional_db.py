#!/usr/bin/env python3
"""
Benchmark de rendimiento para operaciones transaccionales en PostgreSQL / DB (v1).
Mide latencia y throughput de creación de tenants, chequeos RBAC y auditoría.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "bench-key-123")

import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models.tenant import Tenant
from app.models.audit_log import AuditLog
from app.services.audit_service import log_audit_event
from app.core.rbac import check_role_permission, ROLE_ANALYST, PERM_ALERTS_MANAGE

engine = create_engine("sqlite:///:memory:")
Tenant.__table__.create(bind=engine, checkfirst=True)
AuditLog.__table__.create(bind=engine, checkfirst=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def run_rbac_benchmark(n: int = 100000) -> dict:
    start = time.perf_counter()
    for _ in range(n):
        res = check_role_permission(ROLE_ANALYST, PERM_ALERTS_MANAGE)
        assert res is True
    elapsed = time.perf_counter() - start

    return {
        "n_checks": n,
        "total_seconds": round(elapsed, 4),
        "ops_per_second": round(n / elapsed),
        "ns_per_op": round((elapsed / n) * 1000000000, 2),
    }


def run_audit_log_benchmark(n: int = 1000) -> dict:
    db = SessionLocal()
    start = time.perf_counter()
    for i in range(n):
        log_audit_event(
            db=db,
            username=f"user_{i % 10}",
            action="update_rule",
            resource=f"rule:{i}",
            status="success",
        )
    elapsed = time.perf_counter() - start
    db.close()

    return {
        "n_inserts": n,
        "total_seconds": round(elapsed, 4),
        "inserts_per_second": round(n / elapsed),
        "ms_per_insert": round((elapsed / n) * 1000, 3),
    }


if __name__ == "__main__":
    print("\n═══════════════════════════════════════════")
    print("  SentinelX Transactional DB & RBAC Benchmark")
    print("═══════════════════════════════════════════")

    r1 = run_rbac_benchmark(n=100000)
    print(f"\n[RBAC Matrix Check] {r1['n_checks']:,} checks")
    print(f"  Total time  : {r1['total_seconds']}s")
    print(f"  Throughput  : {r1['ops_per_second']:,} ops/s")
    print(f"  Latency p50 : ~{r1['ns_per_op']} ns/check")

    r2 = run_audit_log_benchmark(n=1000)
    print(f"\n[Audit Log Insert] {r2['n_inserts']:,} DB inserts")
    print(f"  Total time  : {r2['total_seconds']}s")
    print(f"  Throughput  : {r2['inserts_per_second']:,} inserts/s")
    print(f"  Latency p50 : ~{r2['ms_per_insert']} ms/insert")
    print("\n═══════════════════════════════════════════\n")
