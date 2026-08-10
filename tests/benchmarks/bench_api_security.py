#!/usr/bin/env python3
"""
Benchmark de rendimiento para la capa de seguridad API, autenticación y RBAC (v1).
Mide velocidad de hashing de API keys, resolución de AuthContext y evaluación RBAC.
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
from app.models.agent_api_key import AgentApiKey
from app.services.agent_api_key_service import create_agent_api_key, validate_agent_api_key
from app.schemas.dependencies import AuthContext, require_permission
from app.core.rbac import ROLE_ANALYST, PERM_ALERTS_READ

engine = create_engine("sqlite:///:memory:")
Tenant.__table__.create(bind=engine, checkfirst=True)
AgentApiKey.__table__.create(bind=engine, checkfirst=True)
SessionLocal = sessionmaker(bind=engine)


def run_api_key_validation_benchmark(n: int = 2000) -> dict:
    db = SessionLocal()
    raw_key, record = create_agent_api_key(db, name="bench-key", tenant_id="tenant-bench")

    start = time.perf_counter()
    for _ in range(n):
        rec = validate_agent_api_key(db, raw_key)
        assert rec is not None
    elapsed = time.perf_counter() - start
    db.close()

    return {
        "n_validations": n,
        "total_seconds": round(elapsed, 4),
        "validations_per_second": round(n / elapsed),
        "ms_per_validation": round((elapsed / n) * 1000, 4),
    }


def run_permission_dependency_benchmark(n: int = 100000) -> dict:
    checker = require_permission(PERM_ALERTS_READ)
    ctx = AuthContext(username="analyst_1", role=ROLE_ANALYST, tenant_id="tenant-bench")

    start = time.perf_counter()
    for _ in range(n):
        res = checker(ctx=ctx)
        assert res.tenant_id == "tenant-bench"
    elapsed = time.perf_counter() - start

    return {
        "n_checks": n,
        "total_seconds": round(elapsed, 4),
        "checks_per_second": round(n / elapsed),
        "ns_per_check": round((elapsed / n) * 1000000000, 2),
    }


if __name__ == "__main__":
    print("\n═══════════════════════════════════════════")
    print("  SentinelX API Security & RBAC Benchmark")
    print("═══════════════════════════════════════════")

    r1 = run_api_key_validation_benchmark(n=2000)
    print(f"\n[Agent API Key DB Validation] {r1['n_validations']:,} validations")
    print(f"  Total time     : {r1['total_seconds']}s")
    print(f"  Throughput     : {r1['validations_per_second']:,} val/s")
    print(f"  Latency p50    : ~{r1['ms_per_validation']} ms/val")

    r2 = run_permission_dependency_benchmark(n=100000)
    print(f"\n[RBAC Dependency Check] {r2['n_checks']:,} checks")
    print(f"  Total time     : {r2['total_seconds']}s")
    print(f"  Throughput     : {r2['checks_per_second']:,} checks/s")
    print(f"  Latency p50    : ~{r2['ns_per_check']} ns/check")
    print("\n═══════════════════════════════════════════\n")
