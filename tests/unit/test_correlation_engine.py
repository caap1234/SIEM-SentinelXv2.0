import pytest
from datetime import datetime, timezone

from app.services.correlation_engine import CorrelationEngine
from app.schemas.detection_rule import DetectionRule
from app.schemas.normalized_event import NormalizedEvent, EventMeta, TenantMeta, SourceMeta, ServiceMeta


def test_correlation_engine_triggers_alert_at_threshold():
    rule = DetectionRule(
        id="TEST_BRUTEFORCE",
        name="Test SSH Bruteforce",
        description="Test description",
        event_conditions={"service.name": "sshd", "event.action": "login_failed"},
        group_by=["source.ip"],
        threshold=3,
        time_window_seconds=60,
    )

    engine = CorrelationEngine(rules=[rule])

    # Send 2 events (below threshold)
    for i in range(2):
        ev = NormalizedEvent(
            tenant=TenantMeta(id="tenant-1"),
            event=EventMeta(id=f"evt-{i}", action="login_failed"),
            service=ServiceMeta(name="sshd"),
            source=SourceMeta(ip="198.51.100.9"),
        )
        alerts = engine.process_event(ev)
        assert len(alerts) == 0

    # Send 3rd event (hits threshold = 3)
    ev_3 = NormalizedEvent(
        tenant=TenantMeta(id="tenant-1"),
        event=EventMeta(id="evt-2", action="login_failed"),
        service=ServiceMeta(name="sshd"),
        source=SourceMeta(ip="198.51.100.9"),
    )
    alerts = engine.process_event(ev_3)
    assert len(alerts) == 1

    alert = alerts[0]
    assert alert["rule_id"] == "TEST_BRUTEFORCE"
    assert alert["tenant_id"] == "tenant-1"
    assert alert["trigger_count"] == 3
    assert alert["group_key"] == "198.51.100.9"
    assert len(alert["related_event_ids"]) == 3


def test_correlation_engine_tenant_isolation():
    rule = DetectionRule(
        id="TEST_ISOLATION",
        name="Test Isolation",
        description="Test",
        event_conditions={"service.name": "exim"},
        group_by=["source.ip"],
        threshold=2,
        time_window_seconds=60,
    )

    engine = CorrelationEngine(rules=[rule])

    # Event for Tenant A
    ev_a = NormalizedEvent(
        tenant=TenantMeta(id="tenant-A"),
        event=EventMeta(id="evt-a"),
        service=ServiceMeta(name="exim"),
        source=SourceMeta(ip="1.1.1.1"),
    )
    # Event for Tenant B
    ev_b = NormalizedEvent(
        tenant=TenantMeta(id="tenant-B"),
        event=EventMeta(id="evt-b"),
        service=ServiceMeta(name="exim"),
        source=SourceMeta(ip="1.1.1.1"),
    )

    assert len(engine.process_event(ev_a)) == 0
    assert len(engine.process_event(ev_b)) == 0  # Tenant B has 1 event, not 2


@pytest.mark.asyncio
async def test_correlation_engine_distributed_kv_support():
    from unittest.mock import AsyncMock
    rule = DetectionRule(
        id="TEST_KV_BRUTEFORCE",
        name="Test KV Bruteforce",
        description="KV test",
        event_conditions={"service.name": "exim", "event.action": "auth_failed"},
        group_by=["source.ip"],
        threshold=50,
        time_window_seconds=300,
    )
    engine = CorrelationEngine(rules=[rule])

    # Simulación de tienda KV en memoria
    kv_data = {}

    class MockKV:
        async def get(self, key):
            if key in kv_data:
                m = AsyncMock()
                m.value = kv_data[key]
                return m
            return None

        async def put(self, key, value):
            kv_data[key] = value

    mock_kv = MockKV()

    # Enviar 49 eventos a través de workers simulados
    for i in range(49):
        ev = NormalizedEvent(
            tenant=TenantMeta(id="default"),
            event=EventMeta(id=f"evt-{i}", action="auth_failed"),
            service=ServiceMeta(name="exim"),
            source=SourceMeta(ip="198.51.100.45"),
        )
        alerts = await engine.process_event_async(ev, kv_store=mock_kv)
        assert len(alerts) == 0

    # Evento 50 (alcanza el umbral exacto = 50)
    ev_50 = NormalizedEvent(
        tenant=TenantMeta(id="default"),
        event=EventMeta(id="evt-50", action="auth_failed"),
        service=ServiceMeta(name="exim"),
        source=SourceMeta(ip="198.51.100.45"),
    )
    alerts = await engine.process_event_async(ev_50, kv_store=mock_kv)
    assert len(alerts) == 1
    assert alerts[0]["trigger_count"] == 50
    assert alerts[0]["rule_id"] == "TEST_KV_BRUTEFORCE"
