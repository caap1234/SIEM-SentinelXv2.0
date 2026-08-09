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
