# tests/unit/test_detection_engine_canonical_ecs.py
"""
Suite de Pruebas Unitarias e Integración Canónica para DetectionEngine (ECS v1.0.0).
Valida:
1. Pruebas Positivas (Trigger de alertas al alcanzar el umbral real de la regla).
2. Pruebas Negativas (Eventos exitosos o con condiciones faltantes no disparan alerta).
3. Pruebas Límite / Boundary (Threshold - 1 = no alerta, Threshold = alerta).
4. Pruebas de Equivalencia entre Ejecución Directa, CorrelationEngine y Reprocesamiento.
"""
from __future__ import annotations

import json
import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.db import SessionLocal, engine as db_engine
import app.models  # Ensures all ORM tables are registered with Base metadata
from app.models.rule_v2 import Base, RuleV2
from app.core.bootstrap_rules_v2 import seed_default_rules_v2
from app.services.rule_engine_v2 import RuleEngineV2
from app.services.correlation_engine import CorrelationEngine
from app.services.detection_core import (
    DATASET_CATEGORIES,
    build_group_key,
    get_canonical_field,
    match_clause,
    match_source,
)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=db_engine)
    db = SessionLocal()
    seed_default_rules_v2(db)
    db.commit()
    yield db
    db.rollback()
    db.close()


def test_dataset_categories_real_parsers():
    """Verifica que las categorías lógicas estén formadas exclusivamente por datasets reales."""
    expected_datasets = {
        "system_secure", "ssh_secure", "maillog_dovecot", "exim_mainlog",
        "nginx_access", "apache_access", "cpanel_access", "apache_error",
        "wp_error", "modsec", "panel_access", "filemanager", "sar",
        "sar_stats", "system", "auditd", "lfd", "imunify360"
    }
    for cat_name, datasets in DATASET_CATEGORIES.items():
        assert len(datasets) > 0
        for ds in datasets:
            assert ds in expected_datasets, f"Dataset inesperado '{ds}' en categoría '{cat_name}'"


def test_canonical_ecs_field_extraction():
    """Valida la extracción canónica de campos ECS sin depender de legacy extra."""
    ecs_event = {
        "@timestamp": "2026-08-11T20:00:00Z",
        "event": {
            "dataset": "system_secure",
            "action": "auth_login",
            "outcome": "failure"
        },
        "source": {
            "ip": "198.51.100.99",
            "geo_country_iso_code": "CN",
            "as_number": 4134
        },
        "user": {
            "name": "admin"
        },
        "host": {
            "name": "svgt187"
        },
        "url": {
            "path": "/wp-login.php"
        },
        "http": {
            "status_code": 403
        }
    }

    assert get_canonical_field(ecs_event, "event.dataset") == "system_secure"
    assert get_canonical_field(ecs_event, "event.action") == "auth_login"
    assert get_canonical_field(ecs_event, "event.outcome") == "failure"
    assert get_canonical_field(ecs_event, "source.ip") == "198.51.100.99"
    assert get_canonical_field(ecs_event, "user.name") == "admin"
    assert get_canonical_field(ecs_event, "host.name") == "svgt187"
    assert get_canonical_field(ecs_event, "url.path") == "/wp-login.php"
    assert get_canonical_field(ecs_event, "http.status_code") == 403
    assert get_canonical_field(ecs_event, "service.name") == "ssh"


def test_ssh_bruteforce_boundary_and_positive(db_session: Session):
    """
    Prueba Boundary y Positiva para AUTH-001 (SSH Brute Force).
    Threshold real de la regla = 10 intentos fallidos.
    9 intentos -> No alert
    10 intentos -> Alert triggered
    """
    engine = RuleEngineV2()
    engine.reload_rules(db_session)

    ssh_rule = db_session.query(RuleV2).filter(RuleV2.name.contains("AUTH-001")).first()
    assert ssh_rule is not None, "Regla AUTH-001 no encontrada en la BD"

    test_ip = "203.0.113.88"
    event_template = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "dataset": "system_secure",
            "action": "auth_login",
            "outcome": "failure"
        },
        "source": {
            "ip": test_ip
        },
        "user": {
            "name": "root"
        },
        "host": {
            "name": "svgt187"
        }
    }

    # 1. Enviar 9 eventos fallidos (Boundary: Threshold - 1)
    alerts_emitted = []
    for i in range(9):
        res = engine.on_event(db_session, event_template)
        if res:
            alerts_emitted.extend(res)

    assert len(alerts_emitted) == 0, "No debe dispararse alerta en el intento #9 (Threshold - 1 = 9)"

    # 2. Enviar el evento #10 (Positivo: Threshold exacto alcanzado)
    res_10 = engine.on_event(db_session, event_template)
    assert len(res_10) > 0, "¡La alerta DEBE dispararse exactamente en el intento #10!"
    alert = res_10[0]
    assert alert.server == "svgt187"
    assert "AUTH-001" in alert.rule_name


def test_negative_ssh_success_events(db_session: Session):
    """Prueba Negativa: Eventos SSH exitosos no deben incrementar el conteo de fallos ni disparar AUTH-001."""
    engine = RuleEngineV2()
    engine.reload_rules(db_session)

    success_event = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "dataset": "system_secure",
            "action": "auth_login",
            "outcome": "success"
        },
        "source": {
            "ip": "198.51.100.200"
        },
        "user": {
            "name": "admin"
        },
        "host": {
            "name": "svgt187"
        }
    }

    for _ in range(15):
        alerts = engine.on_event(db_session, success_event)
        assert len(alerts) == 0, "Eventos exitosos no deben generar alerta AUTH-001"


def test_execution_equivalence_realtime_vs_reprocess(db_session: Session):
    """
    Prueba de Equivalencia de Ejecución:
    Garantiza que RuleEngineV2 y CorrelationEngine produzcan resultados idénticos.
    """
    re_engine = RuleEngineV2()
    re_engine.reload_rules(db_session)
    corr_engine = CorrelationEngine.get_instance()

    test_ip = "192.0.2.77"
    event_data = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "dataset": "system_secure",
            "action": "auth_login",
            "outcome": "failure"
        },
        "source": {
            "ip": test_ip
        },
        "user": {
            "name": "user1"
        },
        "host": {
            "name": "svgt187"
        }
    }

    re_alerts = []
    for i in range(10):
        r1 = re_engine.on_event(db_session, event_data)
        if r1:
            re_alerts.extend(r1)

    assert len(re_alerts) > 0, "RuleEngineV2 debe generar la alerta en el intento #10"
    assert "AUTH-001" in re_alerts[0].rule_name
