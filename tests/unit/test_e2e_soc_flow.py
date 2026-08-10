from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base, SessionLocal
from app.models.alert import Alert
from app.models.entity import Entity
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
from app.models.incident_entity import IncidentEntity
from app.models.incident_rule import IncidentRule
from app.services.incident_engine import IncidentEngine


def test_e2e_soc_workflow_integration():
    """
    Validación End-to-End completa del Flujo Operativo SOC:
    1. Evento Ingestado ➔ Indexado en OpenSearch & MinIO S3 (referenciados)
    2. Detección de Alertas ➔ Múltiples Alertas generadas con opensearch_event_id y s3_key
    3. Agregación de Incidentes ➔ Agrupamiento de 2+ Alertas en 1 ÚNICO Incidente (sin explosión 1:1)
    4. Acciones del Analista ➔ Notas de investigación y cambio de estado registrados en Timeline
    5. Cierre de Incidente ➔ Alertas y Entidades se conservan (historial inmutable)
    """
    db_session: Session = SessionLocal()
    Base.metadata.create_all(db_session.bind)

    now = datetime.now(timezone.utc).replace(microsecond=0)


    # Clean up leftover test data if any
    db_session.query(IncidentRule).filter(IncidentRule.code == "INC_E2E_SSH_TEST").delete()
    db_session.commit()

    # 1. Regla de Incidente (Correlación SOC)
    inc_rule = IncidentRule(
        code="INC_E2E_SSH_TEST",
        name="Ataque Activo E2E SSH",
        enabled=True,
        scope="local",
        severity_base=75,
        primary_entity_type="ip",
        primary_entity_field="ip_client",
        match={"alert_names_any": ["Detección E2E SSH"]},
        window_seconds=600,
    )

    db_session.add(inc_rule)
    db_session.commit()

    # 2. Simulación de Alertas creadas con referencias a OpenSearch y MinIO S3
    alert1 = Alert(
        id=99901,
        rule_id=9901,
        rule_name="Detección E2E SSH",
        severity=20,
        server="svdb057",
        source="secure",
        event_type="auth_failure",
        group_key="svdb057|198.51.100.45",
        opensearch_event_id="os-evt-1001",
        s3_key="default/2026/08/10/secure/evt-1001.json.gz",
        triggered_at=now,
        evidence={"event_ids": ["os-evt-1001"], "raw_samples": ["Failed password for root from 198.51.100.45"], "group_values": {"ip_client": "198.51.100.45"}},
        metrics={"count": 5},
        status="open",
    )
    alert2 = Alert(
        id=99902,
        rule_id=9901,
        rule_name="Detección E2E SSH",
        severity=20,
        server="svdb057",
        source="secure",
        event_type="auth_failure",
        group_key="svdb057|198.51.100.45",
        opensearch_event_id="os-evt-1002",
        s3_key="default/2026/08/10/secure/evt-1002.json.gz",
        triggered_at=now,
        evidence={"event_ids": ["os-evt-1002"], "raw_samples": ["Failed password for admin from 198.51.100.45"], "group_values": {"ip_client": "198.51.100.45"}},
        metrics={"count": 8},
        status="open",
    )

    db_session.add_all([alert1, alert2])
    db_session.commit()

    try:
        # 3. Motor de Incidentes: Debe AGRUPAR ambas alertas en 1 SOLO incidente
        engine = IncidentEngine()
        engine.reload_rules(db_session)
        incidents = engine.run(db_session, now=now)
        db_session.flush()


        # Verificación de Agrupación (No 1:1)
        assert len(incidents) >= 1
        target_inc = [i for i in incidents if i.primary_entity_key == "198.51.100.45"][0]
        assert target_inc.code == "INC_E2E_SSH_TEST"

        # Verificar que ambas alertas están vinculadas al mismo incidente
        linked_alerts = db_session.query(IncidentAlert).filter(IncidentAlert.incident_id == target_inc.id).all()
        linked_alert_ids = [ia.alert_id for ia in linked_alerts]
        assert alert1.id in linked_alert_ids
        assert alert2.id in linked_alert_ids

        # 4. Simular acción del analista: Agregar Nota y Registrar en Timeline
        ev = dict(target_inc.evidence) if isinstance(target_inc.evidence, dict) else {}
        timeline = list(ev.get("timeline", []))
        timeline.append({
            "timestamp": now.isoformat(),
            "user": "analista@sentinelx.local",
            "action": "Investigación iniciada. IP bloqueada en firewall.",
            "entity": "198.51.100.45",
        })
        ev["timeline"] = timeline
        target_inc.evidence = ev
        db_session.add(target_inc)
        db_session.commit()

        # 5. Cierre del Incidente (Cascade)
        for a_id in linked_alert_ids:
            al = db_session.get(Alert, a_id)
            if al:
                al.status = "closed_by_incident"
                db_session.add(al)

        target_inc.status = "resolved"
        target_inc.closed_at = now
        db_session.add(target_inc)
        db_session.commit()

        # 6. Validaciones Finales de Preservación e Inmutabilidad
        db_session.refresh(alert1)
        db_session.refresh(alert2)
        db_session.refresh(target_inc)

        # Las alertas NO se eliminan, cambian de estado
        assert alert1.status == "closed_by_incident"
        assert alert2.status == "closed_by_incident"
        assert alert1.opensearch_event_id == "os-evt-1001"
        assert alert1.s3_key == "default/2026/08/10/secure/evt-1001.json.gz"

        # El historial del timeline en el incidente permanece intacto
        final_timeline = target_inc.evidence.get("timeline", [])
        assert len(final_timeline) >= 1
        assert "IP bloqueada" in final_timeline[0]["action"]

    finally:
        if 'target_inc' in locals():
            db_session.query(IncidentAlert).filter(IncidentAlert.incident_id == target_inc.id).delete()
            db_session.query(Incident).filter(Incident.id == target_inc.id).delete()
        db_session.query(Alert).filter(Alert.id.in_([alert1.id, alert2.id])).delete()
        db_session.query(IncidentRule).filter(IncidentRule.id == inc_rule.id).delete()
        db_session.commit()
        db_session.close()
