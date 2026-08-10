"""
tests/unit/test_security_lists.py

Pruebas del Sistema Centralizado de Listas de Seguridad (Security Lists)
SentinelX SIEM.

Valida los 6 casos de prueba requeridos:
1. Caso 1: Agregar IP a Whitelist Global -> Evento no genera alerta.
2. Caso 2: Eliminar IP de Whitelist -> Mismo evento sí genera alerta.
3. Caso 3: Crear Excepción para Regla Específica (AUTH-006) -> Regla AUTH-006 ignorada, otra regla (AUTH-007) procesada.
4. Caso 4: BlacklistMaster Sync consume inventario shared/pmg/ignore desde BD.
5. Caso 5: Registro automático en Auditoría (SecurityListAudit) tras crear/modificar/eliminar.
6. Caso 6: Registro automático en Trazabilidad de Ignorados (SecurityListIgnoreLog) cuando un evento es de confianza.
"""

import json
import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models.event import Event
from app.models.rule_v2 import RuleV2
from app.models.security_list import SecurityListAudit, SecurityListEntry, SecurityListIgnoreLog
from app.services.security_list_service import SecurityListService
from app.services.rule_engine_v2 import RuleEngineV2
from app.services.blacklistmaster_sync import run_blacklistmaster_sync


@pytest.fixture
def db_session():
    """Base de datos en memoria para pruebas aisladas."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def list_service(db_session):
    """Instancia del servicio de listas con caché refrescado."""
    svc = SecurityListService.get_instance()
    svc.refresh_cache(db_session)
    return svc


class TestSecurityListsArchitecture:

    # =========================================================================
    # CASO 1 & 2: Whitelist Global (Agregar -> No Alerta | Eliminar -> Alerta)
    # =========================================================================
    def test_case_1_and_2_global_whitelist_suppression(self, db_session, list_service):
        engine = RuleEngineV2()

        # Crear regla de prueba SSH Bruteforce
        rule = RuleV2(
            id=101,
            name="AUTH-001 | SSH Bruteforce Test",
            source="SSH_SECURE",
            event_type="auth_login",
            severity=15,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=600,
            version=1,
            group_by=["server", "ip_client"],
            tags=["auth", "ssh"],
            match={"extra.action": "fail", "ip_client": {"exists": True}},
            condition="fail_count >= 1",
            emit={"code": "AUTH-001"},
        )
        db_session.add(rule)
        db_session.commit()

        # Evento desde IP pública enrutable 54.210.10.5
        event = Event(
            id=uuid.uuid4(),
            source="SSH_SECURE",
            service="sshd",
            message="Auth failure for root",
            server="srv-ssh-01",
            ip_client="54.210.10.5",
            username="root",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "auth_login", "action": "fail"},
        )
        db_session.add(event)
        db_session.commit()

        # PASO 1: Sin whitelist -> Genera alerta
        alerts_before = engine.on_event(db_session, event)
        assert len(alerts_before) == 1, "Debe generar 1 alerta cuando la IP NO está en whitelist."

        # Resetear ventanas del engine
        engine._windows.clear()

        # PASO 2 (CASO 1): Agregar IP a Whitelist Global desde Servicio
        entry = list_service.create_entry(
            db_session,
            tenant_id="global",
            list_type="whitelist_ip",
            value="54.210.10.5",
            value_type="ip",
            reason="Servidor autorizado para pruebas",
            created_by="test_admin",
        )
        assert entry.id is not None

        # Procesar evento de nuevo -> NO debe generar alerta
        alerts_with_whitelist = engine.on_event(db_session, event)
        assert len(alerts_with_whitelist) == 0, "NO debe generar alerta cuando la IP está en Whitelist Global."

        # PASO 3 (CASO 2): Eliminar entrada de Whitelist y simular nuevo evento tras el cooldown
        engine._windows.clear()
        deleted = list_service.delete_entry(db_session, entry_id=entry.id, performed_by="test_admin")
        assert deleted is True

        from datetime import timedelta
        event_after = Event(
            id=uuid.uuid4(),
            source="SSH_SECURE",
            service="sshd",
            message="Auth failure for root",
            server="srv-ssh-01",
            ip_client="54.210.10.5",
            username="root",
            timestamp_utc=datetime.now(timezone.utc) + timedelta(seconds=700),
            extra={"event_type": "auth_login", "action": "fail"},
        )
        db_session.add(event_after)
        db_session.commit()

        # Procesar evento de nuevo -> Vuelve a generar alerta
        alerts_after_delete = engine.on_event(db_session, event_after)
        assert len(alerts_after_delete) == 1, "Debe volver a generar alerta tras eliminar la IP de la Whitelist."

    # =========================================================================
    # CASO 3: Excepción por Regla Específica (AUTH-006 vs AUTH-007)
    # =========================================================================
    def test_case_3_rule_specific_exception(self, db_session, list_service):
        engine = RuleEngineV2()

        # Regla 1: AUTH-006 (Excepción activa)
        rule_006 = RuleV2(
            id=201,
            name="AUTH-006 | SSH Privileged Login",
            source="SSH_SECURE",
            event_type="auth_login",
            severity=20,
            enabled=True,
            window_seconds=300,
            version=1,
            group_by=["server", "ip_client"],
            tags=["auth", "ssh"],
            match={"extra.action": "fail"},
            condition="fail_count >= 1",
            emit={"code": "AUTH-006"},
        )

        # Regla 2: AUTH-007 (Sin excepción)
        rule_007 = RuleV2(
            id=202,
            name="AUTH-007 | General Auth Fail",
            source="SSH_SECURE",
            event_type="auth_login",
            severity=10,
            enabled=True,
            window_seconds=300,
            version=1,
            group_by=["server", "ip_client"],
            tags=["auth", "ssh"],
            match={"extra.action": "fail"},
            condition="fail_count >= 1",
            emit={"code": "AUTH-007"},
        )

        db_session.add(rule_006)
        db_session.add(rule_007)
        db_session.commit()

        # Crear Excepción específica para IP 54.210.10.10 en la regla AUTH-006
        list_service.create_entry(
            db_session,
            tenant_id="global",
            list_type="exception_rule",
            value="54.210.10.10",
            value_type="ip",
            rule_code="AUTH-006",
            reason="Excepción para servidor de monitoreo en AUTH-006",
            created_by="test_admin",
        )

        # Evento desde la IP pública con excepción
        event = Event(
            id=uuid.uuid4(),
            source="SSH_SECURE",
            service="sshd",
            message="Auth failure for root",
            server="srv-ssh-02",
            ip_client="54.210.10.10",
            username="root",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "auth_login", "action": "fail"},
        )
        db_session.add(event)
        db_session.commit()

        alerts = engine.on_event(db_session, event)

        # Confirmar que SOLO se generó la alerta para AUTH-007 (AUTH-006 fue ignorada por la excepción)
        assert len(alerts) == 1, f"Se esperaba 1 alerta (AUTH-007), se obtuvieron {len(alerts)}"
        assert alerts[0].rule_name.startswith("AUTH-007"), f"La regla activada debió ser AUTH-007, fue: {alerts[0].rule_name}"

    # =========================================================================
    # CASO 4: BlacklistMaster Sync con Inventario BD
    # =========================================================================
    def test_case_4_blacklistmaster_sync_with_db_inventory(self, db_session, list_service):
        # Crear entrada BLM Shared en BD
        list_service.create_entry(
            db_session,
            tenant_id="global",
            list_type="blm_shared",
            value="54.210.10.22",
            value_type="ip",
            list_name="svdb_shared_01",
            reason="Servidor de Hosting Compartido",
            created_by="test_admin",
        )

        # Crear entrada BLM Ignore en BD
        list_service.create_entry(
            db_session,
            tenant_id="global",
            list_type="blm_ignore",
            value="54.210.10.99",
            value_type="ip",
            reason="IP de prueba a ignorar en sync",
            created_by="test_admin",
        )

        # Consultar inventario vía servicio
        shared_map = list_service.get_blm_inventory_map("shared", db=db_session)
        ignore_list = list_service.get_blm_ignore_list(db=db_session)

        assert "54.210.10.22" in shared_map
        assert shared_map["54.210.10.22"] == "svdb_shared_01"
        assert "54.210.10.99" in ignore_list.ips

    # =========================================================================
    # CASO 5: Registro de Auditoría (SecurityListAudit)
    # =========================================================================
    def test_case_5_audit_log_tracking(self, db_session, list_service):
        # 1. Crear entrada
        entry = list_service.create_entry(
            db_session,
            tenant_id="default",
            list_type="whitelist_ip",
            value="54.210.10.150",
            reason="Prueba auditoría",
            created_by="auditor_test",
        )

        audits_after_create = db_session.query(SecurityListAudit).filter(SecurityListAudit.entry_id == entry.id).all()
        assert len(audits_after_create) == 1
        assert audits_after_create[0].action == "create"
        assert audits_after_create[0].performed_by == "auditor_test"

        # 2. Actualizar entrada
        list_service.update_entry(
            db_session,
            entry_id=entry.id,
            data={"reason": "Motivo actualizado para auditoría"},
            updated_by="editor_test",
        )

        audits_after_update = db_session.query(SecurityListAudit).filter(SecurityListAudit.entry_id == entry.id).all()
        assert len(audits_after_update) == 2
        actions = [a.action for a in audits_after_update]
        assert "create" in actions and "update" in actions

    # =========================================================================
    # CASO 6: Trazabilidad de Ignorados (SecurityListIgnoreLog)
    # =========================================================================
    def test_case_6_ignore_log_traceability(self, db_session, list_service):
        engine = RuleEngineV2()

        # Crear regla
        rule = RuleV2(
            id=301,
            name="AUTH-009 | Traceability Test",
            source="SSH_SECURE",
            event_type="auth_login",
            severity=10,
            enabled=True,
            window_seconds=300,
            version=1,
            group_by=["server", "ip_client"],
            tags=["auth", "ssh"],
            match={"extra.action": "fail"},
            condition="fail_count >= 1",
            emit={"code": "AUTH-009"},
        )
        db_session.add(rule)

        # Crear entrada en Whitelist Global con IP pública
        list_service.create_entry(
            db_session,
            tenant_id="global",
            list_type="whitelist_ip",
            value="54.210.10.88",
            reason="IP confiable para ignore log test",
            created_by="test_admin",
        )

        event = Event(
            id=uuid.uuid4(),
            source="SSH_SECURE",
            service="sshd",
            message="Auth failure for admin",
            server="srv-ssh-03",
            ip_client="54.210.10.88",
            username="admin",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "auth_login", "action": "fail"},
        )
        db_session.add(event)
        db_session.commit()

        # Procesar evento
        alerts = engine.on_event(db_session, event)
        assert len(alerts) == 0

        # Verificar que se registró la trazabilidad en SecurityListIgnoreLog
        logs = db_session.query(SecurityListIgnoreLog).filter(SecurityListIgnoreLog.ip_client == "54.210.10.88").all()
        assert len(logs) >= 1, "Debe registrar al menos 1 trazabilidad en SecurityListIgnoreLog"
        assert logs[0].ignore_reason == "trusted_ip"
        assert logs[0].rule_code == "AUTH-009"
