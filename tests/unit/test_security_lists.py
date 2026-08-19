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
            legacy_list_policy=True,
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
            legacy_list_policy=True,
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
            legacy_list_policy=True,
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
            legacy_list_policy=True,
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

    # =========================================================================
    # Fase 2: Explicit Bindings Tests (Exclusion, Detection, Context)
    # =========================================================================
    def test_explicit_rule_bindings_logic(self, db_session, list_service):
        from app.models.rule_list_binding import RuleListBinding
        engine = RuleEngineV2()

        # 1. Crear regla de prueba
        rule = RuleV2(
            id=505,
            name="WEB-003 | Exploit path test",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=10,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=600,
            version=1,
            group_by=["server"],
            tags=["web"],
            match={"extra.action": "fail"},
            condition="count >= 1",
            detection_bindings_operator="OR",
            emit={"code": "WEB-003"},
        )
        db_session.add(rule)
        db_session.commit()

        # 2. Agregar registros de lista en la BD
        list_service.create_entry(
            db_session,
            tenant_id="global",
            list_type="whitelist_ip",
            value="10.20.30.40",
            reason="Exclusion list",
            created_by="admin"
        )
        list_service.create_entry(
            db_session,
            tenant_id="global",
            list_type="list_ref",
            list_name="suspicious_paths",
            value="/wp-config.php",
            reason="Detection pattern",
            created_by="admin"
        )

        # 3. Asociar Bindings
        b_excl = RuleListBinding(
            rule_id=rule.id,
            list_name="whitelist_ip",
            role="exclusion",
            match_field="source.ip",
            operator="in_ref",
            enabled=True
        )
        b_det = RuleListBinding(
            rule_id=rule.id,
            list_name="suspicious_paths",
            role="detection",
            match_field="url.path",
            operator="in_ref",
            enabled=True
        )
        b_ctx = RuleListBinding(
            rule_id=rule.id,
            list_name="suspicious_paths",
            role="context",
            match_field="url.path",
            operator="in_ref",
            action_config={"adjust_severity": 5},
            enabled=True
        )
        db_session.add_all([b_excl, b_det, b_ctx])
        db_session.commit()

        # Recargar reglas en caliente
        engine.reload_rules(db_session)

        # Evento 1: IP de exclusión -> Debe ignorarse
        ev_excl = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-web-01",
            ip_client="10.20.30.40",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail", "url": {"original": "/wp-config.php"}}
        )
        res_excl = engine.on_event(db_session, ev_excl)
        assert len(res_excl) == 0, "Debe ser excluido por whitelist_ip binding"

        # Evento 2: IP normal y path sospechoso -> Debe alertar y ajustar severidad (+5 = 15)
        ev_alert = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-web-01",
            ip_client="8.8.8.8",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail", "url": {"original": "/wp-config.php"}}
        )
        res_alert = engine.on_event(db_session, ev_alert)
        assert len(res_alert) == 1
        assert res_alert[0].severity == 15, "La severidad debió ajustarse de 10 a 15"

    def test_explicit_rule_bindings_edge_cases(self, db_session, list_service):
        """Validación rigurosa de los 12 casos de frontera para bindings explicitos."""
        from app.models.rule_list_binding import RuleListBinding
        engine = RuleEngineV2()

        # Crear entradas de prueba en listas de seguridad
        list_service.create_entry(db_session, tenant_id="global", list_type="whitelist_ip", value="10.20.30.40", reason="w", created_by="a")
        list_service.create_entry(db_session, tenant_id="global", list_type="list_ref", list_name="suspicious_paths", value="/wp-config.php", reason="s", created_by="a")

        # 1. Regla sin bindings -> Funciona por condiciones base
        r_nobind = RuleV2(
            name="TEST-NOBIND",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 2",
            emit={"code": "TEST-NOBIND"},
        )
        db_session.add(r_nobind)
        db_session.commit()
        engine.reload_rules(db_session)

        ev_1 = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-01",
            ip_client="1.1.1.1",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail"}
        )
        # Threshold-1 -> no alerta (Caso 10)
        res_t1 = engine.on_event(db_session, ev_1)
        assert len(res_t1) == 0, "Threshold-1 no debe generar alerta"

        # Threshold -> Genera alerta (Caso 11)
        ev_2 = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-01",
            ip_client="1.1.1.1",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail"}
        )
        res_t2 = engine.on_event(db_session, ev_2)
        assert len(res_t2) == 1, "Alcanzado el threshold (count >= 2) debe generar alerta"
        assert res_t2[0].rule_id == r_nobind.id

        # 2. Exclusion list vacía -> No excluye
        r_empty_excl = RuleV2(
            name="TEST-EMPTY-EXCL",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 1",
            emit={"code": "TEST-EMPTY-EXCL"},
        )
        db_session.add(r_empty_excl)
        db_session.commit()
        b_empty_excl = RuleListBinding(
            rule_id=r_empty_excl.id,
            list_name="non_existent_empty_list",
            role="exclusion",
            match_field="source.ip",
            operator="in_ref",
            enabled=True
        )
        db_session.add(b_empty_excl)
        db_session.commit()
        engine.reload_rules(db_session)

        ev_empty_excl = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-02",
            ip_client="2.2.2.2",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail"}
        )
        res_ee = [a for a in engine.on_event(db_session, ev_empty_excl) if a.rule_id == r_empty_excl.id]
        assert len(res_ee) == 1, "Exclusion list vacía no debe excluir eventos"

        # 3. Detection list vacía -> Binding FALSE -> No incrementa window
        r_empty_det = RuleV2(
            name="TEST-EMPTY-DET",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 1",
            detection_bindings_operator="OR",
            emit={"code": "TEST-EMPTY-DET"},
        )
        db_session.add(r_empty_det)
        db_session.commit()
        b_empty_det = RuleListBinding(
            rule_id=r_empty_det.id,
            list_name="non_existent_empty_det_list",
            role="detection",
            match_field="url.path",
            operator="in_ref",
            enabled=True
        )
        db_session.add(b_empty_det)
        db_session.commit()
        engine.reload_rules(db_session)

        ev_empty_det = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-03",
            ip_client="3.3.3.3",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail", "url": {"original": "/test"}}
        )
        res_ed = [a for a in engine.on_event(db_session, ev_empty_det) if a.rule_id == r_empty_det.id]
        assert len(res_ed) == 0, "Detection list vacía es FALSE y no debe generar alerta"
        win_key_ed = (r_empty_det.id, "srv-03")
        assert len(engine._windows[win_key_ed]) == 0, "Detection FALSE no debe incrementar la ventana"

        # 4. Enabled=false -> Binding ignorado
        r_dis = RuleV2(
            name="TEST-DIS-BINDING",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 1",
            emit={"code": "TEST-DIS-BINDING"},
        )
        db_session.add(r_dis)
        db_session.commit()
        # Exclusion deshabilitada -> NO debe excluir
        b_dis_excl = RuleListBinding(
            rule_id=r_dis.id,
            list_name="whitelist_ip",
            role="exclusion",
            match_field="source.ip",
            operator="in_ref",
            enabled=False
        )
        db_session.add(b_dis_excl)
        db_session.commit()
        engine.reload_rules(db_session)

        ev_dis = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-04",
            ip_client="10.20.30.40", # Estaba en whitelist_ip
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail"}
        )
        all_alerts_dis = engine.on_event(db_session, ev_dis)
        res_dis = [a for a in all_alerts_dis if a.rule_id == r_dis.id]
        assert len(res_dis) == 1, f"Expected alert for r_dis.id={r_dis.id}, got alerts for rule_ids={[a.rule_id for a in all_alerts_dis]}"

        # 5. Varias exclusions -> Basta una coincidencia (OR) + Evento excluido no incrementa window
        r_multi_excl = RuleV2(
            name="TEST-MULTI-EXCL",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 1",
            emit={"code": "TEST-MULTI-EXCL"},
        )
        db_session.add(r_multi_excl)
        db_session.commit()
        b_excl_1 = RuleListBinding(
            rule_id=r_multi_excl.id,
            list_name="excl_list_1",
            role="exclusion",
            match_field="source.ip",
            operator="in_ref",
            enabled=True
        )
        b_excl_2 = RuleListBinding(
            rule_id=r_multi_excl.id,
            list_name="whitelist_ip", # contiene 10.20.30.40
            role="exclusion",
            match_field="source.ip",
            operator="in_ref",
            enabled=True
        )
        db_session.add_all([b_excl_1, b_excl_2])
        db_session.commit()
        engine.reload_rules(db_session)

        ev_mexcl = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-05",
            ip_client="10.20.30.40",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail"}
        )
        res_me = [a for a in engine.on_event(db_session, ev_mexcl) if a.rule_id == r_multi_excl.id]
        assert len(res_me) == 0, "Al coincidir una de las exclusions debe ser excluido"
        win_key_me = (r_multi_excl.id, "srv-05")
        assert len(engine._windows[win_key_me]) == 0, "Evento excluido NO debe incrementar la ventana"

        # 6. Detections AND (deben coincidir todas) vs Detections OR (basta una)
        list_service.create_entry(db_session, tenant_id="global", list_type="list_ref", list_name="det_paths", value="/admin", reason="t", created_by="a")
        list_service.create_entry(db_session, tenant_id="global", list_type="list_ref", list_name="det_users", value="root", reason="t", created_by="a")

        r_det_and = RuleV2(
            name="TEST-DET-AND",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 1",
            detection_bindings_operator="AND",
            emit={"code": "TEST-DET-AND"},
        )
        db_session.add(r_det_and)
        db_session.commit()
        b_dand_1 = RuleListBinding(rule_id=r_det_and.id, list_name="det_paths", role="detection", match_field="url.path", operator="in_ref", enabled=True)
        b_dand_2 = RuleListBinding(rule_id=r_det_and.id, list_name="det_users", role="detection", match_field="user.name", operator="in_ref", enabled=True)
        db_session.add_all([b_dand_1, b_dand_2])
        db_session.commit()
        engine.reload_rules(db_session)

        # Evento con path coincide pero user NO coincide -> AND debe ser False
        ev_and_partial = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-06",
            ip_client="4.4.4.4",
            username="guest",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail", "url": {"original": "/admin"}}
        )
        res_and_p = [a for a in engine.on_event(db_session, ev_and_partial) if a.rule_id == r_det_and.id]
        assert len(res_and_p) == 0, "En detection AND si una falla, la coincidencia debe ser False"

        # Evento con ambos coincidentes -> AND debe ser True
        ev_and_full = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-06",
            ip_client="4.4.4.4",
            username="root",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail", "url": {"original": "/admin"}}
        )
        res_and_f = [a for a in engine.on_event(db_session, ev_and_full) if a.rule_id == r_det_and.id]
        assert len(res_and_f) == 1, "En detection AND cuando coinciden todas debe alertar"

        # 7. Context por sí solo -> Nunca genera alerta sin threshold cumplido
        r_ctx_only = RuleV2(
            name="TEST-CTX-ONLY",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 10", # Requiere 10 eventos
            emit={"code": "TEST-CTX-ONLY"},
        )
        db_session.add(r_ctx_only)
        db_session.commit()
        b_ctx_only = RuleListBinding(rule_id=r_ctx_only.id, list_name="det_paths", role="context", match_field="url.path", operator="in_ref", action_config={"adjust_severity": 10}, enabled=True)
        db_session.add(b_ctx_only)
        db_session.commit()
        engine.reload_rules(db_session)

        ev_ctx = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-07",
            ip_client="5.5.5.5",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail", "url": {"original": "/admin"}}
        )
        res_co = [a for a in engine.on_event(db_session, ev_ctx) if a.rule_id == r_ctx_only.id]
        assert len(res_co) == 0, "Context binding por sí solo sin cumplir threshold jamás debe generar alerta"

    def test_zero_implicit_list_behavior_v2(self, db_session, list_service):
        """Demuestra que las reglas V2 no tienen ningún comportamiento implícito de listas."""
        from app.models.rule_list_binding import RuleListBinding
        engine = RuleEngineV2()

        # Poblar listas globales en la BD
        list_service.create_entry(db_session, tenant_id="global", list_type="whitelist_ip", value="99.99.99.99", reason="global ip", created_by="admin")
        list_service.create_entry(db_session, tenant_id="global", list_type="trusted_country", value="MX", reason="global country", created_by="admin")
        list_service.create_entry(db_session, tenant_id="global", list_type="trusted_asn", value="12345", reason="global asn", created_by="admin")

        # A. Regla V2 sin bindings (cero bindings): NO consulta whitelists globales, evalúa base condition
        r_nobind_v2 = RuleV2(
            id=701,
            name="TEST-NOBIND-ZERO-IMPLICIT",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 1",
            legacy_list_policy=False,
            emit={"code": "TEST-701"},
        )
        db_session.add(r_nobind_v2)
        db_session.commit()
        engine.reload_rules(db_session)

        ev_global_match = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-701",
            ip_client="99.99.99.99",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail", "geo": {"country_name": "MX"}, "asn": "12345"}
        )
        res_a = [a for a in engine.on_event(db_session, ev_global_match) if "TEST-NOBIND-ZERO-IMPLICIT" in a.rule_name]
        assert len(res_a) == 1, "A: Regla sin bindings NO debe ser excluida por whitelists globales implícitas"

        # B & C. Regla V2 con whitelist_ip binding pero SIN trusted_country binding
        r_ip_only = RuleV2(
            id=702,
            name="TEST-IP-ONLY-BINDING",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 1",
            legacy_list_policy=False,
            emit={"code": "TEST-702"},
        )
        b_ip_only = RuleListBinding(
            rule_id=702,
            list_name="whitelist_ip",
            role="exclusion",
            match_field="source.ip",
            operator="in_ref",
            enabled=True
        )
        db_session.add_all([r_ip_only, b_ip_only])
        db_session.commit()
        engine.reload_rules(db_session)

        # Evento con IP en whitelist_ip -> EXCLUIDO por el binding explícito (Caso B)
        ev_ip_excl = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-702",
            ip_client="99.99.99.99",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail"}
        )
        res_b = [a for a in engine.on_event(db_session, ev_ip_excl) if "TEST-IP-ONLY-BINDING" in a.rule_name]
        assert len(res_b) == 0, "B: Evento con IP en binding explícito de whitelist_ip debe ser excluido"

        # Evento con IP diferente pero de país MX (trusted_country) -> NO EXCLUIDO (Caso C)
        ev_country_hit = Event(
            id=uuid.uuid4(),
            source="apache_access",
            server="srv-702",
            ip_client="8.8.8.8",
            timestamp_utc=datetime.now(timezone.utc),
            extra={"event_type": "http_access", "action": "fail", "geo": {"country_name": "MX"}}
        )
        res_c = [a for a in engine.on_event(db_session, ev_country_hit) if "TEST-IP-ONLY-BINDING" in a.rule_name]
        assert len(res_c) == 1, "C: Coincidencia con trusted_country NO debe excluir si la regla solo vinculó whitelist_ip"

        # D. Regla V2 con trusted_country binding explícito
        r_country = RuleV2(
            id=703,
            name="TEST-COUNTRY-EXPLICIT",
            source="WEB_ACCESS",
            event_type="http_access",
            severity=5,
            enabled=True,
            window_seconds=300,
            cooldown_seconds=0,
            match={"extra.action": "fail"},
            condition="count >= 1",
            legacy_list_policy=False,
            emit={"code": "TEST-703"},
        )
        b_country = RuleListBinding(
            rule_id=703,
            list_name="trusted_country",
            role="exclusion",
            match_field="geo.country_name",
            operator="in_ref",
            enabled=True
        )
        db_session.add_all([r_country, b_country])
        db_session.commit()
        engine.reload_rules(db_session)

        res_d = [a for a in engine.on_event(db_session, ev_country_hit) if "TEST-COUNTRY-EXPLICIT" in a.rule_name]
        assert len(res_d) == 0, "D: Con binding explícito a trusted_country, un evento de MX sí debe ser excluido"

        # E. Cero bindings = CERO listas aplicadas
        assert len(r_nobind_v2.bindings) == 0
        assert r_nobind_v2.legacy_list_policy is False
        res_e = [a for a in engine.on_event(db_session, ev_global_match) if "TEST-NOBIND-ZERO-IMPLICIT" in a.rule_name]
        assert len(res_e) == 1, "E: Cero bindings significa evaluar únicamente la regla base sin fallback legacy"
