"""
tests/unit/test_nats_invalidation.py

Pruebas unitarias de la Invalidación Reactiva por NATS y Recarga en Caliente
SentinelX SIEM (Fase 3).
"""

import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models.rule_v2 import RuleV2
from app.models.rule_list_binding import RuleListBinding
from app.models.security_list import SecurityListEntry
from app.services.security_list_service import SecurityListService
from app.services.rule_engine_v2 import RuleEngineV2
from app.services.rule_engine_runtime import invalidate_rule_engine_cache
from app.services.nats_service import NatsService, NatsUnavailableError


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()


class TestNatsReactiveInvalidation:

    def test_security_list_crud_triggers_local_and_nats_invalidation(self, db_session):
        """
        Valida que al crear, actualizar o eliminar un registro en SecurityListService,
        se invalide el timestamp `_last_load` local y se notifique a NATS.
        """
        svc = SecurityListService.get_instance()
        svc.refresh_cache(db_session)
        assert svc._last_load is not None

        nats_svc = NatsService.get_instance()

        with patch.object(nats_svc, "notify_invalidation_sync") as mock_notify:
            # 1. Crear entrada
            entry = svc.create_entry(
                db_session,
                tenant_id="global",
                list_type="whitelist_ip",
                value="192.168.1.100",
                reason="Prueba NATS",
                created_by="test_admin",
            )
            assert entry.id is not None
            mock_notify.assert_called_with(
                kind="lists",
                tenant_id="global",
                list_type="whitelist_ip",
                list_name=None,
                action="create",
            )

            # 2. Actualizar entrada
            svc.update_entry(
                db_session,
                entry_id=entry.id,
                data={"reason": "Motivo actualizado"},
                updated_by="test_admin",
            )
            mock_notify.assert_called_with(
                kind="lists",
                tenant_id="global",
                list_type="whitelist_ip",
                list_name=None,
                action="update",
            )

            # 3. Eliminar entrada
            svc.delete_entry(db_session, entry_id=entry.id, performed_by="test_admin")
            mock_notify.assert_called_with(
                kind="lists",
                tenant_id="global",
                list_type="whitelist_ip",
                list_name=None,
                action="delete",
            )

    def test_rule_engine_cache_invalidation_resets_reload_timestamp(self, db_session):
        """
        Valida que invalidate_rule_engine_cache() reinicie `_last_reload_at = None`
        e inicie la recarga en la siguiente evaluación.
        """
        engine = RuleEngineV2.get_instance()
        engine.reload_rules(db_session)
        assert engine._last_reload_at is not None

        nats_svc = NatsService.get_instance()

        with patch.object(nats_svc, "notify_invalidation_sync") as mock_notify:
            invalidate_rule_engine_cache()
            assert engine._last_reload_at is None
            mock_notify.assert_called_with(kind="rules")

    def test_nats_offline_graceful_degradation(self, db_session):
        """
        Valida que si NATS está offline o no disponible, las operaciones CRUD
        se completan al 100% sin lanzar excepciones, ejecutando la invalidación local.
        """
        svc = SecurityListService.get_instance()
        svc.refresh_cache(db_session)

        # Simular NATS offline
        nats_svc = NatsService.get_instance()
        with patch.object(nats_svc, "publish_list_invalidation", side_effect=NatsUnavailableError("NATS Offline")):
            entry = svc.create_entry(
                db_session,
                tenant_id="global",
                list_type="whitelist_ip",
                value="10.0.0.50",
                reason="Prueba NATS offline",
                created_by="test_admin",
            )
            assert entry.id is not None
            # Caché local refrescado limpiamente
            assert len([e for e in svc._cache_entries if e["value"] == "10.0.0.50"]) == 1
