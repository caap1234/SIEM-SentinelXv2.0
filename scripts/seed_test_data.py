# scripts/seed_test_data.py
"""
Script de Carga de Datos de Prueba Mínimos para SentinelX SIEM en Entorno Local.
Genera tenant, usuario admin, agente de prueba, eventos en OpenSearch, alertas e incidentes en PostgreSQL,
y objetos de evidencia en MinIO S3 para validación visual completa del dashboard.
"""
from __future__ import annotations

import gzip
import io
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

# Asegurar importación de app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelx.seed")

from app.db import Base, engine, SessionLocal
from app.models.tenant import Tenant
from app.models.user import User
from app.models.agent import RegisteredAgent
from app.models.agent_api_key import AgentApiKey
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.entity import Entity
from app.models.incident_alert import IncidentAlert
from app.models.incident_entity import IncidentEntity
from app.core.security import hash_password
from app.services.agent_api_key_service import create_agent_api_key
from app.core.opensearch_client import OpenSearchClient
from app.services.evidence_service import EvidenceService
from app.schemas.normalized_event import NormalizedEvent, EventMeta, TenantMeta, HostMeta, LogMeta



TENANT_ID = "default"
ADMIN_EMAIL = "admin@sentinelx.local"
ADMIN_PASS = "SentinelX_Admin_2026!"


def seed_database_records() -> dict:
    """Crea registros transaccionales base en PostgreSQL."""
    logger.info("Iniciando seed de registros transaccionales en PostgreSQL...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    results = {}
    try:
        # 1. Tenant default
        tenant = db.query(Tenant).filter(Tenant.id == TENANT_ID).first()
        if not tenant:
            tenant = Tenant(id=TENANT_ID, name="Default Hosting Tenant", status="active")
            db.add(tenant)
            db.commit()
            logger.info("Tenant '%s' creado.", TENANT_ID)
        results["tenant_id"] = TENANT_ID

        # 2. Admin User
        user = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        if not user:
            user = User(
                email=ADMIN_EMAIL,
                full_name="Administrador SIEM",
                hashed_password=hash_password(ADMIN_PASS),
                is_active=True,
                is_admin=True,
            )
            db.add(user)
            db.commit()
            logger.info("Usuario administrador '%s' creado.", ADMIN_EMAIL)
        results["admin_email"] = ADMIN_EMAIL
        results["admin_pass"] = ADMIN_PASS

        # 3. Registered Agent
        hostname = "srv-cpanel-prod-01.acmelocal.com"
        agent = db.query(RegisteredAgent).filter(
            RegisteredAgent.hostname == hostname,
            RegisteredAgent.tenant_id == TENANT_ID
        ).first()

        now = datetime.now(timezone.utc)
        if not agent:
            agent = RegisteredAgent(
                tenant_id=TENANT_ID,
                name="Servidor cPanel Principal #1",
                hostname=hostname,
                ip_address="192.168.1.105",
                os_info="AlmaLinux 9.4 (Sea Turquoise)",
                agent_version="1.0.0",
                status="healthy",
                metadata_json={
                    "cpu_cores": 16,
                    "ram_gb": 64,
                    "kernel": "5.14.0-427.el9.x86_64",
                    "cpanel_version": "120.0.11",
                },
                last_seen_at=now,
            )
            db.add(agent)
            db.commit()
            logger.info("Agente registrado '%s' creado.", hostname)
        results["agent_hostname"] = hostname

        # 4. Agent API Key de prueba
        key_name = "Agent Production Key #1"
        existing_key = db.query(AgentApiKey).filter(AgentApiKey.name == key_name, AgentApiKey.tenant_id == TENANT_ID).first()
        if not existing_key:
            plain_key, api_key_rec = create_agent_api_key(
                db=db,
                name=key_name,
                tenant_id=TENANT_ID,
                agent_id=str(agent.id)
            )
            results["api_key"] = plain_key
            logger.info("API Key de Agente creada: %s", plain_key)
        else:
            results["api_key"] = "sx_live_demoagentkey001.sec8839219380123849102"


        # 5. Alertas de prueba en PostgreSQL
        alert_count = db.query(Alert).count()
        if alert_count == 0:
            sample_alerts = [
                Alert(
                    rule_name="SSH Brute Force Attack Detection",
                    severity=80,
                    server=hostname,
                    source="system_secure",
                    event_type="ssh_login_failed",
                    group_key=f"{hostname}:system_secure:198.51.100.45",
                    triggered_at=now - timedelta(minutes=5),
                    window_start=now - timedelta(minutes=45),
                    window_end=now - timedelta(minutes=5),
                    metrics={"event_count": 15, "source_ip": "198.51.100.45", "target_user": "root"},
                    evidence={"raw_sample": "Failed password for root from 198.51.100.45"},
                    status="open",
                ),
                Alert(
                    rule_name="ModSecurity Web Application Firewall SQLi",
                    severity=95,
                    server=hostname,
                    source="modsec_audit",
                    event_type="modsec_blocked",
                    group_key=f"{hostname}:modsec_audit:203.0.113.199",
                    triggered_at=now - timedelta(minutes=2),
                    window_start=now - timedelta(minutes=20),
                    window_end=now - timedelta(minutes=2),
                    metrics={"event_count": 3, "source_ip": "203.0.113.199", "domain": "cliente-tienda.com"},
                    evidence={"raw_sample": "Access denied with code 403 (phase 2). Pattern match SELECT"},
                    status="open",
                ),
                Alert(
                    rule_name="Exim High Volume Outbound Mail Spool",
                    severity=50,
                    server=hostname,
                    source="exim_mainlog",
                    event_type="exim_spam",
                    group_key=f"{hostname}:exim_mainlog:spammer@domain.com",
                    triggered_at=now - timedelta(hours=1),
                    window_start=now - timedelta(hours=3),
                    window_end=now - timedelta(hours=1),
                    metrics={"event_count": 84, "authenticated_user": "spammer@domain.com"},
                    evidence={"raw_sample": "spammer@domain.com sent 84 emails in 10 minutes"},
                    status="resolved",
                    resolved_at=now - timedelta(minutes=30),
                    resolved_by=ADMIN_EMAIL,
                ),
            ]
            db.add_all(sample_alerts)
            db.commit()
            logger.info("Se crearon %d alertas de prueba en PostgreSQL.", len(sample_alerts))
        results["alert_count"] = db.query(Alert).count()

        # 6. Incidentes de prueba en PostgreSQL
        incident_count = db.query(Incident).count()
        if incident_count == 0:
            sample_incidents = [
                Incident(
                    code="INC-SEC-01",
                    name="Compromiso Potencial de Cuenta Root SSH & Escalación",
                    scope="local",
                    status="open",
                    severity_base=80,
                    severity_current=90,
                    score=90,
                    server=hostname,
                    primary_entity_type="ip",
                    primary_entity_key="198.51.100.45",
                    metrics={"alert_count": 2, "source_ip": "198.51.100.45"},
                    evidence={"details": "Detectados múltiples ataques coordinados sobre puerto 22 e intentos de inyección SQL web."},
                    opened_at=now - timedelta(minutes=45),
                    last_activity_at=now - timedelta(minutes=2),
                )
            ]
            db.add_all(sample_incidents)
            db.commit()
            logger.info("Se crearon %d incidentes de prueba en PostgreSQL.", len(sample_incidents))
        results["incident_count"] = db.query(Incident).count()

        # 7. Entidades de prueba en PostgreSQL
        entity_count = db.query(Entity).count()
        if entity_count == 0:
            sample_entities = [
                Entity(
                    entity_type="ip",
                    entity_key="198.51.100.45",
                    scope="local",
                    score_current=85,
                    severity="high",
                    first_seen_at=now - timedelta(days=2),
                    last_seen_at=now - timedelta(minutes=5),
                    score_updated_at=now - timedelta(minutes=5),
                    attrs={
                        "country": "US",
                        "asn": 15169,
                        "as_org": "Google LLC",
                        "servers": [hostname],
                        "state": "open",
                        "tags": ["brute_force", "malicious_ip"],
                    },
                ),
                Entity(
                    entity_type="ip",
                    entity_key="203.0.113.199",
                    scope="local",
                    score_current=95,
                    severity="critical",
                    first_seen_at=now - timedelta(hours=5),
                    last_seen_at=now - timedelta(minutes=2),
                    score_updated_at=now - timedelta(minutes=2),
                    attrs={
                        "country": "DE",
                        "asn": 24940,
                        "as_org": "Hetzner Online GmbH",
                        "servers": [hostname],
                        "state": "open",
                        "tags": ["sqli", "waf_blocked"],
                    },
                ),
                Entity(
                    entity_type="user",
                    entity_key="root",
                    scope="local",
                    score_current=70,
                    severity="medium",
                    first_seen_at=now - timedelta(days=7),
                    last_seen_at=now - timedelta(minutes=5),
                    score_updated_at=now - timedelta(minutes=5),
                    attrs={
                        "servers": [hostname],
                        "state": "open",
                        "tags": ["privileged_account", "targeted"],
                    },
                ),
            ]
            db.add_all(sample_entities)
            db.commit()
            logger.info("Se crearon %d entidades de prueba en PostgreSQL.", len(sample_entities))
        results["entity_count"] = db.query(Entity).count()

        # 8. Vincular Incidentes con Alertas e Entidades
        inc = db.query(Incident).filter(Incident.code == "INC-SEC-01").first()
        if inc:
            alerts = db.query(Alert).limit(2).all()
            for al in alerts:
                inc_alert = db.query(IncidentAlert).filter(
                    IncidentAlert.incident_id == inc.id, IncidentAlert.alert_id == al.id
                ).first()
                if not inc_alert:
                    db.add(IncidentAlert(incident_id=inc.id, alert_id=al.id, role="trigger"))
            
            ip_ent = db.query(Entity).filter(Entity.entity_key == "198.51.100.45").first()
            if ip_ent:
                inc_ent = db.query(IncidentEntity).filter(
                    IncidentEntity.incident_id == inc.id, IncidentEntity.entity_id == ip_ent.id
                ).first()
                if not inc_ent:
                    db.add(IncidentEntity(incident_id=inc.id, entity_id=ip_ent.id, relation="attacker"))
            db.commit()

    except Exception as e:
        db.rollback()
        logger.error("Error al poblar base de datos PostgreSQL: %s", e)
    finally:
        db.close()

    return results




def seed_opensearch_events():
    """Genera eventos simulados en OpenSearch Data Stream."""
    logger.info("Conectando con OpenSearch para enviar eventos de prueba...")
    try:
        client = OpenSearchClient.get_instance()
        if not client.connect():
            logger.warning("OpenSearch no disponible en este momento. Saltando eventos OpenSearch.")
            return

        now = datetime.now(timezone.utc)
        sample_docs = [
            {
                "@timestamp": (now - timedelta(minutes=i*2)).isoformat(),
                "event": {
                    "id": str(uuid.uuid4()),
                    "kind": "event",
                    "category": "authentication" if i % 2 == 0 else "web",
                    "type": "start" if i % 2 == 0 else "access",
                    "action": "ssh_login_failed" if i % 2 == 0 else "modsec_blocked",
                    "severity": 3 if i % 3 == 0 else 1,
                    "dataset": "system_secure" if i % 2 == 0 else "modsec_audit",
                },
                "tenant": {"id": TENANT_ID},
                "host": {
                    "hostname": "srv-cpanel-prod-01.acmelocal.com",
                    "ip": "192.168.1.105",
                },
                "source": {
                    "ip": f"198.51.100.{10 + i}",
                    "port": 45120 + i,
                    "geo_country_iso_code": "US" if i % 2 == 0 else "DE",
                },
                "user": {
                    "name": "root" if i % 2 == 0 else "admin",
                },
                "log": {
                    "original": f"Failed password for root from 198.51.100.{10+i} port {45120+i} ssh2",
                },
            }
            for i in range(25)
        ]

        target_index = "sentinelx-events-hosting-default"
        # Crear data stream / indexar lote
        actions = []
        for doc in sample_docs:
            actions.append({
                "_op_type": "create",
                "_index": target_index,
                "_id": doc["event"]["id"],
                "_source": doc,
            })

        from opensearchpy import helpers
        success, _ = helpers.bulk(client.client, actions, raise_on_error=False)
        logger.info("Indexados %d eventos de prueba en OpenSearch Data Stream '%s'.", success, target_index)

    except Exception as e:
        logger.warning("Error al indexar eventos en OpenSearch (continuando): %s", e)


def seed_minio_evidence():
    """Genera un archivo de evidencia de prueba en MinIO S3."""
    logger.info("Verificando almacenamiento de evidencia en MinIO S3...")
    try:
        service = EvidenceService()
        now = datetime.now(timezone.utc)
        event = NormalizedEvent(
            timestamp_utc=now,
            tenant=TenantMeta(id=TENANT_ID),
            event=EventMeta(
                id=str(uuid.uuid4()),
                category=["authentication"],
                dataset="system_secure",
                action="ssh_failed_password",
                original="Aug  9 21:00:15 srv-cpanel-prod-01 sshd[12345]: Failed password for root from 198.51.100.45 port 51204 ssh2",
            ),
            host=HostMeta(
                hostname="srv-cpanel-prod-01.acmelocal.com",
                ip="192.168.1.105",
            ),
            log=LogMeta(
                original="Aug  9 21:00:15 srv-cpanel-prod-01 sshd[12345]: Failed password for root from 198.51.100.45 port 51204 ssh2",
            )
        )
        s3_key, sha256_hash, bucket = service.upload_evidence(event)
        logger.info("Evidencia de prueba subida a MinIO. Key: %s, SHA256: %s, Bucket: %s", s3_key, sha256_hash, bucket)
    except Exception as e:
        logger.warning("Error al subir evidencia a MinIO (continuando): %s", e)




def main():
    logger.info("=== SentinelX SIEM — Carga de Datos Iniciales de Prueba ===")
    db_results = seed_database_records()
    seed_opensearch_events()
    seed_minio_evidence()
    logger.info("=== Carga finalizada exitosamente ===")
    print("\n" + "=" * 60)
    print(" RESUMEN DE DATOS INICIALES PARA PRUEBAS LOCALES")
    print("=" * 60)
    print(f" Tenant ID:            {db_results.get('tenant_id')}")
    print(f" Usuario Admin:        {db_results.get('admin_email')}")
    print(f" Contraseña Admin:     {db_results.get('admin_pass')}")
    print(f" Agente Registrado:    {db_results.get('agent_hostname')}")
    print(f" API Key de Agente:    {db_results.get('api_key')}")
    print(f" Alertas Generadas:    {db_results.get('alert_count')}")
    print(f" Incidentes Generados: {db_results.get('incident_count')}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
