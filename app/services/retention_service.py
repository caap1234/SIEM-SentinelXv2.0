from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.entity import Entity
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
from app.models.system_setting import SystemSetting


class RetentionPolicyConfig(BaseModel):
    uploaded_logs_days: int = Field(30, ge=1, le=3650)
    opensearch_events_days: int = Field(90, ge=1, le=3650)
    alerts_days: int = Field(180, ge=1, le=3650)
    entities_days: int = Field(180, ge=1, le=3650)
    incidents_days: int = Field(365, ge=1, le=3650)
    evidence_s3_days: int = Field(365, ge=1, le=3650)
    protect_open_incidents: bool = True


DEFAULT_RETENTION_CONFIG = RetentionPolicyConfig()


def get_retention_config(db: Session) -> RetentionPolicyConfig:
    """Obtiene la configuración de retención actual de system_settings o usa los valores por defecto."""
    setting = db.query(SystemSetting).filter(SystemSetting.key == "retention_policy").first()
    if setting and isinstance(setting.value, dict):
        try:
            return RetentionPolicyConfig(**setting.value)
        except Exception:
            pass
    return DEFAULT_RETENTION_CONFIG.model_copy()


def save_retention_config(db: Session, config: RetentionPolicyConfig) -> RetentionPolicyConfig:
    """Guarda la configuración de retención en system_settings."""
    setting = db.query(SystemSetting).filter(SystemSetting.key == "retention_policy").first()
    if not setting:
        setting = SystemSetting(key="retention_policy", value=config.model_dump())
        db.add(setting)
    else:
        setting.value = config.model_dump()
        db.add(setting)
    db.commit()
    db.refresh(setting)
    return config


class RetentionPurgeSummary(BaseModel):
    dry_run: bool
    uploaded_logs_files: int = 0
    opensearch_events_estimated: int = 0
    alerts_purged: int = 0
    entities_purged: int = 0
    incidents_purged: int = 0
    protected_alerts_skipped: int = 0
    message: str


def preview_retention_purge(db: Session, config: Optional[RetentionPolicyConfig] = None) -> RetentionPurgeSummary:
    """Previsualización de purga por retención (Dry Run)."""
    if config is None:
        config = get_retention_config(db)

    now = datetime.now(timezone.utc)
    
    # 1. Alertas
    cutoff_alerts = now - timedelta(days=config.alerts_days)
    q_alerts = db.query(Alert.id).filter(Alert.triggered_at < cutoff_alerts)
    if config.protect_open_incidents:
        # Excluir alertas asociadas a incidentes abiertos
        open_inc_ids = [i[0] for i in db.query(Incident.id).filter(Incident.status.in_(["open", "in_investigation"])).all()]
        if open_inc_ids:
            protected_alert_ids = [ia[0] for ia in db.query(IncidentAlert.alert_id).filter(IncidentAlert.incident_id.in_(open_inc_ids)).all()]
            if protected_alert_ids:
                q_alerts = q_alerts.filter(Alert.id.notin_(protected_alert_ids))
    alerts_count = q_alerts.count()

    # 2. Incidentes resueltos/cerrados antiguos
    cutoff_incidents = now - timedelta(days=config.incidents_days)
    q_incidents = db.query(Incident.id).filter(
        Incident.closed_at.isnot(None),
        Incident.closed_at < cutoff_incidents,
        Incident.status.in_(["resolved", "false_positive", "closed"])
    )
    incidents_count = q_incidents.count()

    # 3. Entidades
    cutoff_entities = now - timedelta(days=config.entities_days)
    q_entities = db.query(Entity.id).filter(Entity.updated_at < cutoff_entities)
    entities_count = q_entities.count()

    # 4. Uploaded logs
    uploaded_logs_count = 0
    env_dir = (os.getenv("UPLOADED_LOGS_DIR") or "").strip()
    logs_dir = env_dir if env_dir and os.path.isdir(env_dir) else "./app/uploaded_logs"
    if os.path.isdir(logs_dir):
        cutoff_logs_ts = (now - timedelta(days=config.uploaded_logs_days)).timestamp()
        for root, dirs, files in os.walk(logs_dir):
            for f in files:
                p = os.path.join(root, f)
                try:
                    if os.path.getmtime(p) < cutoff_logs_ts:
                        uploaded_logs_count += 1
                except Exception:
                    pass

    return RetentionPurgeSummary(
        dry_run=True,
        uploaded_logs_files=uploaded_logs_count,
        opensearch_events_estimated=0, # OpenSearch ISM maneja su propio ciclo
        alerts_purged=alerts_count,
        entities_purged=entities_count,
        incidents_purged=incidents_count,
        protected_alerts_skipped=0,
        message="Previsualización de retención generada exitosamente. Ningún registro ha sido eliminado."
    )


def execute_retention_purge(db: Session, config: Optional[RetentionPolicyConfig] = None) -> RetentionPurgeSummary:
    """Ejecuta la purga de retención eliminando registros caducados."""
    if config is None:
        config = get_retention_config(db)

    preview = preview_retention_purge(db, config)
    now = datetime.now(timezone.utc)

    try:
        # 1. Eliminar incidentes cerrados antiguos
        cutoff_incidents = now - timedelta(days=config.incidents_days)
        old_inc_ids = [i[0] for i in db.query(Incident.id).filter(
            Incident.closed_at.isnot(None),
            Incident.closed_at < cutoff_incidents,
            Incident.status.in_(["resolved", "false_positive", "closed"])
        ).all()]
        if old_inc_ids:
            db.query(IncidentAlert).filter(IncidentAlert.incident_id.in_(old_inc_ids)).delete(synchronize_session=False)
            db.query(Incident).filter(Incident.id.in_(old_inc_ids)).delete(synchronize_session=False)

        # 2. Eliminar alertas caducadas
        cutoff_alerts = now - timedelta(days=config.alerts_days)
        q_alerts = db.query(Alert.id).filter(Alert.triggered_at < cutoff_alerts)
        if config.protect_open_incidents:
            open_inc_ids = [i[0] for i in db.query(Incident.id).filter(Incident.status.in_(["open", "in_investigation"])).all()]
            if open_inc_ids:
                protected_alert_ids = [ia[0] for ia in db.query(IncidentAlert.alert_id).filter(IncidentAlert.incident_id.in_(open_inc_ids)).all()]
                if protected_alert_ids:
                    q_alerts = q_alerts.filter(Alert.id.notin_(protected_alert_ids))
        old_alert_ids = [a[0] for a in q_alerts.all()]
        if old_alert_ids:
            db.query(Alert).filter(Alert.id.in_(old_alert_ids)).delete(synchronize_session=False)

        # 3. Eliminar entidades inactivas antiguas
        cutoff_entities = now - timedelta(days=config.entities_days)
        old_entity_ids = [e[0] for e in db.query(Entity.id).filter(Entity.updated_at < cutoff_entities).all()]
        if old_entity_ids:
            db.query(Entity).filter(Entity.id.in_(old_entity_ids)).delete(synchronize_session=False)

        # 4. Eliminar archivos de uploaded_logs
        removed_logs = 0
        env_dir = (os.getenv("UPLOADED_LOGS_DIR") or "").strip()
        logs_dir = env_dir if env_dir and os.path.isdir(env_dir) else "./app/uploaded_logs"
        if os.path.isdir(logs_dir):
            cutoff_logs_ts = (now - timedelta(days=config.uploaded_logs_days)).timestamp()
            for root, dirs, files in os.walk(logs_dir):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        if os.path.getmtime(p) < cutoff_logs_ts:
                            os.remove(p)
                            removed_logs += 1
                    except Exception:
                        pass

        db.commit()

        return RetentionPurgeSummary(
            dry_run=False,
            uploaded_logs_files=removed_logs,
            opensearch_events_estimated=0,
            alerts_purged=len(old_alert_ids),
            entities_purged=len(old_entity_ids),
            incidents_purged=len(old_inc_ids),
            protected_alerts_skipped=0,
            message="Purga por retención ejecutada exitosamente."
        )

    except Exception as e:
        db.rollback()
        raise RuntimeError(f"Error durante la ejecución de purga por retención: {e}")
