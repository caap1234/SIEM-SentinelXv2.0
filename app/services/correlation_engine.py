# app/services/correlation_engine.py
"""
Motor de Correlación Reactivo en Tiempo Real con Ventanas Deslizantes en Memoria.
Procesa eventos canónicos NormalizedEvent, evalúa reglas de detección de hosting
y genera Alertas sin realizar consultas SQL.
"""
from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.normalized_event import NormalizedEvent
from app.schemas.detection_rule import DetectionRule
from app.core.hosting_rules import DEFAULT_HOSTING_RULES

logger = logging.getLogger("sentinelx.correlation")


class SlidingWindowBucket:
    """
    Almacena las marcas de tiempo e identificadores de eventos dentro de una ventana deslizante.
    """
    def __init__(self) -> None:
        # deque de tuplas (timestamp_seconds, event_id)
        self.events: deque[Tuple[float, str]] = deque()

    def add_event(self, ts_sec: float, event_id: str) -> None:
        self.events.append((ts_sec, event_id))

    def evict_expired(self, current_ts_sec: float, window_seconds: int) -> None:
        cutoff = current_ts_sec - window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def count(self) -> int:
        return len(self.events)

    def get_event_ids(self) -> List[str]:
        return [eid for _, eid in self.events]

    def clear(self) -> None:
        self.events.clear()


class CorrelationEngine:
    _instance: Optional[CorrelationEngine] = None

    def __init__(self, rules: Optional[List[DetectionRule]] = None) -> None:
        self.rules: List[DetectionRule] = rules if rules is not None else list(DEFAULT_HOSTING_RULES)
        # Diccionario en memoria: (tenant_id, rule_id, group_key) -> SlidingWindowBucket
        self.windows: Dict[Tuple[str, str, str], SlidingWindowBucket] = defaultdict(SlidingWindowBucket)

    @classmethod
    def get_instance(cls) -> CorrelationEngine:
        if cls._instance is None:
            cls._instance = CorrelationEngine()
        return cls._instance

    def register_rule(self, rule: DetectionRule) -> None:
        """Añade o actualiza una regla de detección."""
        self.rules = [r for r in self.rules if r.id != rule.id]
        self.rules.append(rule)

    async def process_event_async(self, event: NormalizedEvent, kv_store: Any = None) -> List[Dict[str, Any]]:
        """
        Procesa un evento canónico normalizado utilizando NATS KV Store para mantener la ventana
        deslizante compartida y consistente entre N instancias distribuidas de correlation_worker.
        """
        doc = event.to_opensearch_doc()
        event_id = str(event.event.id)
        tenant_id = event.tenant.id
        ts_sec = event.timestamp_utc.timestamp()

        generated_alerts: List[Dict[str, Any]] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            if not rule.matches_event(doc):
                continue

            group_key = rule.get_group_key(doc)
            raw_key = f"{tenant_id}.{rule.id}.{group_key}".replace("/", "_").replace(" ", "_")

            # Usar NATS KV si está disponible para consistencia distribuida entre N workers
            events_list: List[Dict[str, Any]] = []
            if kv_store:
                try:
                    entry = await kv_store.get(raw_key)
                    if entry and entry.value:
                        events_list = json.loads(entry.value.decode("utf-8"))
                except Exception:
                    events_list = []

                # Evicción por ventana de tiempo
                cutoff = ts_sec - rule.time_window_seconds
                events_list = [e for e in events_list if e.get("ts", 0) >= cutoff]
                events_list.append({"ts": ts_sec, "id": event_id})

                count = len(events_list)
                if count >= rule.threshold:
                    alert_id = str(uuid.uuid4())
                    related_ids = [e.get("id") for e in events_list if e.get("id")]
                    alert = {
                        "alert_id": alert_id,
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "description": rule.description,
                        "category": rule.category,
                        "tenant_id": tenant_id,
                        "severity": rule.severity,
                        "risk_score": rule.risk_score,
                        "group_key": group_key,
                        "trigger_count": count,
                        "related_event_ids": related_ids,
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "source_ip": doc.get("source", {}).get("ip"),
                        "host_name": doc.get("host", {}).get("name"),
                    }
                    logger.warning("¡ALERTA DISTRIBUIDA SIEM GENERADA! [%s] Regla=%s GroupKey=%s Count=%d/%d", tenant_id, rule.name, group_key, count, rule.threshold)
                    generated_alerts.append(alert)
                    # Reiniciar ventana compartida tras disparar la alerta
                    events_list = []

                try:
                    await kv_store.put(raw_key, json.dumps(events_list).encode("utf-8"))
                except Exception as put_err:
                    logger.error("NATS KV put error: %s", put_err)
            else:
                # Fallback en memoria local
                bucket_key = (tenant_id, rule.id, group_key)
                bucket = self.windows[bucket_key]
                bucket.evict_expired(ts_sec, rule.time_window_seconds)
                bucket.add_event(ts_sec, event_id)

                if bucket.count() >= rule.threshold:
                    related_ids = bucket.get_event_ids()
                    alert_id = str(uuid.uuid4())
                    alert = {
                        "alert_id": alert_id,
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "description": rule.description,
                        "category": rule.category,
                        "tenant_id": tenant_id,
                        "severity": rule.severity,
                        "risk_score": rule.risk_score,
                        "group_key": group_key,
                        "trigger_count": bucket.count(),
                        "related_event_ids": related_ids,
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "source_ip": doc.get("source", {}).get("ip"),
                        "host_name": doc.get("host", {}).get("name"),
                    }
                    logger.warning("¡ALERTA SIEM GENERADA! [%s] Regla=%s GroupKey=%s Count=%d/%d", tenant_id, rule.name, group_key, bucket.count(), rule.threshold)
                    generated_alerts.append(alert)
                    bucket.clear()

        return generated_alerts

    def process_event(self, event: NormalizedEvent) -> List[Dict[str, Any]]:
        """
        Procesa un evento normalizado a través del motor de correlación.
        Retorna una lista de diccionarios de Alertas generadas si se alcanzaron umbrales.
        """
        doc = event.to_opensearch_doc()
        event_id = str(event.event.id)
        tenant_id = event.tenant.id
        ts_sec = event.timestamp_utc.timestamp()

        generated_alerts: List[Dict[str, Any]] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Evaluar si la regla coincide con las condiciones del evento
            if not rule.matches_event(doc):
                continue

            group_key = rule.get_group_key(doc)
            bucket_key = (tenant_id, rule.id, group_key)

            bucket = self.windows[bucket_key]
            bucket.evict_expired(ts_sec, rule.time_window_seconds)
            bucket.add_event(ts_sec, event_id)

            # Verificar si se alcanzó el umbral configurado
            if bucket.count() >= rule.threshold:
                related_ids = bucket.get_event_ids()
                alert_id = str(uuid.uuid4())

                alert = {
                    "alert_id": alert_id,
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "description": rule.description,
                    "category": rule.category,
                    "tenant_id": tenant_id,
                    "severity": rule.severity,
                    "risk_score": rule.risk_score,
                    "group_key": group_key,
                    "trigger_count": bucket.count(),
                    "related_event_ids": related_ids,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "source_ip": doc.get("source", {}).get("ip"),
                    "host_name": doc.get("host", {}).get("name"),
                }

                logger.warning(
                    "¡ALERTA SIEM GENERADA! [%s] Regla=%s GroupKey=%s Count=%d/%d",
                    tenant_id,
                    rule.name,
                    group_key,
                    bucket.count(),
                    rule.threshold,
                )

                generated_alerts.append(alert)
                bucket.clear()  # Limpiar ventana para evitar spam consecutivo

        return generated_alerts
