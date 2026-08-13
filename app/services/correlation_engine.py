# app/services/correlation_engine.py
"""
Motor de Correlación Reactivo en Tiempo Real con Ventanas Deslizantes en Memoria.
Procesa eventos canónicos NormalizedEvent, evalúa reglas de detección ECS
y genera Alertas sin divergencia de lógica (composición directa con RuleEngineV2 / DetectionCore).
"""
from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.normalized_event import NormalizedEvent
from app.db import SessionLocal
from app.services.rule_engine_v2 import RuleEngineV2
from app.services.detection_core import get_canonical_field

logger = logging.getLogger("sentinelx.correlation")


class SlidingWindowBucket:
    def __init__(self) -> None:
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

    def __init__(self, rules: Optional[List[Any]] = None) -> None:
        self.rules: List[Any] = rules if rules is not None else []
        self.windows: Dict[Tuple[str, str, str], SlidingWindowBucket] = defaultdict(SlidingWindowBucket)
        self.rule_engine = RuleEngineV2()

    @classmethod
    def get_instance(cls) -> CorrelationEngine:
        if cls._instance is None:
            cls._instance = CorrelationEngine()
        return cls._instance

    def register_rule(self, rule: Any) -> None:
        self.rules = [r for r in self.rules if getattr(r, "id", None) != getattr(rule, "id", None)]
        self.rules.append(rule)

    async def process_event_async(self, event: NormalizedEvent, kv_store: Any = None) -> List[Dict[str, Any]]:
        doc = event.to_opensearch_doc()
        event_id = str(event.event.id)
        tenant_id = event.tenant.id
        ts_sec = event.timestamp_utc.timestamp()

        generated_alerts: List[Dict[str, Any]] = []

        if self.rules:
            for rule in self.rules:
                if not getattr(rule, "enabled", True):
                    continue

                if hasattr(rule, "matches_event") and not rule.matches_event(doc):
                    continue

                group_key = rule.get_group_key(doc) if hasattr(rule, "get_group_key") else "default"
                raw_key = f"{tenant_id}.{getattr(rule, 'id', 'rule')}.{group_key}".replace("/", "_").replace(" ", "_")

                events_list: List[Dict[str, Any]] = []
                if kv_store:
                    try:
                        entry = await kv_store.get(raw_key)
                        if entry and entry.value:
                            events_list = json.loads(entry.value.decode("utf-8"))
                    except Exception:
                        events_list = []

                    window_sec = int(getattr(rule, "time_window_seconds", 300))
                    cutoff = ts_sec - window_sec
                    events_list = [e for e in events_list if e.get("ts", 0) >= cutoff]
                    events_list.append({"ts": ts_sec, "id": event_id})

                    count = len(events_list)
                    threshold = int(getattr(rule, "threshold", 1))
                    if count >= threshold:
                        alert = {
                            "alert_id": str(uuid.uuid4()),
                            "rule_id": getattr(rule, "id", "rule"),
                            "rule_name": getattr(rule, "name", "Rule"),
                            "description": getattr(rule, "description", ""),
                            "category": getattr(rule, "category", "general"),
                            "tenant_id": tenant_id,
                            "severity": getattr(rule, "severity", 5),
                            "risk_score": getattr(rule, "risk_score", 50),
                            "group_key": group_key,
                            "trigger_count": count,
                            "related_event_ids": [e.get("id") for e in events_list if e.get("id")],
                            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                            "source_ip": get_canonical_field(doc, "source.ip"),
                            "host_name": get_canonical_field(doc, "host.name"),
                        }
                        generated_alerts.append(alert)
                        events_list = []

                    try:
                        await kv_store.put(raw_key, json.dumps(events_list).encode("utf-8"))
                    except Exception as put_err:
                        logger.error("NATS KV put error: %s", put_err)
                else:
                    bucket_key = (tenant_id, getattr(rule, "id", "rule"), group_key)
                    bucket = self.windows[bucket_key]
                    bucket.evict_expired(ts_sec, int(getattr(rule, "time_window_seconds", 300)))
                    bucket.add_event(ts_sec, event_id)

                    threshold = int(getattr(rule, "threshold", 1))
                    if bucket.count() >= threshold:
                        alert = {
                            "alert_id": str(uuid.uuid4()),
                            "rule_id": getattr(rule, "id", "rule"),
                            "rule_name": getattr(rule, "name", "Rule"),
                            "description": getattr(rule, "description", ""),
                            "category": getattr(rule, "category", "general"),
                            "tenant_id": tenant_id,
                            "severity": getattr(rule, "severity", 5),
                            "risk_score": getattr(rule, "risk_score", 50),
                            "group_key": group_key,
                            "trigger_count": bucket.count(),
                            "related_event_ids": bucket.get_event_ids(),
                            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                            "source_ip": get_canonical_field(doc, "source.ip"),
                            "host_name": get_canonical_field(doc, "host.name"),
                        }
                        generated_alerts.append(alert)
                        bucket.clear()

        # También procesar reglas canónicas de DB a través de RuleEngineV2
        db = SessionLocal()
        try:
            db_alerts = self.rule_engine.on_event(db, doc)
            db.commit()
            for a in db_alerts:
                generated_alerts.append({
                    "alert_id": str(getattr(a, "id", "")),
                    "rule_name": a.rule_name,
                    "severity": a.severity,
                    "server": a.server,
                    "group_key": a.group_key,
                    "evidence": a.evidence,
                })
        except Exception as e:
            db.rollback()
            logger.error("Error procesando evento en CorrelationEngine: %s", e)
        finally:
            db.close()

        return generated_alerts

    def process_event(self, event: NormalizedEvent) -> List[Dict[str, Any]]:
        doc = event.to_opensearch_doc()
        event_id = str(event.event.id)
        tenant_id = event.tenant.id
        ts_sec = event.timestamp_utc.timestamp()

        generated_alerts: List[Dict[str, Any]] = []

        if self.rules:
            for rule in self.rules:
                if not getattr(rule, "enabled", True):
                    continue

                if hasattr(rule, "matches_event") and not rule.matches_event(doc):
                    continue

                group_key = rule.get_group_key(doc) if hasattr(rule, "get_group_key") else "default"
                bucket_key = (tenant_id, getattr(rule, "id", "rule"), group_key)

                bucket = self.windows[bucket_key]
                bucket.evict_expired(ts_sec, int(getattr(rule, "time_window_seconds", 300)))
                bucket.add_event(ts_sec, event_id)

                threshold = int(getattr(rule, "threshold", 1))
                if bucket.count() >= threshold:
                    alert = {
                        "alert_id": str(uuid.uuid4()),
                        "rule_id": getattr(rule, "id", "rule"),
                        "rule_name": getattr(rule, "name", "Rule"),
                        "description": getattr(rule, "description", ""),
                        "category": getattr(rule, "category", "general"),
                        "tenant_id": tenant_id,
                        "severity": getattr(rule, "severity", 5),
                        "risk_score": getattr(rule, "risk_score", 50),
                        "group_key": group_key,
                        "trigger_count": bucket.count(),
                        "related_event_ids": bucket.get_event_ids(),
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "source_ip": get_canonical_field(doc, "source.ip"),
                        "host_name": get_canonical_field(doc, "host.name"),
                    }
                    generated_alerts.append(alert)
                    bucket.clear()

        # Procesar reglas canónicas de DB a través de RuleEngineV2
        db = SessionLocal()
        try:
            db_alerts = self.rule_engine.on_event(db, doc)
            db.commit()
            for a in db_alerts:
                generated_alerts.append({
                    "alert_id": str(getattr(a, "id", "")),
                    "rule_name": a.rule_name,
                    "severity": a.severity,
                    "server": a.server,
                    "group_key": a.group_key,
                    "evidence": a.evidence,
                })
        except Exception as e:
            db.rollback()
            logger.error("Error procesando evento en CorrelationEngine: %s", e)
        finally:
            db.close()

        return generated_alerts
