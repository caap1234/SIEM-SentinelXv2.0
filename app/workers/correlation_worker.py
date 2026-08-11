# app/workers/correlation_worker.py
"""
Worker asíncrono que consume eventos normalizados desde NATS JetStream, los procesa
mediante el motor de correlación reactivo y guarda las Alertas resultantes en PostgreSQL.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, List, Tuple

from app.core.nats_config import STREAM_NORMALIZED, SUBJECT_NORMALIZED_HOSTING
from app.services.nats_service import NatsService
from app.services.correlation_engine import CorrelationEngine
from app.schemas.normalized_event import NormalizedEvent
from app.db import SessionLocal
from app.models.alert import Alert

logger = logging.getLogger("sentinelx.correlation_worker")

CONSUMER_CORRELATION = "correlation_engine_group"
SUBJECT_ALERTS_TRIGGERED = "sentinelx.alerts.triggered"


class CorrelationWorker:
    def __init__(
        self,
        batch_size: int = 500,
        batch_timeout: float = 0.5,
        stream_name: str = STREAM_NORMALIZED,
        consumer_name: str = CONSUMER_CORRELATION,
    ) -> None:
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.stream_name = stream_name
        self.consumer_name = consumer_name
        self.running = False
        self.nats_service = NatsService.get_instance()
        self.engine = CorrelationEngine.get_instance()
        self._psub: Any = None
        self.kv_store: Any = None

    async def process_batch(self, messages: List[Any]) -> Tuple[int, int]:
        """
        Procesa un lote de eventos de NATS a través del motor de correlación.
        Retorna (eventos_procesados, alertas_generadas).
        """
        if not messages:
            return 0, 0

        processed_count = 0
        generated_alerts_count = 0

        db = SessionLocal()
        try:
            for msg in messages:
                try:
                    payload = json.loads(msg.data.decode("utf-8"))
                    event = NormalizedEvent.model_validate(payload)
                except Exception as parse_err:
                    logger.error("Error al parsear evento para correlación: %s", parse_err)
                    try:
                        await msg.ack()
                    except Exception:
                        pass
                    continue

                # Procesar en el motor de correlación reactivo distribuido NATS KV
                alerts = await self.engine.process_event_async(event, kv_store=self.kv_store)
                processed_count += 1

                for alert_dict in alerts:
                    generated_alerts_count += 1
                    # Guardar alerta en PostgreSQL
                    alert_entry = Alert(
                        rule_name=str(alert_dict.get("rule_name", "Security Detection Rule")),
                        severity=int(alert_dict.get("severity", 50)),
                        server=event.host.hostname or event.host.name or "unknown",
                        source=event.event.dataset or "generic",
                        group_key=str(alert_dict.get("group_key", "default")),
                        opensearch_event_id=str(event.event.id),
                        triggered_at=event.timestamp_utc,
                        status="open",
                        evidence=alert_dict.get("evidence", {}),
                    )
                    db.add(alert_entry)

                    # Publicar alerta a NATS
                    try:
                        await self.nats_service.publish_dlq(
                            payload_dict=alert_dict,
                            reason="alert_triggered",
                            subject=SUBJECT_ALERTS_TRIGGERED,
                        )
                    except Exception:
                        pass

                try:
                    await msg.ack()
                except Exception:
                    pass

            db.commit()
        except Exception as db_err:
            db.rollback()
            logger.error("Error al guardar alertas en PostgreSQL: %s", db_err)
        finally:
            db.close()

        return processed_count, generated_alerts_count

    async def run_once(self) -> Tuple[int, int]:
        if not self.nats_service._connected or not self.nats_service.js:
            connected = await self.nats_service.connect()
            if not connected:
                return 0, 0

        if self.kv_store is None and self.nats_service.js:
            try:
                self.kv_store = await self.nats_service.get_kv_store("sentinelx_correlation_kv")
            except Exception:
                pass

        try:
            if self._psub is None:
                self._psub = await self.nats_service.js.pull_subscribe(
                    subject=SUBJECT_NORMALIZED_HOSTING,
                    durable=self.consumer_name,
                    stream=self.stream_name,
                )
            messages = await self._psub.fetch(batch=self.batch_size, timeout=self.batch_timeout)
            return await self.process_batch(messages)
        except Exception as e:
            self._psub = None
            if "timeout" not in str(e).lower():
                logger.debug("Info/Timeout en fetch de correlación NATS: %s", e)
            return 0, 0

    async def start(self) -> None:
        self.running = True
        logger.info("Correlation Worker iniciado.")
        while self.running:
            try:
                processed, alerts = await self.run_once()
                if alerts > 0:
                    logger.info("Worker de Correlación: %d eventos procesados, %d alertas generadas", processed, alerts)
                if processed == 0:
                    await asyncio.sleep(0.2)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Excepción no capturada en Correlation Worker: %s", e)
                await asyncio.sleep(1.0)

    def stop(self) -> None:
        self.running = False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = CorrelationWorker()
    try:
        asyncio.run(worker.start())
    except KeyboardInterrupt:
        worker.stop()
