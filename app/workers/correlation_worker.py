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

                # Procesar en el motor de correlación reactivo
                alerts = self.engine.process_event(event)
                processed_count += 1

                for alert_dict in alerts:
                    generated_alerts_count += 1
                    # Guardar alerta en PostgreSQL
                    alert_entry = Alert(
                        title=alert_dict["rule_name"],
                        description=alert_dict["description"],
                        severity=str(alert_dict["severity"]),
                        status="new",
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

        try:
            psub = await self.nats_service.js.pull_subscribe(
                subject=SUBJECT_NORMALIZED_HOSTING,
                durable=self.consumer_name,
                stream=self.stream_name,
            )
            messages = await psub.fetch(batch=self.batch_size, timeout=self.batch_timeout)
            return await self.process_batch(messages)
        except Exception as e:
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
